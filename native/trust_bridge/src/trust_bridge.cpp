#define TRUST_BRIDGE_BUILD

#include "trust_bridge.h"

#ifndef _WIN32
int TrustBridge_SetCacheConfig(std::uint32_t, std::uint32_t) { return -1; }
int TrustBridge_VerifyFile(const wchar_t*, unsigned long*) { return -1; }
int TrustBridge_GetSignerInfoJson(const wchar_t*, char**) { return -1; }
int TrustBridge_ComputeFileSha256Hex(const wchar_t*, char**) { return -1; }
int TrustBridge_ScanCacheLookupByFile(const wchar_t*, int*, char**) { return -1; }
int TrustBridge_ScanCacheStore(const char*, int) { return -1; }
void TrustBridge_Free(void*) {}
#else

#define NOMINMAX
#include <windows.h>
#include <objbase.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

std::uint64_t nowMs() {
  return static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::wstring normalizePath(std::wstring s) {
  for (auto& ch : s) {
    if (ch == L'/') ch = L'\\';
    if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
  }
  if (s.rfind(L"\\\\?\\", 0) == 0) s = s.substr(4);
  if (s.rfind(L"\\??\\", 0) == 0) s = s.substr(4);
  return s;
}

std::optional<std::uint64_t> fileWriteTime100ns(const wchar_t* path) {
  if (!path || !path[0]) return std::nullopt;
  WIN32_FILE_ATTRIBUTE_DATA fad{};
  if (!GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) return std::nullopt;
  ULARGE_INTEGER uli{};
  uli.LowPart = fad.ftLastWriteTime.dwLowDateTime;
  uli.HighPart = fad.ftLastWriteTime.dwHighDateTime;
  return static_cast<std::uint64_t>(uli.QuadPart);
}

std::string wideToUtf8(const std::wstring& ws) {
  if (ws.empty()) return {};
  int needed = WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), nullptr, 0, nullptr, nullptr);
  if (needed <= 0) return {};
  std::string out(static_cast<std::size_t>(needed), '\0');
  int written = WideCharToMultiByte(CP_UTF8, 0, ws.data(), static_cast<int>(ws.size()), out.data(), needed, nullptr, nullptr);
  if (written <= 0) return {};
  return out;
}

std::string jsonEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size() + 8);
  for (unsigned char c : s) {
    switch (c) {
      case '\\': out += "\\\\"; break;
      case '"': out += "\\\""; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20) {
          char buf[7]{};
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned int>(c));
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  return out;
}

bool allocUtf8String(const std::string& s, char** out) {
  if (!out) return false;
  *out = nullptr;
  void* mem = CoTaskMemAlloc(s.size() + 1);
  if (!mem) return false;
  std::memcpy(mem, s.data(), s.size());
  static_cast<char*>(mem)[s.size()] = '\0';
  *out = static_cast<char*>(mem);
  return true;
}

struct CacheEntry {
  LONG status{0};
  bool trusted{false};
  std::uint64_t writeTime{0};
  std::uint64_t cachedAt{0};
  std::list<std::wstring>::iterator it;
};

std::mutex gMu;
std::unordered_map<std::wstring, CacheEntry> gCache;
std::list<std::wstring> gLru;
std::uint32_t gMaxEntries = 4096;
std::uint32_t gTtlMs = 600000;

void touchLru(CacheEntry& e, const std::wstring& key) {
  if (gLru.empty()) {
    gLru.push_front(key);
    e.it = gLru.begin();
    return;
  }
  gLru.erase(e.it);
  gLru.push_front(key);
  e.it = gLru.begin();
}

void evictIfNeeded() {
  while (gCache.size() > gMaxEntries && !gLru.empty()) {
    const auto& back = gLru.back();
    gCache.erase(back);
    gLru.pop_back();
  }
}

std::pair<LONG, bool> verifyFileNoCache(const wchar_t* filePath) {
  WINTRUST_FILE_INFO fileInfo{};
  fileInfo.cbStruct = sizeof(fileInfo);
  fileInfo.pcwszFilePath = filePath;
  fileInfo.hFile = nullptr;
  fileInfo.pgKnownSubject = nullptr;

  WINTRUST_DATA data{};
  data.cbStruct = sizeof(data);
  data.dwUIChoice = WTD_UI_NONE;
  data.fdwRevocationChecks = WTD_REVOKE_NONE;
  data.dwUnionChoice = WTD_CHOICE_FILE;
  data.pFile = &fileInfo;
  data.dwStateAction = WTD_STATEACTION_VERIFY;
  data.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  data.dwUIContext = 0;

  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  LONG status = WinVerifyTrust(nullptr, &action, &data);
  data.dwStateAction = WTD_STATEACTION_CLOSE;
  WinVerifyTrust(nullptr, &action, &data);
  return {status, status == ERROR_SUCCESS};
}

std::optional<std::wstring> certName(HCERTSTORE store, HCRYPTMSG msg, DWORD which) {
  DWORD signerInfoSize = 0;
  if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)) return std::nullopt;
  std::string buf;
  buf.resize(signerInfoSize);
  if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, buf.data(), &signerInfoSize)) return std::nullopt;
  auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());

  CERT_INFO ci{};
  ci.Issuer = si->Issuer;
  ci.SerialNumber = si->SerialNumber;

  PCCERT_CONTEXT cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);
  if (!cert) return std::nullopt;

  wchar_t nameBuf[512]{};
  DWORD flags = 0;
  DWORD type = CERT_NAME_SIMPLE_DISPLAY_TYPE;
  if (which == 1) {
    flags = CERT_NAME_ISSUER_FLAG;
  }
  DWORD got = CertGetNameStringW(cert, type, flags, nullptr, nameBuf, static_cast<DWORD>(std::size(nameBuf)));
  CertFreeCertificateContext(cert);
  if (got <= 1) return std::nullopt;
  return std::wstring(nameBuf);
}

std::optional<std::string> certThumbprintHex(HCERTSTORE store, HCRYPTMSG msg) {
  DWORD signerInfoSize = 0;
  if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize)) return std::nullopt;
  std::string buf;
  buf.resize(signerInfoSize);
  if (!CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, buf.data(), &signerInfoSize)) return std::nullopt;
  auto* si = reinterpret_cast<CMSG_SIGNER_INFO*>(buf.data());

  CERT_INFO ci{};
  ci.Issuer = si->Issuer;
  ci.SerialNumber = si->SerialNumber;

  PCCERT_CONTEXT cert = CertFindCertificateInStore(store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &ci, nullptr);
  if (!cert) return std::nullopt;

  BYTE hash[64]{};
  DWORD hashLen = sizeof(hash);
  if (!CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID, hash, &hashLen) || hashLen == 0) {
    CertFreeCertificateContext(cert);
    return std::nullopt;
  }
  CertFreeCertificateContext(cert);
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(hashLen * 2);
  for (DWORD i = 0; i < hashLen; i++) {
    out.push_back(kHex[(hash[i] >> 4) & 0xF]);
    out.push_back(kHex[hash[i] & 0xF]);
  }
  return out;
}

struct ScanHashEntry {
  std::uint64_t writeTime{0};
  std::string hashHex;
  std::uint64_t cachedAt{0};
};

struct ScanVerdictEntry {
  int verdict{0};
  std::uint64_t cachedAt{0};
};

std::mutex gScanMu;
std::unordered_map<std::wstring, ScanHashEntry> gPathToHash;
std::unordered_map<std::string, ScanVerdictEntry> gHashToVerdict;
std::uint32_t gScanVerdictTtlMs = 3600000;

std::optional<std::string> sha256HexOfFile(const wchar_t* filePath) {
  if (!filePath || !filePath[0]) return std::nullopt;
  HANDLE h = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return std::nullopt;

  BCRYPT_ALG_HANDLE hAlg = nullptr;
  BCRYPT_HASH_HANDLE hHash = nullptr;
  DWORD objLen = 0;
  DWORD cb = 0;
  DWORD hashLen = 0;
  std::vector<BYTE> obj;
  std::vector<BYTE> hash;

  const NTSTATUS stAlg = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
  if (stAlg < 0) {
    CloseHandle(h);
    return std::nullopt;
  }
  if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&objLen), sizeof(objLen), &cb, 0) < 0 || objLen == 0) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(h);
    return std::nullopt;
  }
  if (BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, reinterpret_cast<PUCHAR>(&hashLen), sizeof(hashLen), &cb, 0) < 0 || hashLen == 0) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(h);
    return std::nullopt;
  }
  obj.resize(objLen);
  hash.resize(hashLen);
  if (BCryptCreateHash(hAlg, &hHash, obj.data(), objLen, nullptr, 0, 0) < 0) {
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(h);
    return std::nullopt;
  }

  BYTE buf[65536];
  while (true) {
    DWORD read = 0;
    if (!ReadFile(h, buf, static_cast<DWORD>(sizeof(buf)), &read, nullptr)) {
      BCryptDestroyHash(hHash);
      BCryptCloseAlgorithmProvider(hAlg, 0);
      CloseHandle(h);
      return std::nullopt;
    }
    if (read == 0) break;
    if (BCryptHashData(hHash, buf, read, 0) < 0) {
      BCryptDestroyHash(hHash);
      BCryptCloseAlgorithmProvider(hAlg, 0);
      CloseHandle(h);
      return std::nullopt;
    }
  }
  if (BCryptFinishHash(hHash, hash.data(), hashLen, 0) < 0) {
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    CloseHandle(h);
    return std::nullopt;
  }
  BCryptDestroyHash(hHash);
  BCryptCloseAlgorithmProvider(hAlg, 0);
  CloseHandle(h);

  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(hash.size() * 2);
  for (BYTE b : hash) {
    out.push_back(kHex[(b >> 4) & 0xF]);
    out.push_back(kHex[b & 0xF]);
  }
  return out;
}

bool isHexLower(const std::string& s) {
  if (s.size() != 64) return false;
  for (unsigned char c : s) {
    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (!ok) return false;
  }
  return true;
}

}  // namespace

extern "C" int TrustBridge_SetCacheConfig(std::uint32_t maxEntries, std::uint32_t ttlMs) {
  std::lock_guard<std::mutex> lk(gMu);
  gMaxEntries = maxEntries > 0 ? maxEntries : 4096;
  gTtlMs = ttlMs > 0 ? ttlMs : 600000;
  evictIfNeeded();
  return 0;
}

extern "C" int TrustBridge_VerifyFile(const wchar_t* filePath, unsigned long* outStatus) {
  if (outStatus) *outStatus = static_cast<unsigned long>(-1);
  if (!filePath || !filePath[0]) return 0;
  const auto writeTime = fileWriteTime100ns(filePath).value_or(0);
  const auto norm = normalizePath(std::wstring(filePath));
  const auto now = nowMs();
  {
    std::lock_guard<std::mutex> lk(gMu);
    auto it = gCache.find(norm);
    if (it != gCache.end()) {
      auto& e = it->second;
      const bool fresh = (e.writeTime == writeTime) && (now >= e.cachedAt) && ((now - e.cachedAt) <= gTtlMs);
      if (fresh) {
        touchLru(e, it->first);
        if (outStatus) *outStatus = static_cast<unsigned long>(e.status);
        return e.trusted ? 1 : 0;
      }
    }
  }

  const auto res = verifyFileNoCache(filePath);
  {
    std::lock_guard<std::mutex> lk(gMu);
    auto it = gCache.find(norm);
    if (it == gCache.end()) {
      gLru.push_front(norm);
      CacheEntry e;
      e.status = res.first;
      e.trusted = res.second;
      e.writeTime = writeTime;
      e.cachedAt = now;
      e.it = gLru.begin();
      gCache.emplace(norm, std::move(e));
    } else {
      auto& e = it->second;
      e.status = res.first;
      e.trusted = res.second;
      e.writeTime = writeTime;
      e.cachedAt = now;
      touchLru(e, it->first);
    }
    evictIfNeeded();
  }
  if (outStatus) *outStatus = static_cast<unsigned long>(res.first);
  return res.second ? 1 : 0;
}

extern "C" int TrustBridge_GetSignerInfoJson(const wchar_t* filePath, char** outUtf8Json) {
  if (!outUtf8Json) return -1;
  *outUtf8Json = nullptr;
  if (!filePath || !filePath[0]) return -1;

  HCERTSTORE store = nullptr;
  HCRYPTMSG msg = nullptr;
  DWORD enc = 0, content = 0, format = 0;
  BOOL ok = CryptQueryObject(CERT_QUERY_OBJECT_FILE, filePath,
                            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED | CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                            CERT_QUERY_FORMAT_FLAG_BINARY, 0, &enc, &content, &format, &store, &msg, nullptr);
  if (!ok || !store || !msg) {
    if (store) CertCloseStore(store, 0);
    if (msg) CryptMsgClose(msg);
    return -2;
  }

  const auto subject = certName(store, msg, 0).value_or(L"");
  const auto issuer = certName(store, msg, 1).value_or(L"");
  const auto thumb = certThumbprintHex(store, msg).value_or("");

  CryptMsgClose(msg);
  CertCloseStore(store, 0);

  std::string json = "{\"subject\":";
  if (subject.empty()) json += "null";
  else json += std::string("\"") + jsonEscape(wideToUtf8(subject)) + "\"";
  json += ",\"issuer\":";
  if (issuer.empty()) json += "null";
  else json += std::string("\"") + jsonEscape(wideToUtf8(issuer)) + "\"";
  json += ",\"thumbprint\":";
  if (thumb.empty()) json += "null";
  else json += std::string("\"") + jsonEscape(thumb) + "\"";
  json += "}";

  if (!allocUtf8String(json, outUtf8Json)) return -3;
  return 0;
}

extern "C" int TrustBridge_ComputeFileSha256Hex(const wchar_t* filePath, char** outUtf8Hex) {
  if (!outUtf8Hex) return -1;
  *outUtf8Hex = nullptr;
  if (!filePath || !filePath[0]) return -1;
  const auto h = sha256HexOfFile(filePath);
  if (!h || h->empty()) return -2;
  if (!allocUtf8String(*h, outUtf8Hex)) return -3;
  return 0;
}

extern "C" int TrustBridge_ScanCacheLookupByFile(const wchar_t* filePath, int* outVerdict, char** outUtf8Hex) {
  if (outVerdict) *outVerdict = 0;
  if (outUtf8Hex) *outUtf8Hex = nullptr;
  if (!filePath || !filePath[0]) return -1;
  const auto wt = fileWriteTime100ns(filePath).value_or(0);
  const auto key = normalizePath(std::wstring(filePath));
  const auto now = nowMs();
  std::string hashHex;
  {
    std::lock_guard<std::mutex> lk(gScanMu);
    auto it = gPathToHash.find(key);
    if (it != gPathToHash.end()) {
      if (it->second.writeTime == wt && !it->second.hashHex.empty()) {
        hashHex = it->second.hashHex;
      }
    }
  }
  if (hashHex.empty()) {
    const auto h = sha256HexOfFile(filePath);
    if (!h || h->empty() || !isHexLower(*h)) return -2;
    hashHex = *h;
    std::lock_guard<std::mutex> lk(gScanMu);
    gPathToHash[key] = ScanHashEntry{wt, hashHex, now};
  }
  if (outUtf8Hex) {
    if (!allocUtf8String(hashHex, outUtf8Hex)) return -3;
  }
  {
    std::lock_guard<std::mutex> lk(gScanMu);
    auto it = gHashToVerdict.find(hashHex);
    if (it == gHashToVerdict.end()) return 0;
    const bool fresh = (now >= it->second.cachedAt) && ((now - it->second.cachedAt) <= gScanVerdictTtlMs);
    if (!fresh) {
      gHashToVerdict.erase(it);
      return 0;
    }
    if (outVerdict) *outVerdict = it->second.verdict;
    return 1;
  }
}

extern "C" int TrustBridge_ScanCacheStore(const char* utf8HashHex, int verdict) {
  const std::string h = (utf8HashHex && utf8HashHex[0]) ? std::string(utf8HashHex) : std::string();
  if (!isHexLower(h)) return -1;
  const auto now = nowMs();
  std::lock_guard<std::mutex> lk(gScanMu);
  gHashToVerdict[h] = ScanVerdictEntry{verdict, now};
  return 0;
}

extern "C" void TrustBridge_Free(void* p) {
  if (!p) return;
  CoTaskMemFree(p);
}

#endif

