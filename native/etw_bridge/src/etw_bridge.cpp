#define ETW_BRIDGE_BUILD

#include "etw_bridge.h"

#ifndef _WIN32
void* EtwBridge_Create(const wchar_t*) { return nullptr; }
int EtwBridge_Start(void*, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, std::uint64_t, int, int, int, std::uint32_t) { return -1; }
int EtwBridge_Stop(void*, std::uint32_t) { return -1; }
int EtwBridge_PollJson(void*, char**) { return -1; }
int EtwBridge_SetRulesJson(void*, const char*) { return -1; }
int EtwBridge_SetTrackedPids(void*, const std::uint32_t*, std::uint32_t, int) { return -1; }
int EtwBridge_SetContextCapacity(void*, std::uint32_t) { return -1; }
void EtwBridge_Free(void*) {}
void EtwBridge_Destroy(void*) {}
#else

#define NOMINMAX
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <evntprov.h>
#include <objbase.h>
#include <winternl.h>

#include <atomic>
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cctype>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "etw_rule_engine.h"

namespace {

constexpr GUID kGuidKernelProcess = {0x22FB2CD6, 0x0E7B, 0x422B, {0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16}};
constexpr GUID kGuidKernelFile = {0xEDD08927, 0x9CC4, 0x4E65, {0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89}};
constexpr GUID kGuidKernelRegistry = {0x70EB4F03, 0xC1DE, 0x4F73, {0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD}};
constexpr GUID kGuidKernelNetwork = {0x7DD42A49, 0x5329, 0x4832, {0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88}};

bool sameGuid(const GUID& a, const GUID& b) {
  return std::memcmp(&a, &b, sizeof(GUID)) == 0;
}

const char* providerKindName(anxin::ProviderKind k) {
  switch (k) {
    case anxin::ProviderKind::Process: return "Process";
    case anxin::ProviderKind::File: return "File";
    case anxin::ProviderKind::Registry: return "Registry";
    case anxin::ProviderKind::Network: return "Network";
    default: return "Unknown";
  }
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

std::wstring utf8ToWideLossy(const std::string_view s) {
  if (s.empty()) return {};
  int needed = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  if (needed <= 0) return {};
  std::wstring out(static_cast<std::size_t>(needed), L'\0');
  int written = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), needed);
  if (written <= 0) return {};
  return out;
}

bool isWhitespace(unsigned char c) {
  return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

std::string trimAscii(const std::string& s) {
  std::size_t start = 0;
  while (start < s.size() && isWhitespace(static_cast<unsigned char>(s[start]))) start++;
  std::size_t end = s.size();
  while (end > start && isWhitespace(static_cast<unsigned char>(s[end - 1]))) end--;
  return s.substr(start, end - start);
}

std::string sanitizeText(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (unsigned char c : s) {
    if (c == 0) continue;
    if (c < 0x20) {
      if (c == '\t' || c == '\n' || c == '\r') out.push_back(static_cast<char>(c));
      continue;
    }
    out.push_back(static_cast<char>(c));
  }
  return trimAscii(out);
}

bool containsUtf8ReplacementChar(const std::string& s) {
  static constexpr unsigned char rep[] = {0xEF, 0xBF, 0xBD};
  for (std::size_t i = 0; i + 3 <= s.size(); i++) {
    if (static_cast<unsigned char>(s[i]) == rep[0] && static_cast<unsigned char>(s[i + 1]) == rep[1] &&
        static_cast<unsigned char>(s[i + 2]) == rep[2]) {
      return true;
    }
  }
  return false;
}

bool isLikelyReadableText(const std::string& s) {
  if (s.empty()) return false;
  if (containsUtf8ReplacementChar(s)) return false;
  int bad = 0;
  int nul = 0;
  int total = 0;
  for (unsigned char c : s) {
    total++;
    if (c == 0) {
      nul++;
      continue;
    }
    if (c < 0x20) {
      if (c != '\t' && c != '\n' && c != '\r') bad++;
      continue;
    }
  }
  if (nul) return false;
  const double ratio = static_cast<double>(bad) / static_cast<double>(total > 0 ? total : 1);
  return ratio <= 0.05;
}

std::vector<std::string> filterLikelyStrings(const std::vector<std::string>& strings) {
  std::vector<std::string> out;
  out.reserve(strings.size());
  for (const auto& it : strings) {
    if (!isLikelyReadableText(it)) continue;
    auto s = trimAscii(it);
    if (s.empty()) continue;
    out.push_back(std::move(s));
    if (out.size() >= 64) break;
  }
  return out;
}

std::vector<std::string> splitOnNull(const std::wstring& ws, int minLen) {
  std::vector<std::string> out;
  std::wstring cur;
  for (wchar_t ch : ws) {
    if (ch == 0) {
      auto s = sanitizeText(wideToUtf8(cur));
      if (!s.empty() && static_cast<int>(s.size()) >= minLen) out.push_back(std::move(s));
      cur.clear();
      continue;
    }
    cur.push_back(ch);
  }
  auto s = sanitizeText(wideToUtf8(cur));
  if (!s.empty() && static_cast<int>(s.size()) >= minLen) out.push_back(std::move(s));
  return out;
}

std::vector<std::string> extractStringsHeuristic(const std::vector<std::uint8_t>& bytes, int minLen) {
  std::vector<std::string> utf16;
  std::vector<std::string> utf8;
  {
    const std::size_t wcharCount = bytes.size() / 2;
    std::wstring ws;
    ws.resize(wcharCount);
    std::memcpy(ws.data(), bytes.data(), wcharCount * 2);
    utf16 = splitOnNull(ws, minLen);
  }
  {
    std::string raw(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    auto ws = utf8ToWideLossy(raw);
    utf8 = splitOnNull(ws, minLen);
  }

  const auto a = filterLikelyStrings(utf8);
  const auto b = filterLikelyStrings(utf16);

  auto hasRegHint = [](const std::vector<std::string>& list) -> bool {
    for (const auto& s : list) {
      if (s.rfind("\\REGISTRY\\", 0) == 0) return true;
      if (s.size() >= 5) {
        const auto prefix = s.substr(0, 5);
        if (prefix == "HKLM\\" || prefix == "HKCU\\" || prefix == "HKCR\\" || prefix == "HKU\\" || prefix == "HKCC\\") return true;
      }
    }
    return false;
  };

  const bool ha = hasRegHint(a);
  const bool hb = hasRegHint(b);
  if (hb && !ha) return utf16;
  if (ha && !hb) return utf8;

  auto score = [](const std::vector<std::string>& list) -> int {
    int sc = 0;
    for (const auto& s : list) {
      if (s.rfind("\\REGISTRY\\", 0) == 0) sc += 80;
      if (s.rfind("HKLM\\", 0) == 0 || s.rfind("HKCU\\", 0) == 0 || s.rfind("HKCR\\", 0) == 0 || s.rfind("HKU\\", 0) == 0 ||
          s.rfind("HKCC\\", 0) == 0) {
        sc += 70;
      }
      int bs = 0;
      for (char c : s) if (c == '\\') bs++;
      sc += (bs * 6 > 60 ? 60 : bs * 6);
      sc += (static_cast<int>(s.size()) / 6 > 30 ? 30 : static_cast<int>(s.size()) / 6);
    }
    return sc;
  };

  const int sa = score(a);
  const int sb = score(b);
  if (sb > sa) return utf16;
  if (sa > sb) return utf8;
  if (b.size() > a.size()) return utf16;
  if (a.size() > b.size()) return utf8;
  return !b.empty() ? utf16 : utf8;
}

std::optional<std::string> pickBestPathCandidate(const std::vector<std::string>& strings) {
  const auto list = filterLikelyStrings(strings);
  struct Scored {
    std::string s;
    int score;
    std::size_t idx;
  };
  std::vector<Scored> scored;
  scored.reserve(list.size());
  for (std::size_t i = 0; i < list.size(); i++) {
    const auto& s = list[i];
    const bool hasSlash = s.find('\\') != std::string::npos;
    const bool hasDrive = s.size() >= 3 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':' && s[2] == '\\';
    const bool hasDevice = s.rfind("\\Device\\", 0) == 0 || s.rfind("\\\\?\\", 0) == 0;
    std::string lower = s;
    for (auto& ch : lower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    const bool looksLikeExe = lower.size() >= 4 && lower.rfind(".exe") == lower.size() - 4;
    const int score = (hasDrive ? 50 : 0) + (hasDevice ? 30 : 0) + (hasSlash ? 10 : 0) + (looksLikeExe ? 10 : 0) +
                      (static_cast<int>(s.size()) / 10 > 20 ? 20 : static_cast<int>(s.size()) / 10);
    scored.push_back({s, score, i});
  }
  std::sort(scored.begin(), scored.end(), [](const Scored& a, const Scored& b) {
    if (a.score != b.score) return a.score > b.score;
    if (a.s.size() != b.s.size()) return a.s.size() > b.s.size();
    return a.idx > b.idx;
  });

  auto isPathLike = [](const std::string& s) -> bool {
    if (s.empty()) return false;
    if (s.find('\\') != std::string::npos) return true;
    if (s.size() >= 4) {
      std::string lower = s;
      for (auto& ch : lower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
      if (lower.rfind(".exe") == lower.size() - 4) return true;
    }
    return false;
  };
  for (const auto& it : scored) {
    if (isPathLike(it.s)) return it.s;
  }
  return std::nullopt;
}

std::vector<std::string> pickTopPathCandidates(const std::vector<std::string>& strings, std::size_t maxN, bool penalizeExe) {
  const auto list = filterLikelyStrings(strings);
  struct Scored {
    std::string s;
    int score;
    std::size_t idx;
  };
  std::vector<Scored> scored;
  scored.reserve(list.size());
  for (std::size_t i = 0; i < list.size(); i++) {
    const auto& s = list[i];
    const bool hasSlash = s.find('\\') != std::string::npos;
    const bool hasDrive = s.size() >= 3 && ((s[0] >= 'A' && s[0] <= 'Z') || (s[0] >= 'a' && s[0] <= 'z')) && s[1] == ':' && s[2] == '\\';
    const bool hasDevice = s.rfind("\\Device\\", 0) == 0 || s.rfind("\\\\?\\", 0) == 0;
    std::string lower = s;
    for (auto& ch : lower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    const bool looksLikeExe = lower.size() >= 4 && lower.rfind(".exe") == lower.size() - 4;
    int score = (hasDrive ? 50 : 0) + (hasDevice ? 30 : 0) + (hasSlash ? 10 : 0) +
                (static_cast<int>(s.size()) / 10 > 20 ? 20 : static_cast<int>(s.size()) / 10);
    if (!penalizeExe && looksLikeExe) score += 10;
    if (penalizeExe && looksLikeExe) score -= 20;
    scored.push_back({s, score, i});
  }
  std::sort(scored.begin(), scored.end(), [](const Scored& a, const Scored& b) {
    if (a.score != b.score) return a.score > b.score;
    if (a.s.size() != b.s.size()) return a.s.size() > b.s.size();
    return a.idx > b.idx;
  });

  auto isPathLike = [](const std::string& s) -> bool {
    if (s.empty()) return false;
    if (s.find('\\') != std::string::npos) return true;
    if (s.size() >= 4) {
      std::string lower = s;
      for (auto& ch : lower) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
      if (lower.rfind(".exe") == lower.size() - 4) return true;
    }
    return false;
  };

  std::vector<std::string> out;
  out.reserve(maxN > 0 ? maxN : 1);
  for (const auto& it : scored) {
    if (out.size() >= maxN) break;
    if (!isPathLike(it.s)) continue;
    std::string key = it.s;
    for (auto& ch : key) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    bool dup = false;
    for (const auto& o : out) {
      std::string ok = o;
      for (auto& ch : ok) ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
      if (ok == key) {
        dup = true;
        break;
      }
    }
    if (dup) continue;
    out.push_back(it.s);
  }
  return out;
}

std::string mapFileOp(const EVENT_DESCRIPTOR& d) {
  const int id = static_cast<int>(d.Id);
  const int opcode = static_cast<int>(d.Opcode);
  if (id == 30 || id == 12 || id == 10) return "Create";
  if (id == 15) return "Open";
  if (id == 16 || id == 17) return "Modify";
  if (id == 26 || id == 11) return "Delete";
  if (id == 27 || id == 19) return "Rename";
  const int op = (opcode == 32 || opcode == 35 || opcode == 36) ? opcode : ((id == 32 || id == 35 || id == 36) ? id : 0);
  if (op == 32) return "Create";
  if (op == 35) return "Delete";
  if (op == 36) return "Rename";
  return {};
}

std::string mapNetworkOp(const EVENT_DESCRIPTOR& d) {
  const int opcode = static_cast<int>(d.Opcode);
  const int id = static_cast<int>(d.Id);
  auto isCand = [](int x) {
    switch (x) {
      case 10:
      case 11:
      case 12:
      case 13:
      case 14:
      case 15:
      case 16:
        return true;
      default:
        return false;
    }
  };
  if (isCand(opcode) || isCand(id)) return "Connect";
  return {};
}

std::string mapRegistryOp(std::uint8_t opcode, std::uint16_t id) {
  switch (id) {
    case 1: return "CreateKey";
    case 2: return "OpenKey";
    case 3: return "DeleteKey";
    case 4: return "QueryValue";
    case 5: return "SetValue";
    case 6: return "DeleteValue";
    case 7: return "QueryKey";
    case 8: return "EnumerateKey";
    case 9: return "EnumerateValue";
    case 10: return "QueryMultipleValue";
    case 11: return "SetInformationKey";
    case 12: return "FlushKey";
    case 13: return "CloseKey";
    case 14: return "SetSecurityKey";
    case 15: return "QuerySecurityKey";
    case 16: return "RenameKey";
    default: break;
  }
  switch (opcode) {
    case 1: return "CreateKey";
    case 2: return "OpenKey";
    case 3: return "DeleteKey";
    case 4: return "QueryValue";
    case 5: return "SetValue";
    case 6: return "DeleteValue";
    case 7: return "QueryKey";
    case 8: return "EnumerateKey";
    case 9: return "EnumerateValue";
    case 10: return "QueryMultipleValue";
    case 11: return "SetInformationKey";
    case 12: return "FlushKey";
    case 13: return "CloseKey";
    case 14: return "SetSecurityKey";
    case 15: return "QuerySecurityKey";
    case 16: return "RenameKey";
    default: break;
  }
  if (id != 0) return std::string("EventId_") + std::to_string(id);
  return std::string("Opcode_") + std::to_string(static_cast<int>(opcode));
}

std::uint64_t filetimeToUnixMs(std::uint64_t ts100ns) {
  constexpr std::uint64_t kEpochDiffMs = 11644473600000ULL;
  return (ts100ns / 10000ULL) - kEpochDiffMs;
}

std::string filetimeToIso(std::uint64_t ts100ns) {
  const std::uint64_t unixMs = filetimeToUnixMs(ts100ns);
  std::chrono::system_clock::time_point tp{std::chrono::milliseconds(unixMs)};
  std::time_t tt = std::chrono::system_clock::to_time_t(tp);
  std::tm tm{};
  gmtime_s(&tm, &tt);
  char buf[32]{};
  const auto ms = unixMs % 1000ULL;
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03lluZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                static_cast<unsigned long long>(ms));
  return std::string(buf);
}

std::uint32_t readU32LE(const std::vector<std::uint8_t>& bytes, std::size_t off) {
  if (off + 4 > bytes.size()) return 0;
  return static_cast<std::uint32_t>(bytes[off]) |
         (static_cast<std::uint32_t>(bytes[off + 1]) << 8) |
         (static_cast<std::uint32_t>(bytes[off + 2]) << 16) |
         (static_cast<std::uint32_t>(bytes[off + 3]) << 24);
}

std::uint16_t readU16BE(const std::vector<std::uint8_t>& bytes, std::size_t off) {
  if (off + 2 > bytes.size()) return 0;
  return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[off]) << 8) |
                                    static_cast<std::uint16_t>(bytes[off + 1]));
}

bool isLoopbackIpv4(std::uint8_t a) {
  return a == 127;
}

bool isPrivateIpv4(std::uint8_t a, std::uint8_t b) {
  if (a == 10) return true;
  if (a == 172 && b >= 16 && b <= 31) return true;
  if (a == 192 && b == 168) return true;
  if (a == 169 && b == 254) return true;
  return false;
}

bool isBadIpv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  if (a == 0) return true;
  if (a == 255) return true;
  if (a == 224) return true;
  if (a == 239) return true;
  if (a == 127 && b == 0 && c == 0 && d == 1) return false;
  return false;
}

std::string ipv4ToString(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return std::to_string(static_cast<unsigned>(a)) + "." + std::to_string(static_cast<unsigned>(b)) + "." +
         std::to_string(static_cast<unsigned>(c)) + "." + std::to_string(static_cast<unsigned>(d));
}

struct NetworkCfg {
  bool enabled{true};
  bool filterPrivateIps{true};
  bool skipLoopback{true};
};

struct NetworkParsed {
  std::string json;
  std::string target;
  std::string remoteIp;
  std::uint16_t remotePort{0};
};

std::optional<NetworkParsed> parseNetworkUserDataHeuristic(const std::vector<std::uint8_t>& bytes, const NetworkCfg& cfg) {
  if (!cfg.enabled) return std::nullopt;
  if (bytes.size() < 12) return std::nullopt;

  const std::size_t limit = bytes.size() - 12;
  int bestScore = -1;
  NetworkParsed best{};

  for (std::size_t off = 0; off <= limit; off++) {
    const std::uint8_t a1 = bytes[off];
    const std::uint8_t b1 = bytes[off + 1];
    const std::uint8_t c1 = bytes[off + 2];
    const std::uint8_t d1 = bytes[off + 3];
    const std::uint8_t a2 = bytes[off + 4];
    const std::uint8_t b2 = bytes[off + 5];
    const std::uint8_t c2 = bytes[off + 6];
    const std::uint8_t d2 = bytes[off + 7];

    if (isBadIpv4(a1, b1, c1, d1) || isBadIpv4(a2, b2, c2, d2)) continue;

    const std::uint16_t sport = readU16BE(bytes, off + 8);
    const std::uint16_t dport = readU16BE(bytes, off + 10);
    if (sport < 1 || dport < 1) continue;
    if (sport > 65535 || dport > 65535) continue;

    const bool localIsLoop = isLoopbackIpv4(a1);
    const bool remoteIsLoop = isLoopbackIpv4(a2);
    if (cfg.skipLoopback && (localIsLoop || remoteIsLoop)) continue;

    const bool localIsPrivate = isPrivateIpv4(a1, b1);
    const bool remoteIsPrivate = isPrivateIpv4(a2, b2);
    if (cfg.filterPrivateIps && remoteIsPrivate) continue;

    int score = 0;
    if (localIsPrivate && !remoteIsPrivate) score += 20;
    if (!localIsPrivate && !remoteIsPrivate) score += 10;
    if (dport == 80 || dport == 443 || dport == 53) score += 6;
    score += std::min(20, static_cast<int>(dport / 1000));

    const auto remoteIp = ipv4ToString(a2, b2, c2, d2);
    const auto target = std::string("TCP ") + remoteIp + ":" + std::to_string(dport);

    if (score > bestScore) {
      bestScore = score;
      best.remoteIp = remoteIp;
      best.remotePort = dport;
      best.target = target;
      best.json =
          std::string("{\"protocol\":\"TCP\",\"remoteIp\":\"") + remoteIp +
          "\",\"remotePort\":" + std::to_string(dport) +
          ",\"direction\":\"outbound\",\"target\":\"" + target + "\"}";
    }
  }

  if (bestScore < 0) return std::nullopt;
  return best;
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

std::vector<std::uint8_t> sliceUserData(const EVENT_RECORD* r, std::uint32_t maxBytes) {
  if (!r || !r->UserData || r->UserDataLength == 0) return {};
  std::size_t len = static_cast<std::size_t>(r->UserDataLength);
  if (maxBytes > 0 && len > maxBytes) len = maxBytes;
  std::vector<std::uint8_t> out(len);
  std::memcpy(out.data(), r->UserData, len);
  return out;
}

struct EtwBridgeState {
  std::wstring sessionName;

  TRACEHANDLE sessionHandle{0};
  TRACEHANDLE traceHandle{0};
  EVENT_TRACE_LOGFILEW logfile{};
  std::vector<std::uint8_t> propertiesBuf;

  std::atomic<bool> running{false};
  std::atomic<bool> stopping{false};

  std::thread traceThread;
  std::mutex qMu;
  std::deque<std::string> queue;
  std::size_t maxQueueLen{8192};

  NetworkCfg netCfg{};
  std::uint32_t userDataMaxBytes{65536};

  std::mutex engineMu;
  anxin::EtwRuleEngine engine;
};

EVENT_TRACE_PROPERTIES* buildProps(EtwBridgeState& st) {
  const auto propsSize = sizeof(EVENT_TRACE_PROPERTIES);
  const auto nameBytes = (st.sessionName.size() + 1) * sizeof(wchar_t);
  const auto totalSize = propsSize + nameBytes + 1024;
  st.propertiesBuf.assign(totalSize, 0);
  auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(st.propertiesBuf.data());
  props->Wnode.BufferSize = static_cast<ULONG>(totalSize);
  props->Wnode.ClientContext = 1;
  props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  props->LoggerNameOffset = static_cast<ULONG>(propsSize);
  auto* namePtr = reinterpret_cast<wchar_t*>(st.propertiesBuf.data() + propsSize);
  std::memcpy(namePtr, st.sessionName.c_str(), nameBytes);
  return props;
}

void pushJson(EtwBridgeState& st, std::string json) {
  std::lock_guard<std::mutex> lk(st.qMu);
  st.queue.push_back(std::move(json));
  while (st.queue.size() > st.maxQueueLen) st.queue.pop_front();
}

void pushStatus(EtwBridgeState& st, const std::string& message) {
  pushJson(st, std::string("{\"type\":\"status\",\"message\":\"") + jsonEscape(message) + "\"}");
}

void pushError(EtwBridgeState& st, const std::string& code, const std::string& message) {
  pushJson(st, std::string("{\"type\":\"error\",\"code\":\"") + jsonEscape(code) + "\",\"message\":\"" + jsonEscape(message) + "\"}");
}

struct RegistryParsed {
  std::string json;
  std::string type;
  std::string keyPath;
  std::string valueName;
};

RegistryParsed parseRegistryUserDataJson(const std::vector<std::uint8_t>& bytes, std::uint8_t opcode, std::uint16_t id) {
  const auto strings = extractStringsHeuristic(bytes, 3);
  const auto filtered = filterLikelyStrings(strings);

  RegistryParsed out;
  std::string keyPath;
  for (const auto& s : filtered) {
    if (s.rfind("\\REGISTRY\\", 0) == 0 || s.rfind("HKLM\\", 0) == 0 || s.rfind("HKCU\\", 0) == 0 || s.rfind("HKCR\\", 0) == 0 ||
        s.rfind("HKU\\", 0) == 0 || s.rfind("HKCC\\", 0) == 0) {
      keyPath = s;
      break;
    }
  }
  if (keyPath.empty() && !filtered.empty()) keyPath = filtered[0];

  std::string valueName;
  for (const auto& s : filtered) {
    if (s.empty()) continue;
    if (s == keyPath) continue;
    if (s.find('\\') != std::string::npos) continue;
    valueName = s;
    break;
  }

  out.type = mapRegistryOp(opcode, id);
  std::string json = std::string("{\"type\":\"") + jsonEscape(out.type) + "\"";
  json += ",\"keyPath\":";
  json += keyPath.empty() ? "null" : (std::string("\"") + jsonEscape(keyPath) + "\"");
  json += ",\"valueName\":";
  json += valueName.empty() ? "null" : (std::string("\"") + jsonEscape(valueName) + "\"");
  json += "}";
  out.json = std::move(json);
  out.keyPath = std::move(keyPath);
  out.valueName = std::move(valueName);
  return out;
}

void __stdcall onEventRecord(PEVENT_RECORD record) {
  auto* st = reinterpret_cast<EtwBridgeState*>(record ? record->UserContext : nullptr);
  if (!st) return;
  if (st->stopping.load(std::memory_order_relaxed)) return;

  const auto& hdr = record->EventHeader;
  const auto providerId = hdr.ProviderId;
  const auto& desc = hdr.EventDescriptor;

  const bool isProcess = sameGuid(providerId, kGuidKernelProcess);
  const bool isFile = sameGuid(providerId, kGuidKernelFile);
  const bool isRegistry = sameGuid(providerId, kGuidKernelRegistry);
  const bool isNetwork = st->netCfg.enabled && sameGuid(providerId, kGuidKernelNetwork);
  if (!isProcess && !isFile && !isRegistry && !isNetwork) return;

  const auto bytes = sliceUserData(record, st->userDataMaxBytes);
  if (bytes.empty()) return;

  const std::uint64_t ts = static_cast<std::uint64_t>(hdr.TimeStamp.QuadPart);
  const std::uint64_t unixMs = filetimeToUnixMs(ts);
  const auto timestamp = filetimeToIso(ts);

  std::string provider = isProcess ? "Process" : (isFile ? "File" : (isRegistry ? "Registry" : "Network"));
  std::string dataJson = "{}";
  anxin::ProviderKind providerKind = isProcess ? anxin::ProviderKind::Process : (isFile ? anxin::ProviderKind::File : (isRegistry ? anxin::ProviderKind::Registry : anxin::ProviderKind::Network));
  std::uint32_t eventPid = hdr.ProcessId;
  std::uint32_t eventPpid = 0;
  std::string eventOp;
  std::string eventTarget;
  std::string eventTarget2;
  std::string eventImage;

  if (isProcess) {
    if (desc.Opcode == 1 || desc.Opcode == 2) {
      const std::uint32_t pid = readU32LE(bytes, 0);
      const std::uint32_t ppid = readU32LE(bytes, 4);
      const auto strings = extractStringsHeuristic(bytes, 3);
      const auto image = pickBestPathCandidate(strings).value_or("");
      const std::string typ = desc.Opcode == 1 ? "Start" : "Stop";
      eventPid = pid;
      eventPpid = ppid;
      eventOp = typ;
      eventTarget = image;
      eventImage = image;
      dataJson = std::string("{\"processId\":") + std::to_string(pid) +
                 ",\"parentProcessId\":" + std::to_string(ppid) +
                 ",\"imageName\":" + (image.empty() ? "null" : (std::string("\"") + jsonEscape(image) + "\"")) +
                 ",\"type\":\"" + typ + "\"}";
    } else {
      return;
    }
  } else if (isFile) {
    const auto op = mapFileOp(desc);
    if (op.empty()) return;
    const auto strings = extractStringsHeuristic(bytes, 3);
    std::string fileName;
    std::string fileName2;
    {
      const std::size_t want = (op == "Rename") ? 2 : 1;
      const auto cands = pickTopPathCandidates(strings, want, true);
      if (!cands.empty()) fileName = cands[0];
      if (cands.size() > 1) fileName2 = cands[1];
    }
    if (fileName.empty()) fileName = pickBestPathCandidate(strings).value_or("");
    if (fileName.empty()) return;
    eventOp = op;
    eventTarget = fileName;
    if (op == "Rename") eventTarget2 = fileName2;
    dataJson = std::string("{\"fileName\":\"") + jsonEscape(fileName) + "\",\"type\":\"" + op + "\"}";
  } else if (isRegistry) {
    const auto reg = parseRegistryUserDataJson(bytes, desc.Opcode, desc.Id);
    eventOp = reg.type;
    eventTarget = reg.keyPath;
    dataJson = reg.json;
  } else if (isNetwork) {
    const auto op = mapNetworkOp(desc);
    if (op.empty()) return;
    const auto parsed = parseNetworkUserDataHeuristic(bytes, st->netCfg);
    if (!parsed) return;
    eventOp = op;
    eventTarget = parsed->target;
    dataJson = std::string("{\"type\":\"") + op + "\"," + parsed->json.substr(1);
  }

  std::string json;
  json.reserve(256);
  json += "{\"type\":\"log\",\"event\":{";
  json += "\"timestamp\":\"";
  json += jsonEscape(timestamp);
  json += "\",\"pid\":";
  json += std::to_string(eventPid);
  json += ",\"tid\":";
  json += std::to_string(hdr.ThreadId);
  json += ",\"provider\":\"";
  json += provider;
  json += "\",\"opcode\":";
  json += std::to_string(static_cast<unsigned int>(desc.Opcode));
  json += ",\"id\":";
  json += std::to_string(static_cast<unsigned int>(desc.Id));
  json += ",\"data\":";
  json += dataJson;
  json += "}}";
  pushJson(*st, std::move(json));

  if (!eventOp.empty()) {
    anxin::EtwEventInput in;
    in.tsMs = unixMs;
    in.pid = eventPid;
    in.ppid = eventPpid;
    in.provider = providerKind;
    in.op = eventOp;
    in.target = eventTarget;
    in.target2 = eventTarget2;
    in.processImage = eventImage;
    std::optional<anxin::EtwMatchResult> match;
    {
      std::lock_guard<std::mutex> lk(st->engineMu);
      match = st->engine.onEvent(in);
    }
    if (match) {
      std::string mj;
      mj.reserve(512);
      mj += "{\"type\":\"match\",\"pid\":";
      mj += std::to_string(in.pid);
      mj += ",\"match\":{";
      mj += "\"ruleId\":\"";
      mj += jsonEscape(match->ruleId);
      mj += "\",\"threatType\":\"";
      mj += jsonEscape(match->threatType);
      mj += "\",\"severity\":";
      mj += std::to_string(match->severity);
      mj += ",\"recommendAction\":\"";
      mj += jsonEscape(match->recommendAction);
      mj += "\",\"evidence\":[";
      for (std::size_t i = 0; i < match->evidence.size(); i++) {
        if (i) mj += ",";
        mj += "\"";
        mj += jsonEscape(match->evidence[i]);
        mj += "\"";
      }
      mj += "]},\"event\":{";
      mj += "\"timestamp\":\"";
      mj += jsonEscape(timestamp);
      mj += "\",\"provider\":\"";
      mj += jsonEscape(std::string(providerKindName(in.provider)));
      mj += "\",\"op\":\"";
      mj += jsonEscape(in.op);
      mj += "\",\"target\":";
      if (in.target.empty()) {
        mj += "null";
      } else {
        mj += "\"";
        mj += jsonEscape(in.target);
        mj += "\"";
      }
      mj += "},\"context\":[";
      for (std::size_t i = 0; i < match->context.size(); i++) {
        const auto& c = match->context[i];
        if (i) mj += ",";
        mj += "{\"tsMs\":";
        mj += std::to_string(static_cast<unsigned long long>(c.tsMs));
        mj += ",\"provider\":\"";
        mj += jsonEscape(std::string(providerKindName(c.provider)));
        mj += "\",\"op\":\"";
        mj += jsonEscape(c.op);
        mj += "\",\"target\":";
        if (c.target.empty()) {
          mj += "null";
        } else {
          mj += "\"";
          mj += jsonEscape(c.target);
          mj += "\"";
        }
        mj += "}";
      }
      mj += "]}";
      pushJson(*st, std::move(mj));
    }
  }
}

void runTraceThread(EtwBridgeState* st) {
  if (!st) return;
  ULONG status = ProcessTrace(&st->traceHandle, 1, nullptr, nullptr);
  st->running.store(false, std::memory_order_relaxed);
  if (status != ERROR_SUCCESS && !st->stopping.load(std::memory_order_relaxed)) {
    pushError(*st, "ETW_PROCESSTRACE_FAILED", std::string("ProcessTrace failed: ") + std::to_string(status));
  }
}

}  // namespace

extern "C" void* EtwBridge_Create(const wchar_t* sessionName) {
  try {
    auto* st = new EtwBridgeState();
    if (sessionName && sessionName[0]) {
      st->sessionName = sessionName;
    } else {
      st->sessionName = L"AnXinSecuritySession";
    }
    return st;
  } catch (...) {
    return nullptr;
  }
}

extern "C" int EtwBridge_Start(
    void* handle,
    std::uint64_t processAnyKeyword, std::uint64_t processAllKeyword,
    std::uint64_t fileAnyKeyword, std::uint64_t fileAllKeyword,
    std::uint64_t registryAnyKeyword, std::uint64_t registryAllKeyword,
    std::uint64_t networkAnyKeyword, std::uint64_t networkAllKeyword,
    int networkEnabled,
    int filterPrivateIps,
    int skipLoopback,
    std::uint32_t userDataMaxBytes) {
  auto* st = reinterpret_cast<EtwBridgeState*>(handle);
  if (!st) return -1;
  if (st->running.load(std::memory_order_relaxed)) return 0;

  st->netCfg.enabled = networkEnabled != 0;
  st->netCfg.filterPrivateIps = filterPrivateIps != 0;
  st->netCfg.skipLoopback = skipLoopback != 0;
  st->userDataMaxBytes = userDataMaxBytes > 0 ? userDataMaxBytes : 65536;

  st->stopping.store(false, std::memory_order_relaxed);

  ULONG status = ERROR_SUCCESS;

  buildProps(*st);
  auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(st->propertiesBuf.data());

  ControlTraceW(0, st->sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);

  status = StartTraceW(&st->sessionHandle, st->sessionName.c_str(), props);
  if (status == ERROR_ALREADY_EXISTS) {
    ControlTraceW(0, st->sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
    Sleep(150);
    status = StartTraceW(&st->sessionHandle, st->sessionName.c_str(), props);
  }
  if (status != ERROR_SUCCESS) {
    pushError(*st, "ETW_STARTTRACE_FAILED", std::string("StartTraceW failed: ") + std::to_string(status));
    return static_cast<int>(status);
  }

  auto failAfterStart = [&](const char* code, const std::string& message, ULONG stCode) -> int {
    pushError(*st, code, message);
    buildProps(*st);
    auto* p = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(st->propertiesBuf.data());
    ControlTraceW(st->sessionHandle, st->sessionName.c_str(), p, EVENT_TRACE_CONTROL_STOP);
    st->sessionHandle = 0;
    st->traceHandle = 0;
    st->running.store(false, std::memory_order_relaxed);
    return static_cast<int>(stCode);
  };

  std::memset(&st->logfile, 0, sizeof(st->logfile));
  st->logfile.LogFileName = nullptr;
  st->logfile.LoggerName = const_cast<LPWSTR>(st->sessionName.c_str());
  st->logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
  st->logfile.EventRecordCallback = onEventRecord;
  st->logfile.Context = st;

  st->traceHandle = OpenTraceW(&st->logfile);
  if (st->traceHandle == INVALID_PROCESSTRACE_HANDLE) {
    const auto le = GetLastError();
    return failAfterStart("ETW_OPENTRACE_FAILED", std::string("OpenTraceW failed: ") + std::to_string(le), le ? le : static_cast<ULONG>(-2));
  }

  st->running.store(true, std::memory_order_relaxed);
  st->traceThread = std::thread(runTraceThread, st);

  status = EnableTraceEx2(st->sessionHandle, &kGuidKernelProcess, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                          processAnyKeyword, processAllKeyword, 0, nullptr);
  if (status != ERROR_SUCCESS) {
    if (st->traceHandle != 0 && st->traceHandle != INVALID_PROCESSTRACE_HANDLE) {
      CloseTrace(st->traceHandle);
    }
    st->traceHandle = 0;
    if (st->traceThread.joinable()) st->traceThread.join();
    st->running.store(false, std::memory_order_relaxed);
    return failAfterStart("ETW_ENABLE_PROVIDER_FAILED", std::string("EnableTraceEx2(Process) failed: ") + std::to_string(status), status);
  }
  status = EnableTraceEx2(st->sessionHandle, &kGuidKernelFile, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                          fileAnyKeyword, fileAllKeyword, 0, nullptr);
  if (status != ERROR_SUCCESS) {
    if (st->traceHandle != 0 && st->traceHandle != INVALID_PROCESSTRACE_HANDLE) {
      CloseTrace(st->traceHandle);
    }
    st->traceHandle = 0;
    if (st->traceThread.joinable()) st->traceThread.join();
    st->running.store(false, std::memory_order_relaxed);
    return failAfterStart("ETW_ENABLE_PROVIDER_FAILED", std::string("EnableTraceEx2(File) failed: ") + std::to_string(status), status);
  }
  status = EnableTraceEx2(st->sessionHandle, &kGuidKernelRegistry, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                          registryAnyKeyword, registryAllKeyword, 0, nullptr);
  if (status != ERROR_SUCCESS) {
    if (st->traceHandle != 0 && st->traceHandle != INVALID_PROCESSTRACE_HANDLE) {
      CloseTrace(st->traceHandle);
    }
    st->traceHandle = 0;
    if (st->traceThread.joinable()) st->traceThread.join();
    st->running.store(false, std::memory_order_relaxed);
    return failAfterStart("ETW_ENABLE_PROVIDER_FAILED", std::string("EnableTraceEx2(Registry) failed: ") + std::to_string(status), status);
  }
  if (st->netCfg.enabled) {
    status = EnableTraceEx2(st->sessionHandle, &kGuidKernelNetwork, EVENT_CONTROL_CODE_ENABLE_PROVIDER, TRACE_LEVEL_INFORMATION,
                            networkAnyKeyword, networkAllKeyword, 0, nullptr);
    if (status != ERROR_SUCCESS) {
      if (st->traceHandle != 0 && st->traceHandle != INVALID_PROCESSTRACE_HANDLE) {
        CloseTrace(st->traceHandle);
      }
      st->traceHandle = 0;
      if (st->traceThread.joinable()) st->traceThread.join();
      st->running.store(false, std::memory_order_relaxed);
      return failAfterStart("ETW_ENABLE_PROVIDER_FAILED", std::string("EnableTraceEx2(Network) failed: ") + std::to_string(status), status);
    }
  }

  pushStatus(*st, "Monitoring started");
  return 0;
}

extern "C" int EtwBridge_Stop(void* handle, std::uint32_t timeoutMs) {
  auto* st = reinterpret_cast<EtwBridgeState*>(handle);
  if (!st) return -1;
  if (!st->running.load(std::memory_order_relaxed)) return 0;

  st->stopping.store(true, std::memory_order_relaxed);
  buildProps(*st);
  auto* props = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(st->propertiesBuf.data());
  ULONG status = ControlTraceW(st->sessionHandle, st->sessionName.c_str(), props, EVENT_TRACE_CONTROL_STOP);
  (void)status;

  if (st->traceHandle != 0 && st->traceHandle != INVALID_PROCESSTRACE_HANDLE) {
    CloseTrace(st->traceHandle);
  }
  st->traceHandle = 0;

  const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
  while (st->running.load(std::memory_order_relaxed) && std::chrono::steady_clock::now() < deadline) {
    Sleep(25);
  }

  if (st->traceThread.joinable()) st->traceThread.join();

  st->sessionHandle = 0;
  st->running.store(false, std::memory_order_relaxed);
  pushStatus(*st, "Monitoring stopped");
  return 0;
}

extern "C" int EtwBridge_PollJson(void* handle, char** outUtf8Json) {
  if (!outUtf8Json) return -1;
  *outUtf8Json = nullptr;
  auto* st = reinterpret_cast<EtwBridgeState*>(handle);
  if (!st) return -1;
  std::string item;
  {
    std::lock_guard<std::mutex> lk(st->qMu);
    if (st->queue.empty()) return 0;
    item = std::move(st->queue.front());
    st->queue.pop_front();
  }
  if (item.empty()) return 0;

  void* mem = CoTaskMemAlloc(item.size() + 1);
  if (!mem) return -2;
  std::memcpy(mem, item.data(), item.size());
  static_cast<char*>(mem)[item.size()] = '\0';
  *outUtf8Json = static_cast<char*>(mem);
  return 1;
}

extern "C" int EtwBridge_SetRulesJson(void* handle, const char* utf8Json) {
  auto* st = reinterpret_cast<EtwBridgeState*>(handle);
  if (!st) return -1;
  const char* p = utf8Json ? utf8Json : "";
  std::lock_guard<std::mutex> lk(st->engineMu);
  return st->engine.setRulesJson(std::string_view(p, std::strlen(p)));
}

extern "C" int EtwBridge_SetTrackedPids(void* handle, const std::uint32_t* pids, std::uint32_t count, int includeChildren) {
  auto* st = reinterpret_cast<EtwBridgeState*>(handle);
  if (!st) return -1;
  std::lock_guard<std::mutex> lk(st->engineMu);
  return st->engine.setTrackedPids(pids, count, includeChildren != 0);
}

extern "C" int EtwBridge_SetContextCapacity(void* handle, std::uint32_t perPidEvents) {
  auto* st = reinterpret_cast<EtwBridgeState*>(handle);
  if (!st) return -1;
  std::lock_guard<std::mutex> lk(st->engineMu);
  st->engine.setContextCapacity(perPidEvents);
  return 0;
}

extern "C" void EtwBridge_Free(void* p) {
  if (!p) return;
  CoTaskMemFree(p);
}

extern "C" void EtwBridge_Destroy(void* handle) {
  auto* st = reinterpret_cast<EtwBridgeState*>(handle);
  if (!st) return;
  EtwBridge_Stop(st, 2500);
  delete st;
}

#endif
