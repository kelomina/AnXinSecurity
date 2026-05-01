#include "trust_bridge.h"

#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

static int expect(bool cond) {
  return cond ? 0 : 1;
}

static std::wstring getEnvW(const wchar_t* name) {
  wchar_t buf[4096]{};
  DWORD n = GetEnvironmentVariableW(name, buf, static_cast<DWORD>(std::size(buf)));
  if (n == 0 || n >= std::size(buf)) return L"";
  return std::wstring(buf, buf + n);
}

static bool fileExists(const std::wstring& p) {
  const DWORD a = GetFileAttributesW(p.c_str());
  return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static bool writeFileBytes(const std::wstring& p, const std::vector<std::uint8_t>& data) {
  HANDLE h = CreateFileW(p.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) return false;
  DWORD written = 0;
  BOOL ok = WriteFile(h, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
  CloseHandle(h);
  return ok && written == data.size();
}

int main() {
  TrustBridge_SetCacheConfig(1024, 600000);

  const auto sys = getEnvW(L"SystemRoot");
  if (!sys.empty()) {
    const auto notepad = sys + L"\\System32\\notepad.exe";
    if (fileExists(notepad)) {
      unsigned long st = 0;
      const int ok = TrustBridge_VerifyFile(notepad.c_str(), &st);
      if (expect(ok == 0 || ok == 1) != 0) return 1;
      if (expect(st != static_cast<unsigned long>(-1)) != 0) return 2;
      char* signer = nullptr;
      TrustBridge_GetSignerInfoJson(notepad.c_str(), &signer);
      if (signer) TrustBridge_Free(signer);
    }
  }

  const auto tmp = getEnvW(L"TEMP");
  if (tmp.empty()) return 2;
  const auto unsignedPath = tmp + L"\\anxin_unsigned_test.bin";
  std::vector<std::uint8_t> data(1024, 0x41);
  if (expect(writeFileBytes(unsignedPath, data)) != 0) return 3;
  unsigned long st2 = 0;
  const int ok2 = TrustBridge_VerifyFile(unsignedPath.c_str(), &st2);
  if (expect(ok2 == 0) != 0) return 4;

  char* hex = nullptr;
  if (expect(TrustBridge_ComputeFileSha256Hex(unsignedPath.c_str(), &hex) == 0) != 0) return 5;
  if (expect(hex != nullptr) != 0) return 6;
  const std::string h = std::string(hex);
  TrustBridge_Free(hex);
  if (expect(h.size() == 64) != 0) return 7;
  for (char c : h) {
    const bool ok = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    if (expect(ok) != 0) return 8;
  }

  if (expect(TrustBridge_ScanCacheStore(h.c_str(), 2) == 0) != 0) return 9;
  int verdict = 0;
  char* hex2 = nullptr;
  const int hit = TrustBridge_ScanCacheLookupByFile(unsignedPath.c_str(), &verdict, &hex2);
  if (hex2) TrustBridge_Free(hex2);
  if (expect(hit == 1) != 0) return 10;
  if (expect(verdict == 2) != 0) return 11;

  DeleteFileW(unsignedPath.c_str());
  return 0;
}

