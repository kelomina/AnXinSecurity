#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <detours.h>

#include <string>
#include <vector>
#include <cwchar>

using CreateFileWFn = HANDLE(WINAPI*)(
    LPCWSTR,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    HANDLE);

using CreateFileAFn = HANDLE(WINAPI*)(
    LPCSTR,
    DWORD,
    DWORD,
    LPSECURITY_ATTRIBUTES,
    DWORD,
    DWORD,
    HANDLE);

namespace {

constexpr wchar_t kDefaultPipeName[] = L"\\\\.\\pipe\\anxin_security_filehook";
constexpr wchar_t kPipeNameEnv[] = L"ANXIN_HOOK_PIPE";
constexpr DWORD kPipeConnectTimeoutMs = 200;
constexpr DWORD kPipeOpenRetryMs = 20;
constexpr int kPipeOpenRetries = 5;
constexpr DWORD kHeartbeatIntervalMs = 10000;
constexpr DWORD kHeartbeatAckTimeoutMs = 1000;

CreateFileWFn gCreateFileW = ::CreateFileW;
CreateFileAFn gCreateFileA = ::CreateFileA;
CreateFileWFn gKernelBaseCreateFileW = nullptr;
CreateFileAFn gKernelBaseCreateFileA = nullptr;
thread_local bool gInsideHook = false;
HMODULE gSelfModule = nullptr;
HANDLE gHeartbeatThread = nullptr;
volatile LONG gHeartbeatStop = 0;

void detachDetours();

std::wstring readPipeName() {
  wchar_t value[512]{};
  DWORD n = ::GetEnvironmentVariableW(kPipeNameEnv, value, static_cast<DWORD>(std::size(value)));
  if (n == 0 || n >= static_cast<DWORD>(std::size(value))) {
    return std::wstring(kDefaultPipeName);
  }
  return std::wstring(value, value + n);
}

std::string utf8FromWide(const wchar_t* ws) {
  if (!ws || !*ws) return {};
  int len = ::WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
  if (len <= 1) return {};
  std::string out(static_cast<std::size_t>(len - 1), '\0');
  int written = ::WideCharToMultiByte(CP_UTF8, 0, ws, -1, out.data(), len - 1, nullptr, nullptr);
  if (written <= 0) return {};
  return out;
}

std::wstring wideFromAnsi(const char* s) {
  if (!s || !*s) return {};
  int wlen = ::MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
  if (wlen <= 1) return {};
  std::wstring ws(static_cast<std::size_t>(wlen - 1), L'\0');
  int wwritten = ::MultiByteToWideChar(CP_ACP, 0, s, -1, ws.data(), wlen - 1);
  if (wwritten <= 0) return {};
  return ws;
}

void appendEscaped(std::string& out, const std::string& text) {
  for (unsigned char c : text) {
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
          wsprintfA(buf, "\\u%04x", static_cast<unsigned int>(c));
          out += buf;
        } else {
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
}

std::wstring deviceToDosPath(const std::wstring& path) {
  if (path.empty()) return path;
  if (_wcsnicmp(path.c_str(), L"\\Device\\", 8) != 0) return path;
  wchar_t drives[512]{};
  DWORD n = ::GetLogicalDriveStringsW(static_cast<DWORD>(std::size(drives)), drives);
  if (n == 0 || n >= static_cast<DWORD>(std::size(drives))) return path;
  for (wchar_t* p = drives; *p; p += wcslen(p) + 1) {
    std::wstring drive = p;
    if (drive.size() < 2) continue;
    std::wstring devName = drive.substr(0, 2);
    wchar_t target[512]{};
    DWORD tn = ::QueryDosDeviceW(devName.c_str(), target, static_cast<DWORD>(std::size(target)));
    if (tn == 0) continue;
    std::wstring devPath = target;
    if (_wcsnicmp(path.c_str(), devPath.c_str(), devPath.size()) == 0) {
      std::wstring rest = path.substr(devPath.size());
      if (!rest.empty() && rest.front() != L'\\') rest.insert(rest.begin(), L'\\');
      return drive + rest;
    }
  }
  return path;
}

std::wstring normalizePathW(const wchar_t* ws) {
  if (!ws || !*ws) return {};
  std::wstring s(ws);
  if (_wcsnicmp(s.c_str(), L"\\??\\", 4) == 0) {
    s = s.substr(4);
  }
  if (_wcsnicmp(s.c_str(), L"\\\\?\\UNC\\", 8) == 0) {
    s = L"\\" + s.substr(7);
  } else if (_wcsnicmp(s.c_str(), L"\\\\?\\", 4) == 0) {
    s = s.substr(4);
  }
  if (s.size() >= 2 && s[1] == L':') return s;
  if (s.rfind(L"\\\\", 0) == 0) return s;
  if (_wcsnicmp(s.c_str(), L"\\Device\\", 8) == 0) return deviceToDosPath(s);
  wchar_t buf[4096]{};
  DWORD len = ::GetFullPathNameW(s.c_str(), static_cast<DWORD>(std::size(buf)), buf, nullptr);
  if (len > 0 && len < static_cast<DWORD>(std::size(buf))) return std::wstring(buf, buf + len);
  return s;
}

std::string utf8FromWideAbs(const wchar_t* ws) {
  std::wstring norm = normalizePathW(ws);
  return utf8FromWide(norm.c_str());
}

std::string utf8FromAnsiAbs(const char* s) {
  std::wstring ws = wideFromAnsi(s);
  return utf8FromWideAbs(ws.c_str());
}

std::string pathFromHandleUtf8(HANDLE h) {
  if (!h || h == INVALID_HANDLE_VALUE) return {};
  wchar_t buf[4096]{};
  DWORD len = ::GetFinalPathNameByHandleW(h, buf, static_cast<DWORD>(std::size(buf)), FILE_NAME_NORMALIZED);
  if (len == 0 || len >= static_cast<DWORD>(std::size(buf))) return {};
  return utf8FromWideAbs(buf);
}

std::string buildMessage(const char* apiName, const std::string& filePathUtf8) {
  std::string out;
  out.reserve(320 + filePathUtf8.size());
  out += "{\"type\":\"hook_notice\",\"source\":\"detours_createfile\",\"api\":\"";
  appendEscaped(out, apiName ? std::string(apiName) : std::string("CreateFile"));
  out += "\",\"pid\":";
  out += std::to_string(::GetCurrentProcessId());
  out += ",\"tid\":";
  out += std::to_string(::GetCurrentThreadId());
  out += ",\"ts\":";
  out += std::to_string(::GetTickCount64());
  out += ",\"path\":\"";
  appendEscaped(out, filePathUtf8);
  out += "\"}\n";
  return out;
}

std::string buildHeartbeat() {
  std::string out;
  out.reserve(160);
  out += "{\"type\":\"heartbeat\",\"pid\":";
  out += std::to_string(::GetCurrentProcessId());
  out += ",\"ts\":";
  out += std::to_string(::GetTickCount64());
  out += "}\n";
  return out;
}

HANDLE openPipeHandle(const std::wstring& pipeName, DWORD desiredAccess) {
  for (int i = 0; i < kPipeOpenRetries; ++i) {
    if (!::WaitNamedPipeW(pipeName.c_str(), kPipeConnectTimeoutMs)) {
      DWORD err = ::GetLastError();
      if (err == ERROR_PIPE_BUSY) {
        ::Sleep(kPipeOpenRetryMs);
        continue;
      }
      return INVALID_HANDLE_VALUE;
    }
    HANDLE hPipe = ::CreateFileW(
        pipeName.c_str(),
        desiredAccess,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hPipe != INVALID_HANDLE_VALUE) return hPipe;
    DWORD err = ::GetLastError();
    if (err == ERROR_PIPE_BUSY) {
      ::Sleep(kPipeOpenRetryMs);
      continue;
    }
    return INVALID_HANDLE_VALUE;
  }
  return INVALID_HANDLE_VALUE;
}

bool waitHeartbeatAck(HANDLE hPipe) {
  DWORD start = ::GetTickCount();
  std::string buf;
  buf.reserve(256);
  while (::GetTickCount() - start < kHeartbeatAckTimeoutMs) {
    DWORD avail = 0;
    if (!::PeekNamedPipe(hPipe, nullptr, 0, nullptr, &avail, nullptr)) return false;
    if (avail > 0) {
      char tmp[256]{};
      DWORD toRead = avail > 255 ? 255 : avail;
      DWORD read = 0;
      if (!::ReadFile(hPipe, tmp, toRead, &read, nullptr)) return false;
      if (read > 0) {
        buf.append(tmp, tmp + read);
        if (buf.find("heartbeat_ack") != std::string::npos) return true;
        if (buf.find("ok") != std::string::npos) return true;
      }
    }
    ::Sleep(20);
  }
  return false;
}

DWORD WINAPI heartbeatThreadProc(LPVOID) {
  int missed = 0;
  while (::InterlockedCompareExchange(&gHeartbeatStop, 0, 0) == 0) {
    std::wstring pipeName = readPipeName();
    bool ok = false;
    if (!pipeName.empty()) {
      HANDLE hPipe = openPipeHandle(pipeName, GENERIC_READ | GENERIC_WRITE);
      if (hPipe != INVALID_HANDLE_VALUE) {
        std::string payload = buildHeartbeat();
        DWORD written = 0;
        if (::WriteFile(hPipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr)) {
          ok = waitHeartbeatAck(hPipe);
        }
        ::CloseHandle(hPipe);
      }
    }
    if (ok) {
      missed = 0;
    } else {
      missed += 1;
      if (missed >= 2) {
        detachDetours();
        if (gSelfModule) {
          ::FreeLibraryAndExitThread(gSelfModule, 0);
        }
        return 0;
      }
    }
    DWORD slept = 0;
    while (slept < kHeartbeatIntervalMs && ::InterlockedCompareExchange(&gHeartbeatStop, 0, 0) == 0) {
      ::Sleep(200);
      slept += 200;
    }
  }
  return 0;
}

void sendNotice(const char* apiName, const std::string& pathUtf8) {
  std::wstring pipeName = readPipeName();
  if (pipeName.empty()) return;
  HANDLE hPipe = openPipeHandle(pipeName, GENERIC_WRITE);
  if (hPipe == INVALID_HANDLE_VALUE) return;
  std::string payload = buildMessage(apiName, pathUtf8);
  DWORD written = 0;
  ::WriteFile(hPipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
  ::CloseHandle(hPipe);
}

class HookGuard {
 public:
  HookGuard() : entered_(!gInsideHook) {
    if (entered_) gInsideHook = true;
  }
  ~HookGuard() {
    if (entered_) gInsideHook = false;
  }
  bool entered() const { return entered_; }
 private:
  bool entered_{false};
};

HANDLE WINAPI HookCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) {
  HookGuard guard;
  HANDLE h = gCreateFileW(
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile);
  if (guard.entered()) {
    std::string path = pathFromHandleUtf8(h);
    if (path.empty()) path = utf8FromWideAbs(lpFileName);
    if (!path.empty()) sendNotice("CreateFileW", path);
  }
  return h;
}

HANDLE WINAPI HookCreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) {
  HookGuard guard;
  HANDLE h = gCreateFileA(
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile);
  if (guard.entered()) {
    std::string path = pathFromHandleUtf8(h);
    if (path.empty()) path = utf8FromAnsiAbs(lpFileName);
    if (!path.empty()) sendNotice("CreateFileA", path);
  }
  return h;
}

void attachDetours() {
  HMODULE kernelBase = ::GetModuleHandleW(L"KernelBase.dll");
  if (kernelBase) {
    gKernelBaseCreateFileW = reinterpret_cast<CreateFileWFn>(::GetProcAddress(kernelBase, "CreateFileW"));
    gKernelBaseCreateFileA = reinterpret_cast<CreateFileAFn>(::GetProcAddress(kernelBase, "CreateFileA"));
  }

  if (DetourTransactionBegin() != NO_ERROR) return;
  if (DetourUpdateThread(::GetCurrentThread()) != NO_ERROR) {
    DetourTransactionAbort();
    return;
  }

  DetourAttach(reinterpret_cast<PVOID*>(&gCreateFileW), HookCreateFileW);
  DetourAttach(reinterpret_cast<PVOID*>(&gCreateFileA), HookCreateFileA);
  if (gKernelBaseCreateFileW) {
    DetourAttach(reinterpret_cast<PVOID*>(&gKernelBaseCreateFileW), HookCreateFileW);
  }
  if (gKernelBaseCreateFileA) {
    DetourAttach(reinterpret_cast<PVOID*>(&gKernelBaseCreateFileA), HookCreateFileA);
  }

  DetourTransactionCommit();
}

void detachDetours() {
  if (DetourTransactionBegin() != NO_ERROR) return;
  if (DetourUpdateThread(::GetCurrentThread()) != NO_ERROR) {
    DetourTransactionAbort();
    return;
  }

  DetourDetach(reinterpret_cast<PVOID*>(&gCreateFileW), HookCreateFileW);
  DetourDetach(reinterpret_cast<PVOID*>(&gCreateFileA), HookCreateFileA);
  if (gKernelBaseCreateFileW) {
    DetourDetach(reinterpret_cast<PVOID*>(&gKernelBaseCreateFileW), HookCreateFileW);
  }
  if (gKernelBaseCreateFileA) {
    DetourDetach(reinterpret_cast<PVOID*>(&gKernelBaseCreateFileA), HookCreateFileA);
  }

  DetourTransactionCommit();
}

}  

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    gSelfModule = hinst;
    ::DisableThreadLibraryCalls(hinst);
    DetourRestoreAfterWith();
    attachDetours();
    ::InterlockedExchange(&gHeartbeatStop, 0);
    gHeartbeatThread = ::CreateThread(nullptr, 0, heartbeatThreadProc, nullptr, 0, nullptr);
  } else if (reason == DLL_PROCESS_DETACH) {
    ::InterlockedExchange(&gHeartbeatStop, 1);
    if (gHeartbeatThread) {
      ::CloseHandle(gHeartbeatThread);
      gHeartbeatThread = nullptr;
    }
    detachDetours();
  }
  return TRUE;
}
