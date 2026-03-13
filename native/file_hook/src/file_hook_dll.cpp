#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <detours.h>

#include <string>
#include <vector>

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

CreateFileWFn gCreateFileW = ::CreateFileW;
CreateFileAFn gCreateFileA = ::CreateFileA;
CreateFileWFn gKernelBaseCreateFileW = nullptr;
CreateFileAFn gKernelBaseCreateFileA = nullptr;
thread_local bool gInsideHook = false;

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

std::string utf8FromAnsi(const char* s) {
  if (!s || !*s) return {};
  int wlen = ::MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
  if (wlen <= 1) return {};
  std::wstring ws(static_cast<std::size_t>(wlen - 1), L'\0');
  int wwritten = ::MultiByteToWideChar(CP_ACP, 0, s, -1, ws.data(), wlen - 1);
  if (wwritten <= 0) return {};
  return utf8FromWide(ws.c_str());
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

HANDLE openPipeHandle(const std::wstring& pipeName) {
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
        GENERIC_WRITE,
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

void sendNotice(const char* apiName, const std::string& pathUtf8) {
  std::wstring pipeName = readPipeName();
  if (pipeName.empty()) return;
  HANDLE hPipe = openPipeHandle(pipeName);
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
  if (guard.entered()) {
    sendNotice("CreateFileW", utf8FromWide(lpFileName));
  }
  return gCreateFileW(
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile);
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
  if (guard.entered()) {
    sendNotice("CreateFileA", utf8FromAnsi(lpFileName));
  }
  return gCreateFileA(
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile);
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
    ::DisableThreadLibraryCalls(hinst);
    DetourRestoreAfterWith();
    attachDetours();
  } else if (reason == DLL_PROCESS_DETACH) {
    detachDetours();
  }
  return TRUE;
}
