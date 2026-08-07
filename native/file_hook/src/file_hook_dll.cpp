#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <detours.h>

#include <string>
#include <vector>
#include <cwchar>
#include <cstdint>
#include <mutex>
#include <sstream>
#include <unordered_map>
#include <deque>
#include <iostream>
#include <fstream>

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

using OpenProcessFn = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using VirtualAllocExFn = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
using WriteProcessMemoryFn = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
using CreateRemoteThreadFn = HANDLE(WINAPI*)(
    HANDLE,
    LPSECURITY_ATTRIBUTES,
    SIZE_T,
    LPTHREAD_START_ROUTINE,
    LPVOID,
    DWORD,
    LPDWORD);
using CreateRemoteThreadExFn = HANDLE(WINAPI*)(
    HANDLE,
    LPSECURITY_ATTRIBUTES,
    SIZE_T,
    LPTHREAD_START_ROUTINE,
    LPVOID,
    DWORD,
    LPPROC_THREAD_ATTRIBUTE_LIST,
    LPDWORD);
using NtCreateThreadExFn = LONG(WINAPI*)(
    PHANDLE,
    ACCESS_MASK,
    LPVOID,
    HANDLE,
    LPTHREAD_START_ROUTINE,
    LPVOID,
    ULONG,
    SIZE_T,
    SIZE_T,
    SIZE_T,
    LPVOID);
using NtSuspendProcessFn = LONG(WINAPI*)(HANDLE);
using NtResumeProcessFn = LONG(WINAPI*)(HANDLE);

namespace {

constexpr wchar_t kDefaultPipeName[] = L"\\\\.\\pipe\\anxin_security_filehook";
constexpr wchar_t kPipeNameEnv[] = L"ANXIN_HOOK_PIPE";
constexpr DWORD kPipeConnectTimeoutMs = 200;
constexpr DWORD kPipeOpenRetryMs = 20;
constexpr int kPipeOpenRetries = 50;
constexpr DWORD kPipeCachedHandleTtlMs = 3000;
constexpr DWORD kHeartbeatIntervalMs = 10000;
constexpr DWORD kHeartbeatAckTimeoutMs = 1000;
constexpr ULONGLONG kInjectionChainWindowMs = 5000;
constexpr std::size_t kMaxTrackedProcessHandles = 2048;
constexpr std::size_t kMaxTrackedInjectionChains = 1024;

struct NativeInjectionChain {
  ULONGLONG startedAt{0};
  ULONGLONG lastSeen{0};
  bool sawOpenProcess{false};
  bool sawVirtualAllocEx{false};
  bool sawWriteProcessMemory{false};
  std::string baseAddress;
  SIZE_T size{0};
};

CreateFileWFn gCreateFileW = ::CreateFileW;
CreateFileAFn gCreateFileA = ::CreateFileA;
CreateFileWFn gKernelBaseCreateFileW = nullptr;
CreateFileAFn gKernelBaseCreateFileA = nullptr;
OpenProcessFn gOpenProcess = ::OpenProcess;
VirtualAllocExFn gVirtualAllocEx = ::VirtualAllocEx;
WriteProcessMemoryFn gWriteProcessMemory = ::WriteProcessMemory;
CreateRemoteThreadFn gCreateRemoteThread = ::CreateRemoteThread;
CreateRemoteThreadExFn gCreateRemoteThreadEx = nullptr;
OpenProcessFn gKernelBaseOpenProcess = nullptr;
VirtualAllocExFn gKernelBaseVirtualAllocEx = nullptr;
WriteProcessMemoryFn gKernelBaseWriteProcessMemory = nullptr;
CreateRemoteThreadFn gKernelBaseCreateRemoteThread = nullptr;
CreateRemoteThreadExFn gKernelBaseCreateRemoteThreadEx = nullptr;
HMODULE gNtdll = nullptr;
NtCreateThreadExFn gNtCreateThreadEx = nullptr;
NtSuspendProcessFn gNtSuspendProcess = nullptr;
NtResumeProcessFn gNtResumeProcess = nullptr;
thread_local bool gInsideHook = false;
HMODULE gSelfModule = nullptr;
HANDLE gHeartbeatThread = nullptr;
volatile LONG gHeartbeatStop = 0;
std::mutex gProcessStateMutex;
std::mutex gPipeWriteMutex;
HANDLE gCachedPipeHandle = INVALID_HANDLE_VALUE;
std::wstring gCachedPipeName;
ULONGLONG gCachedPipeLastUsed = 0;
std::unordered_map<std::uintptr_t, DWORD> gProcessHandleTargets;
/*
 * VUL-050: LRU 逐出辅助队列。记录句柄的插入顺序，当 gProcessHandleTargets
 * 超过上限时，从队列头部弹出最旧的句柄并从 map 中删除，而非全表清空。
 * 全表清空会被攻击者利用：先用 2048+ 个可疑句柄填满表触发 clear()，
 * 然后后续的 CreateRemoteThread 因查不到目标 PID 而不被阻断。
 *
 * VUL-050: LRU eviction queue. Records insertion order of handles so
 * that when gProcessHandleTargets exceeds the limit, the oldest entry
 * is evicted individually instead of clearing the whole table. The old
 * clear() behavior was exploitable: an attacker fills the table with
 * 2048+ suspicious handles to trigger clear(), then a subsequent
 * CreateRemoteThread finds no target PID and is not blocked.
 */
std::deque<std::uintptr_t> gProcessHandleLru;
std::unordered_map<unsigned long long, NativeInjectionChain> gInjectionChains;

void detachDetours();

std::wstring readPipeName() {
  /*
   * VUL-051: 不再从环境变量 ANXIN_HOOK_PIPE 读取管道名。
   * 被注入进程的环境块由其父进程完全控制，恶意父进程可设置
   * ANXIN_HOOK_PIPE 指向攻击者管道，接收全部 hook 上报并回复 ACK 维持
   * hook 存活，真实服务端对该进程无可见性。
   * 现在直接使用硬编码的默认管道名。
   *
   * VUL-051: No longer read the pipe name from the ANXIN_HOOK_PIPE
   * environment variable. The injected process's environment block is
   * fully controlled by its parent, which could set ANXIN_HOOK_PIPE to
   * an attacker-controlled pipe to receive all hook reports and reply
   * with ACKs to keep the hook alive, blinding the real service.
   * Now uses the hardcoded default pipe name directly.
   */
  return std::wstring(kDefaultPipeName);
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

std::string currentProcessPathUtf8() {
  wchar_t buf[4096]{};
  DWORD len = ::GetModuleFileNameW(nullptr, buf, static_cast<DWORD>(std::size(buf)));
  if (len == 0 || len >= static_cast<DWORD>(std::size(buf))) return {};
  return utf8FromWideAbs(buf);
}

std::string pathFromHandleUtf8(HANDLE h) {
  if (!h || h == INVALID_HANDLE_VALUE) return {};
  wchar_t buf[4096]{};
  DWORD len = ::GetFinalPathNameByHandleW(h, buf, static_cast<DWORD>(std::size(buf)), FILE_NAME_NORMALIZED);
  if (len == 0 || len >= static_cast<DWORD>(std::size(buf))) return {};
  return utf8FromWideAbs(buf);
}

std::wstring processPathFromHandleW(HANDLE h) {
  if (!h || h == INVALID_HANDLE_VALUE) return {};
  wchar_t buf[4096]{};
  DWORD size = static_cast<DWORD>(std::size(buf));
  if (::QueryFullProcessImageNameW(h, 0, buf, &size) && size > 0 && size < static_cast<DWORD>(std::size(buf))) {
    return normalizePathW(buf);
  }
  return {};
}

std::wstring processPathFromPidW(DWORD pid) {
  if (pid == 0 || pid == 4 || pid == ::GetCurrentProcessId()) return {};
  HANDLE h = nullptr;
  if (gOpenProcess) {
    h = gOpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  } else {
    h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  }
  if (!h) return {};
  std::wstring path = processPathFromHandleW(h);
  ::CloseHandle(h);
  return path;
}

std::wstring lowerWide(std::wstring value) {
  for (auto& ch : value) {
    if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
  }
  return value;
}

std::wstring fileNameFromPathW(const std::wstring& path) {
  std::size_t pos = path.find_last_of(L"\\/");
  if (pos == std::wstring::npos) return path;
  return path.substr(pos + 1);
}

bool isProtectedProcessNameW(const std::wstring& processName) {
  std::wstring name = lowerWide(processName);
  return name == L"csrss.exe" ||
      name == L"smss.exe" ||
      name == L"wininit.exe" ||
      name == L"services.exe" ||
      name == L"lsass.exe" ||
      name == L"winlogon.exe" ||
      name == L"system" ||
      name == L"system idle process" ||
      name == L"anxin-security.exe" ||
      name == L"anxinsecurity.exe";
}

bool shouldNeverSuspendTarget(DWORD targetPid, HANDLE hProcess) {
  if (targetPid == 0 || targetPid == 4 || targetPid == ::GetCurrentProcessId()) return true;
  std::wstring path = processPathFromHandleW(hProcess);
  if (path.empty()) {
    path = processPathFromPidW(targetPid);
  }
  if (path.empty()) {
    return true;
  }
  return isProtectedProcessNameW(fileNameFromPathW(path));
}

std::string hexFromPtr(const void* ptr) {
  if (!ptr) return {};
  std::ostringstream oss;
  oss << "0x" << std::hex << reinterpret_cast<std::uintptr_t>(ptr);
  return oss.str();
}

void appendStringField(std::string& out, const char* name, const std::string& value) {
  if (value.empty()) return;
  out += ",\"";
  out += name;
  out += "\":\"";
  appendEscaped(out, value);
  out += "\"";
}

void appendBoolField(std::string& out, const char* name, bool value) {
  out += ",\"";
  out += name;
  out += "\":";
  out += value ? "true" : "false";
}

void appendU64Field(std::string& out, const char* name, unsigned long long value) {
  out += ",\"";
  out += name;
  out += "\":";
  out += std::to_string(value);
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

std::string buildProcessInjectionMessage(
    const char* apiName,
    DWORD targetPid,
    DWORD desiredAccess,
    const std::string& baseAddress,
    SIZE_T size,
    const std::string& startAddress,
    bool blocked,
    bool targetSuspended,
    DWORD lastError,
    const std::string& chain) {
  std::string out;
  out.reserve(512);
  out += "{\"type\":\"hook_notice\",\"source\":\"detours_process_injection\",\"api\":\"";
  appendEscaped(out, apiName ? std::string(apiName) : std::string("ProcessApi"));
  out += "\",\"pid\":";
  out += std::to_string(::GetCurrentProcessId());
  out += ",\"tid\":";
  out += std::to_string(::GetCurrentThreadId());
  out += ",\"ts\":";
  out += std::to_string(::GetTickCount64());
  appendStringField(out, "processPath", currentProcessPathUtf8());
  appendU64Field(out, "targetPid", static_cast<unsigned long long>(targetPid));
  if (desiredAccess != 0) {
    appendU64Field(out, "desiredAccess", static_cast<unsigned long long>(desiredAccess));
  }
  appendStringField(out, "baseAddress", baseAddress);
  if (size != 0) {
    appendU64Field(out, "size", static_cast<unsigned long long>(size));
  }
  appendStringField(out, "startAddress", startAddress);
  appendBoolField(out, "blocked", blocked);
  appendBoolField(out, "targetSuspended", targetSuspended);
  if (lastError != 0) {
    appendU64Field(out, "lastError", static_cast<unsigned long long>(lastError));
  }
  appendStringField(out, "chain", chain);
  out += "}\n";
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
      if (err == ERROR_PIPE_BUSY || err == ERROR_FILE_NOT_FOUND || err == ERROR_SEM_TIMEOUT) {
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

void closeCachedPipeHandleLocked() {
  if (gCachedPipeHandle != INVALID_HANDLE_VALUE) {
    ::CloseHandle(gCachedPipeHandle);
    gCachedPipeHandle = INVALID_HANDLE_VALUE;
  }
  gCachedPipeName.clear();
  gCachedPipeLastUsed = 0;
}

HANDLE getCachedPipeHandleLocked(const std::wstring& pipeName, DWORD* lastError) {
  if (lastError) *lastError = 0;

  ULONGLONG now = ::GetTickCount64();
  if (gCachedPipeHandle != INVALID_HANDLE_VALUE) {
    if (gCachedPipeName == pipeName && now - gCachedPipeLastUsed <= kPipeCachedHandleTtlMs) {
      return gCachedPipeHandle;
    }
    closeCachedPipeHandleLocked();
  }

  HANDLE hPipe = openPipeHandle(pipeName, GENERIC_WRITE);
  if (hPipe == INVALID_HANDLE_VALUE) {
    if (lastError) *lastError = ::GetLastError();
    return INVALID_HANDLE_VALUE;
  }

  gCachedPipeHandle = hPipe;
  gCachedPipeName = pipeName;
  gCachedPipeLastUsed = now;
  return gCachedPipeHandle;
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

void appendDetoursDiagnostic(const char* stage, const std::string& payloadFields);

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

bool sendPayload(const std::string& payload, DWORD* lastError = nullptr) {
  if (lastError) *lastError = 0;
  std::wstring pipeName = readPipeName();
  if (pipeName.empty()) {
    if (lastError) *lastError = ERROR_INVALID_NAME;
    return false;
  }
  std::lock_guard<std::mutex> lock(gPipeWriteMutex);

  for (int attempt = 0; attempt < 2; ++attempt) {
    DWORD openError = 0;
    HANDLE hPipe = getCachedPipeHandleLocked(pipeName, &openError);
    if (hPipe == INVALID_HANDLE_VALUE) {
      if (lastError) *lastError = openError != 0 ? openError : ::GetLastError();
      return false;
    }

    DWORD written = 0;
    BOOL ok =
        ::WriteFile(hPipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
    DWORD err = ok ? 0 : ::GetLastError();
    if (ok && written == static_cast<DWORD>(payload.size())) {
      gCachedPipeLastUsed = ::GetTickCount64();
      return true;
    }

    // 同一条注入链会在毫秒级连续上报多条消息。若服务端刚好关闭了上一根
    // pipe 实例，缓存句柄会在这里失效；关闭后重连一次，避免事件链中段丢失。
    closeCachedPipeHandleLocked();
    if (attempt == 0 && (err == ERROR_BROKEN_PIPE || err == ERROR_NO_DATA || err == ERROR_PIPE_NOT_CONNECTED)) {
      continue;
    }
    if (lastError) *lastError = ok ? ERROR_WRITE_FAULT : err;
    return false;
  }

  if (lastError) *lastError = ERROR_WRITE_FAULT;
  return false;
}

void sendNotice(const char* apiName, const std::string& pathUtf8) {
  (void)sendPayload(buildMessage(apiName, pathUtf8));
}

bool sendProcessInjectionNotice(
    const char* apiName,
    DWORD targetPid,
    DWORD desiredAccess,
    const std::string& baseAddress,
    SIZE_T size,
    const std::string& startAddress,
    bool blocked,
    bool targetSuspended,
    DWORD lastError,
    const std::string& chain) {
  if (targetPid == 0 || targetPid == 4 || targetPid == ::GetCurrentProcessId()) {
    std::string diag;
    diag += "\"api\":\"";
    appendEscaped(diag, apiName ? std::string(apiName) : std::string("ProcessApi"));
    diag += "\",\"targetPid\":";
    diag += std::to_string(targetPid);
    diag += ",\"blocked\":";
    diag += blocked ? "true" : "false";
    diag += ",\"targetSuspended\":";
    diag += targetSuspended ? "true" : "false";
    diag += ",\"skipReason\":\"invalid_or_self_target\"";
    appendDetoursDiagnostic("process_injection_notice_skipped", diag);
    return false;
  }
  DWORD pipeError = 0;
  bool reported = sendPayload(buildProcessInjectionMessage(
      apiName,
      targetPid,
      desiredAccess,
      baseAddress,
      size,
      startAddress,
      blocked,
      targetSuspended,
      lastError,
      chain),
      &pipeError);
  std::string diag;
  diag += "\"api\":\"";
  appendEscaped(diag, apiName ? std::string(apiName) : std::string("ProcessApi"));
  diag += "\",\"targetPid\":";
  diag += std::to_string(targetPid);
  diag += ",\"blocked\":";
  diag += blocked ? "true" : "false";
  diag += ",\"targetSuspended\":";
  diag += targetSuspended ? "true" : "false";
  diag += ",\"reported\":";
  diag += reported ? "true" : "false";
  diag += ",\"pipeError\":";
  diag += std::to_string(pipeError);
  diag += ",\"lastError\":";
  diag += std::to_string(lastError);
  appendStringField(diag, "chain", chain);
  appendStringField(diag, "baseAddress", baseAddress);
  appendStringField(diag, "startAddress", startAddress);
  if (size != 0) {
    appendU64Field(diag, "size", static_cast<unsigned long long>(size));
  }
  appendDetoursDiagnostic("process_injection_notice_sent", diag);
  if (!reported) {
    std::cerr << "[file_hook_detours] failed to report injection event api="
              << (apiName ? apiName : "ProcessApi")
              << " targetPid=" << targetPid
              << " blocked=" << (blocked ? 1 : 0)
              << " targetSuspended=" << (targetSuspended ? 1 : 0)
              << " pipeError=" << pipeError
              << std::endl;
  }
  return reported;
}

bool suspiciousOpenProcessAccess(DWORD desiredAccess) {
  constexpr DWORD kSuspiciousAccess =
      PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
  return (desiredAccess & kSuspiciousAccess) != 0;
}

unsigned long long injectionChainKey(DWORD sourcePid, DWORD targetPid) {
  return (static_cast<unsigned long long>(sourcePid) << 32) |
      static_cast<unsigned long long>(targetPid);
}

void pruneInjectionChainsLocked(ULONGLONG now) {
  for (auto it = gInjectionChains.begin(); it != gInjectionChains.end();) {
    if (now - it->second.lastSeen > kInjectionChainWindowMs) {
      it = gInjectionChains.erase(it);
    } else {
      ++it;
    }
  }
  while (gInjectionChains.size() > kMaxTrackedInjectionChains) {
    auto oldest = gInjectionChains.begin();
    for (auto it = gInjectionChains.begin(); it != gInjectionChains.end(); ++it) {
      if (it->second.lastSeen < oldest->second.lastSeen) oldest = it;
    }
    gInjectionChains.erase(oldest);
  }
}

NativeInjectionChain& chainForTargetLocked(DWORD targetPid, ULONGLONG now) {
  unsigned long long key = injectionChainKey(::GetCurrentProcessId(), targetPid);
  auto& chain = gInjectionChains[key];
  if (chain.startedAt == 0 || now - chain.startedAt > kInjectionChainWindowMs) {
    chain = NativeInjectionChain{};
    chain.startedAt = now;
  }
  chain.lastSeen = now;
  return chain;
}

void recordProcessHandle(HANDLE hProcess, DWORD targetPid) {
  if (!hProcess || hProcess == INVALID_HANDLE_VALUE || targetPid == 0) return;
  std::lock_guard<std::mutex> lock(gProcessStateMutex);
  std::uintptr_t key = reinterpret_cast<std::uintptr_t>(hProcess);
  /*
   * VUL-050: 若句柄已存在则先从 LRU 队列移除旧条目（避免重复），
   * 然后重新插入队尾以更新其 LRU 顺序。新句柄直接插入 map 和队尾。
   *
   * VUL-050: If the handle already exists, first remove its old entry from
   * the LRU queue (to avoid duplicates), then re-push to the back to
   * refresh its LRU order. New handles are inserted into the map and the
   * queue back directly.
   */
  if (gProcessHandleTargets.find(key) != gProcessHandleTargets.end()) {
    for (auto it = gProcessHandleLru.begin(); it != gProcessHandleLru.end(); ++it) {
      if (*it == key) { gProcessHandleLru.erase(it); break; }
    }
  }
  gProcessHandleTargets[key] = targetPid;
  gProcessHandleLru.push_back(key);
  /*
   * VUL-050: 超过上限时逐出最旧条目（队头），而非全表清空。
   * 逐出是 O(1) 的，且保留了其他有效条目，防止攻击者刷量致盲检测。
   *
   * VUL-050: Evict the oldest entry (queue front) when over the limit,
   * instead of clearing the whole table. Eviction is O(1) and preserves
   * other valid entries, preventing attackers from blinding detection by
   * flooding the table.
   */
  while (gProcessHandleTargets.size() > kMaxTrackedProcessHandles && !gProcessHandleLru.empty()) {
    std::uintptr_t oldest = gProcessHandleLru.front();
    gProcessHandleLru.pop_front();
    gProcessHandleTargets.erase(oldest);
  }
}

DWORD targetPidFromProcessHandle(HANDLE hProcess) {
  if (!hProcess || hProcess == INVALID_HANDLE_VALUE) return 0;
  DWORD pid = ::GetProcessId(hProcess);
  if (pid != 0) {
    recordProcessHandle(hProcess, pid);
    return pid;
  }
  std::lock_guard<std::mutex> lock(gProcessStateMutex);
  auto it = gProcessHandleTargets.find(reinterpret_cast<std::uintptr_t>(hProcess));
  if (it == gProcessHandleTargets.end()) return 0;
  return it->second;
}

void updateNativeInjectionChain(
    DWORD targetPid,
    const char* apiName,
    const std::string& baseAddress,
    SIZE_T size) {
  if (targetPid == 0 || targetPid == 4 || targetPid == ::GetCurrentProcessId()) return;
  ULONGLONG now = ::GetTickCount64();
  std::lock_guard<std::mutex> lock(gProcessStateMutex);
  pruneInjectionChainsLocked(now);
  auto& chain = chainForTargetLocked(targetPid, now);
  std::string api = apiName ? apiName : "";
  if (api == "OpenProcess") {
    chain.sawOpenProcess = true;
  } else if (api == "VirtualAllocEx") {
    chain.sawVirtualAllocEx = true;
    chain.baseAddress = baseAddress;
    chain.size = size;
  } else if (api == "WriteProcessMemory") {
    chain.sawWriteProcessMemory = true;
    if (!baseAddress.empty()) chain.baseAddress = baseAddress;
    if (size != 0) chain.size = size;
  }
}

bool shouldBlockRemoteThread(
    DWORD targetPid,
    const char* terminalApiName,
    std::string& chainSummary,
    std::string& baseAddress,
    SIZE_T& size) {
  if (targetPid == 0 || targetPid == 4 || targetPid == ::GetCurrentProcessId()) return false;
  ULONGLONG now = ::GetTickCount64();
  std::lock_guard<std::mutex> lock(gProcessStateMutex);
  pruneInjectionChainsLocked(now);
  unsigned long long key = injectionChainKey(::GetCurrentProcessId(), targetPid);
  auto it = gInjectionChains.find(key);
  if (it == gInjectionChains.end()) return false;
  const auto& chain = it->second;
  bool strongChain = chain.sawWriteProcessMemory && (chain.sawVirtualAllocEx || chain.sawOpenProcess);
  if (!strongChain) return false;
  chainSummary = "OpenProcess>VirtualAllocEx>WriteProcessMemory>";
  chainSummary += terminalApiName ? terminalApiName : "CreateRemoteThread";
  baseAddress = chain.baseAddress;
  size = chain.size;
  gInjectionChains.erase(it);
  return true;
}

bool suspendTargetProcessForDecision(HANDLE hProcess, DWORD targetPid) {
  if (!gNtSuspendProcess || shouldNeverSuspendTarget(targetPid, hProcess)) return false;

  if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
    LONG status = gNtSuspendProcess(hProcess);
    if (status == 0) return true;
  }

  HANDLE suspendHandle = nullptr;
  constexpr DWORD kSuspendAccess = PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION;
  if (gOpenProcess) {
    suspendHandle = gOpenProcess(kSuspendAccess, FALSE, targetPid);
  } else {
    suspendHandle = ::OpenProcess(kSuspendAccess, FALSE, targetPid);
  }
  if (!suspendHandle) return false;
  LONG status = gNtSuspendProcess(suspendHandle);
  ::CloseHandle(suspendHandle);
  return status == 0;
}

bool resumeTargetProcessAfterReportFailure(HANDLE hProcess, DWORD targetPid) {
  if (!gNtResumeProcess || targetPid == 0 || targetPid == 4 || targetPid == ::GetCurrentProcessId()) return false;

  if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
    LONG status = gNtResumeProcess(hProcess);
    if (status == 0) return true;
  }

  HANDLE resumeHandle = nullptr;
  constexpr DWORD kResumeAccess = PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION;
  if (gOpenProcess) {
    resumeHandle = gOpenProcess(kResumeAccess, FALSE, targetPid);
  } else {
    resumeHandle = ::OpenProcess(kResumeAccess, FALSE, targetPid);
  }
  if (!resumeHandle) return false;
  LONG status = gNtResumeProcess(resumeHandle);
  ::CloseHandle(resumeHandle);
  return status == 0;
}

/*
 * VUL-052: 恢复失败时的看门狗线程。
 * 旧代码在 resumeTargetProcessAfterReportFailure 失败时无重试、无看门狗，
 * 目标进程永久挂起。与 VUL-051（管道重定向）配合，攻击者干扰管道通信使
 * 上报失败，目标进程被永久冻结。
 *
 * 现在在看门狗线程中最多重试 kMaxResumeRetries 次，每次间隔
 * kResumeRetryIntervalMs。看门狗复制目标 PID 并自行打开句柄，不依赖
 * 调用方的 hProcess（可能已关闭）。
 *
 * VUL-052: Watchdog thread for resume failures. The old code had no retry
 * and no watchdog when resumeTargetProcessAfterReportFailure failed,
 * leaving the target permanently suspended. Combined with VUL-051 (pipe
 * redirection), an attacker could disrupt pipe communication to make
 * reporting fail and freeze the target forever. Now the watchdog retries
 * up to kMaxResumeRetries times with kResumeRetryIntervalMs interval.
 * The watchdog copies the target PID and opens its own handle, not
 * relying on the caller's hProcess (which may be closed).
 */
constexpr int kMaxResumeRetries = 5;
constexpr DWORD kResumeRetryIntervalMs = 500;

struct ResumeWatchdogParams {
  DWORD targetPid{0};
};

DWORD WINAPI resumeWatchdogThreadProc(LPVOID arg) {
  std::unique_ptr<ResumeWatchdogParams> params(static_cast<ResumeWatchdogParams*>(arg));
  if (!params || params->targetPid == 0) return 0;
  DWORD pid = params->targetPid;
  if (pid == 4 || pid == ::GetCurrentProcessId()) return 0;

  for (int i = 0; i < kMaxResumeRetries; ++i) {
    ::Sleep(kResumeRetryIntervalMs);
    if (!gNtResumeProcess) continue;

    /* 检查进程是否仍存在 */
    HANDLE checkHandle = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!checkHandle) {
      /* 进程已退出，无需恢复 */
      return 0;
    }
    DWORD exitCode = 0;
    if (::GetExitCodeProcess(checkHandle, &exitCode) && exitCode != STILL_ACTIVE) {
      ::CloseHandle(checkHandle);
      return 0;
    }
    ::CloseHandle(checkHandle);

    /* 尝试恢复 */
    HANDLE resumeHandle = nullptr;
    constexpr DWORD kResumeAccess = PROCESS_SUSPEND_RESUME | PROCESS_QUERY_LIMITED_INFORMATION;
    if (gOpenProcess) {
      resumeHandle = gOpenProcess(kResumeAccess, FALSE, pid);
    } else {
      resumeHandle = ::OpenProcess(kResumeAccess, FALSE, pid);
    }
    if (resumeHandle) {
      LONG status = gNtResumeProcess(resumeHandle);
      ::CloseHandle(resumeHandle);
      if (status == 0) {
        /* 恢复成功 */
        return 0;
      }
    }
  }
  /* 达到最大重试次数仍未恢复，记录诊断（目标可能永久冻结） */
  std::cerr << "[file_hook_detours] WARNING: resume watchdog exhausted for pid="
            << pid << " after " << kMaxResumeRetries << " retries" << std::endl;
  return 0;
}

void launchResumeWatchdog(DWORD targetPid) {
  if (targetPid == 0 || targetPid == 4 || targetPid == ::GetCurrentProcessId()) return;
  auto* params = new ResumeWatchdogParams();
  params->targetPid = targetPid;
  HANDLE h = ::CreateThread(nullptr, 0, resumeWatchdogThreadProc, params, 0, nullptr);
  if (h) {
    ::CloseHandle(h);
  } else {
    delete params;
  }
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

std::wstring runtimeDiagnosticsPathW() {
  wchar_t appData[4096]{};
  DWORD n = ::GetEnvironmentVariableW(L"APPDATA", appData, static_cast<DWORD>(std::size(appData)));
  if (n == 0 || n >= static_cast<DWORD>(std::size(appData))) return {};
  std::wstring dir(appData, appData + n);
  dir += L"\\AnXinSecurity\\runtime";
  ::CreateDirectoryW((std::wstring(appData, appData + n) + L"\\AnXinSecurity").c_str(), nullptr);
  ::CreateDirectoryW(dir.c_str(), nullptr);
  return dir + L"\\file_hook_detours_diagnostics.jsonl";
}

void appendDetoursDiagnostic(const char* stage, const std::string& payloadFields) {
  HookGuard guard;
  std::wstring path = runtimeDiagnosticsPathW();
  if (path.empty()) return;
  HANDLE file = ::CreateFileW(
      path.c_str(),
      FILE_APPEND_DATA,
      FILE_SHARE_READ | FILE_SHARE_WRITE,
      nullptr,
      OPEN_ALWAYS,
      FILE_ATTRIBUTE_NORMAL,
      nullptr);
  if (file == INVALID_HANDLE_VALUE) return;

  std::string line;
  line.reserve(256 + payloadFields.size());
  line += "{\"stage\":\"";
  appendEscaped(line, stage ? std::string(stage) : std::string("unknown"));
  line += "\",\"sourcePid\":";
  line += std::to_string(::GetCurrentProcessId());
  line += ",\"tid\":";
  line += std::to_string(::GetCurrentThreadId());
  line += ",\"tick\":";
  line += std::to_string(::GetTickCount64());
  if (!payloadFields.empty()) {
    line += ",";
    line += payloadFields;
  }
  line += "}\n";

  DWORD written = 0;
  (void)::WriteFile(file, line.data(), static_cast<DWORD>(line.size()), &written, nullptr);
  ::CloseHandle(file);
}

HANDLE HookCreateFileWImpl(
    CreateFileWFn original,
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) {
  HookGuard guard;
  HANDLE h = original
      ? original(
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
            hTemplateFile)
      : INVALID_HANDLE_VALUE;
  if (guard.entered()) {
    std::string path = pathFromHandleUtf8(h);
    if (path.empty()) path = utf8FromWideAbs(lpFileName);
    if (!path.empty()) sendNotice("CreateFileW", path);
  }
  return h;
}

HANDLE WINAPI HookCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) {
  return HookCreateFileWImpl(
      gCreateFileW,
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile);
}

HANDLE WINAPI HookKernelBaseCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) {
  return HookCreateFileWImpl(
      gKernelBaseCreateFileW ? gKernelBaseCreateFileW : gCreateFileW,
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile);
}

HANDLE HookCreateFileAImpl(
    CreateFileAFn original,
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) {
  HookGuard guard;
  HANDLE h = original
      ? original(
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
            hTemplateFile)
      : INVALID_HANDLE_VALUE;
  if (guard.entered()) {
    std::string path = pathFromHandleUtf8(h);
    if (path.empty()) path = utf8FromAnsiAbs(lpFileName);
    if (!path.empty()) sendNotice("CreateFileA", path);
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
  return HookCreateFileAImpl(
      gCreateFileA,
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile);
}

HANDLE WINAPI HookKernelBaseCreateFileA(
    LPCSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile) {
  return HookCreateFileAImpl(
      gKernelBaseCreateFileA ? gKernelBaseCreateFileA : gCreateFileA,
      lpFileName,
      dwDesiredAccess,
      dwShareMode,
      lpSecurityAttributes,
      dwCreationDisposition,
      dwFlagsAndAttributes,
      hTemplateFile);
}

HANDLE HookOpenProcessImpl(
    OpenProcessFn original,
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId) {
  HookGuard guard;
  HANDLE h = original ? original(dwDesiredAccess, bInheritHandle, dwProcessId) : nullptr;
  if (guard.entered() && h && suspiciousOpenProcessAccess(dwDesiredAccess)) {
    recordProcessHandle(h, dwProcessId);
    updateNativeInjectionChain(dwProcessId, "OpenProcess", {}, 0);
    sendProcessInjectionNotice(
        "OpenProcess",
        dwProcessId,
        dwDesiredAccess,
        {},
        0,
        {},
        false,
        false,
        0,
        {});
  }
  return h;
}

HANDLE WINAPI HookOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
  return HookOpenProcessImpl(gOpenProcess, dwDesiredAccess, bInheritHandle, dwProcessId);
}

HANDLE WINAPI HookKernelBaseOpenProcess(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwProcessId) {
  return HookOpenProcessImpl(
      gKernelBaseOpenProcess ? gKernelBaseOpenProcess : gOpenProcess,
      dwDesiredAccess,
      bInheritHandle,
      dwProcessId);
}

LPVOID HookVirtualAllocExImpl(
    VirtualAllocExFn original,
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect) {
  HookGuard guard;
  LPVOID remoteMem = original
      ? original(hProcess, lpAddress, dwSize, flAllocationType, flProtect)
      : nullptr;
  if (guard.entered() && remoteMem) {
    DWORD targetPid = targetPidFromProcessHandle(hProcess);
    std::string baseAddress = hexFromPtr(remoteMem);
    updateNativeInjectionChain(targetPid, "VirtualAllocEx", baseAddress, dwSize);
    sendProcessInjectionNotice(
        "VirtualAllocEx",
        targetPid,
        0,
        baseAddress,
        dwSize,
        {},
        false,
        false,
        0,
        {});
  }
  return remoteMem;
}

LPVOID WINAPI HookVirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect) {
  return HookVirtualAllocExImpl(
      gVirtualAllocEx, hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID WINAPI HookKernelBaseVirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect) {
  return HookVirtualAllocExImpl(
      gKernelBaseVirtualAllocEx ? gKernelBaseVirtualAllocEx : gVirtualAllocEx,
      hProcess,
      lpAddress,
      dwSize,
      flAllocationType,
      flProtect);
}

BOOL HookWriteProcessMemoryImpl(
    WriteProcessMemoryFn original,
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten) {
  HookGuard guard;
  BOOL ok = original
      ? original(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten)
      : FALSE;
  if (guard.entered() && ok) {
    DWORD targetPid = targetPidFromProcessHandle(hProcess);
    std::string baseAddress = hexFromPtr(lpBaseAddress);
    updateNativeInjectionChain(targetPid, "WriteProcessMemory", baseAddress, nSize);
    sendProcessInjectionNotice(
        "WriteProcessMemory",
        targetPid,
        0,
        baseAddress,
        nSize,
        {},
        false,
        false,
        0,
        {});
  }
  return ok;
}

BOOL WINAPI HookWriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten) {
  return HookWriteProcessMemoryImpl(
      gWriteProcessMemory, hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL WINAPI HookKernelBaseWriteProcessMemory(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten) {
  return HookWriteProcessMemoryImpl(
      gKernelBaseWriteProcessMemory ? gKernelBaseWriteProcessMemory : gWriteProcessMemory,
      hProcess,
      lpBaseAddress,
      lpBuffer,
      nSize,
      lpNumberOfBytesWritten);
}

HANDLE HookCreateRemoteThreadImpl(
    CreateRemoteThreadFn original,
    const char* apiName,
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId) {
  HookGuard guard;
  if (guard.entered()) {
    DWORD targetPid = targetPidFromProcessHandle(hProcess);
    std::string chain;
    std::string baseAddress;
    SIZE_T writeSize = 0;
    if (shouldBlockRemoteThread(targetPid, apiName, chain, baseAddress, writeSize)) {
      bool targetSuspended = suspendTargetProcessForDecision(hProcess, targetPid);
      {
        std::string diag;
        diag += "\"api\":\"";
        appendEscaped(diag, apiName ? std::string(apiName) : std::string("CreateRemoteThread"));
        diag += "\",\"targetPid\":";
        diag += std::to_string(targetPid);
        diag += ",\"targetSuspended\":";
        diag += targetSuspended ? "true" : "false";
        appendStringField(diag, "chain", chain);
        appendStringField(diag, "baseAddress", baseAddress);
        appendStringField(diag, "startAddress", hexFromPtr(reinterpret_cast<const void*>(lpStartAddress)));
        if (writeSize != 0) {
          appendU64Field(diag, "size", static_cast<unsigned long long>(writeSize));
        }
        appendDetoursDiagnostic("remote_thread_block_decision", diag);
      }
      bool reported = sendProcessInjectionNotice(
          apiName,
          targetPid,
          0,
          baseAddress,
          writeSize,
          hexFromPtr(reinterpret_cast<const void*>(lpStartAddress)),
          true,
          targetSuspended,
          ERROR_ACCESS_DENIED,
          chain);
      if (targetSuspended && !reported) {
        /* VUL-052: 恢复失败时启动看门狗线程重试，防止目标永久冻结 */
        if (!resumeTargetProcessAfterReportFailure(hProcess, targetPid)) {
          launchResumeWatchdog(targetPid);
        }
      }
      {
        std::string diag;
        diag += "\"api\":\"";
        appendEscaped(diag, apiName ? std::string(apiName) : std::string("CreateRemoteThread"));
        diag += "\",\"targetPid\":";
        diag += std::to_string(targetPid);
        diag += ",\"targetSuspended\":";
        diag += targetSuspended ? "true" : "false";
        diag += ",\"reported\":";
        diag += reported ? "true" : "false";
        diag += ",\"rolledBack\":";
        diag += (targetSuspended && !reported) ? "true" : "false";
        appendDetoursDiagnostic("remote_thread_block_result", diag);
      }
      std::cerr << "[file_hook_detours] blocked " << apiName
                << " targetPid=" << targetPid
                << " targetSuspended=" << (targetSuspended ? 1 : 0)
                << " reported=" << (reported ? 1 : 0)
                << std::endl;
      ::SetLastError(ERROR_ACCESS_DENIED);
      return nullptr;
    }
  }

  HANDLE hThread = original
      ? original(
      hProcess,
      lpThreadAttributes,
      dwStackSize,
      lpStartAddress,
      lpParameter,
      dwCreationFlags,
            lpThreadId)
      : nullptr;
  if (guard.entered() && hThread) {
    DWORD targetPid = targetPidFromProcessHandle(hProcess);
    sendProcessInjectionNotice(
        apiName,
        targetPid,
        0,
        {},
        0,
        hexFromPtr(reinterpret_cast<const void*>(lpStartAddress)),
        false,
        false,
        0,
        {});
  }
  return hThread;
}

HANDLE WINAPI HookCreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId) {
  return HookCreateRemoteThreadImpl(
      gCreateRemoteThread,
      "CreateRemoteThread",
      hProcess,
      lpThreadAttributes,
      dwStackSize,
      lpStartAddress,
      lpParameter,
      dwCreationFlags,
      lpThreadId);
}

HANDLE WINAPI HookKernelBaseCreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId) {
  return HookCreateRemoteThreadImpl(
      gKernelBaseCreateRemoteThread ? gKernelBaseCreateRemoteThread : gCreateRemoteThread,
      "CreateRemoteThread",
      hProcess,
      lpThreadAttributes,
      dwStackSize,
      lpStartAddress,
      lpParameter,
      dwCreationFlags,
      lpThreadId);
}

HANDLE HookCreateRemoteThreadExImpl(
    CreateRemoteThreadExFn original,
    const char* apiName,
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId) {
  HookGuard guard;
  if (guard.entered()) {
    DWORD targetPid = targetPidFromProcessHandle(hProcess);
    std::string chain;
    std::string baseAddress;
    SIZE_T writeSize = 0;
    if (shouldBlockRemoteThread(targetPid, apiName, chain, baseAddress, writeSize)) {
      bool targetSuspended = suspendTargetProcessForDecision(hProcess, targetPid);
      {
        std::string diag;
        diag += "\"api\":\"";
        appendEscaped(diag, apiName ? std::string(apiName) : std::string("CreateRemoteThreadEx"));
        diag += "\",\"targetPid\":";
        diag += std::to_string(targetPid);
        diag += ",\"targetSuspended\":";
        diag += targetSuspended ? "true" : "false";
        appendStringField(diag, "chain", chain);
        appendStringField(diag, "baseAddress", baseAddress);
        appendStringField(diag, "startAddress", hexFromPtr(reinterpret_cast<const void*>(lpStartAddress)));
        if (writeSize != 0) {
          appendU64Field(diag, "size", static_cast<unsigned long long>(writeSize));
        }
        appendDetoursDiagnostic("remote_thread_block_decision", diag);
      }
      bool reported = sendProcessInjectionNotice(
          apiName,
          targetPid,
          0,
          baseAddress,
          writeSize,
          hexFromPtr(reinterpret_cast<const void*>(lpStartAddress)),
          true,
          targetSuspended,
          ERROR_ACCESS_DENIED,
          chain);
      if (targetSuspended && !reported) {
        /* VUL-052: 恢复失败时启动看门狗线程重试，防止目标永久冻结 */
        if (!resumeTargetProcessAfterReportFailure(hProcess, targetPid)) {
          launchResumeWatchdog(targetPid);
        }
      }
      {
        std::string diag;
        diag += "\"api\":\"";
        appendEscaped(diag, apiName ? std::string(apiName) : std::string("CreateRemoteThreadEx"));
        diag += "\",\"targetPid\":";
        diag += std::to_string(targetPid);
        diag += ",\"targetSuspended\":";
        diag += targetSuspended ? "true" : "false";
        diag += ",\"reported\":";
        diag += reported ? "true" : "false";
        diag += ",\"rolledBack\":";
        diag += (targetSuspended && !reported) ? "true" : "false";
        appendDetoursDiagnostic("remote_thread_block_result", diag);
      }
      std::cerr << "[file_hook_detours] blocked " << apiName
                << " targetPid=" << targetPid
                << " targetSuspended=" << (targetSuspended ? 1 : 0)
                << " reported=" << (reported ? 1 : 0)
                << std::endl;
      ::SetLastError(ERROR_ACCESS_DENIED);
      return nullptr;
    }
  }

  HANDLE hThread = original
      ? original(
            hProcess,
            lpThreadAttributes,
            dwStackSize,
            lpStartAddress,
            lpParameter,
            dwCreationFlags,
            lpAttributeList,
            lpThreadId)
      : nullptr;
  if (guard.entered() && hThread) {
    DWORD targetPid = targetPidFromProcessHandle(hProcess);
    sendProcessInjectionNotice(
        apiName,
        targetPid,
        0,
        {},
        0,
        hexFromPtr(reinterpret_cast<const void*>(lpStartAddress)),
        false,
        false,
        0,
        {});
  }
  return hThread;
}

HANDLE WINAPI HookCreateRemoteThreadEx(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId) {
  return HookCreateRemoteThreadExImpl(
      gCreateRemoteThreadEx,
      "CreateRemoteThreadEx",
      hProcess,
      lpThreadAttributes,
      dwStackSize,
      lpStartAddress,
      lpParameter,
      dwCreationFlags,
      lpAttributeList,
      lpThreadId);
}

HANDLE WINAPI HookKernelBaseCreateRemoteThreadEx(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    LPDWORD lpThreadId) {
  return HookCreateRemoteThreadExImpl(
      gKernelBaseCreateRemoteThreadEx ? gKernelBaseCreateRemoteThreadEx : gCreateRemoteThreadEx,
      "CreateRemoteThreadEx",
      hProcess,
      lpThreadAttributes,
      dwStackSize,
      lpStartAddress,
      lpParameter,
      dwCreationFlags,
      lpAttributeList,
      lpThreadId);
}

LONG HookNtCreateThreadExImpl(
    NtCreateThreadExFn original,
    const char* apiName,
    PHANDLE phThread,
    ACCESS_MASK desiredAccess,
    LPVOID objectAttributes,
    HANDLE hProcess,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    ULONG createFlags,
    SIZE_T zeroBits,
    SIZE_T stackSize,
    SIZE_T maximumStackSize,
    LPVOID attributeList) {
  HookGuard guard;
  if (guard.entered()) {
    DWORD targetPid = targetPidFromProcessHandle(hProcess);
    std::string chain;
    std::string baseAddress;
    SIZE_T writeSize = 0;
    if (shouldBlockRemoteThread(targetPid, apiName, chain, baseAddress, writeSize)) {
      bool targetSuspended = suspendTargetProcessForDecision(hProcess, targetPid);
      {
        std::string diag;
        diag += "\"api\":\"";
        appendEscaped(diag, apiName ? std::string(apiName) : std::string("NtCreateThreadEx"));
        diag += "\",\"targetPid\":";
        diag += std::to_string(targetPid);
        diag += ",\"targetSuspended\":";
        diag += targetSuspended ? "true" : "false";
        appendStringField(diag, "chain", chain);
        appendStringField(diag, "baseAddress", baseAddress);
        appendStringField(diag, "startAddress", hexFromPtr(reinterpret_cast<const void*>(lpStartAddress)));
        if (writeSize != 0) {
          appendU64Field(diag, "size", static_cast<unsigned long long>(writeSize));
        }
        appendDetoursDiagnostic("remote_thread_block_decision", diag);
      }
      bool reported = sendProcessInjectionNotice(
          apiName,
          targetPid,
          static_cast<DWORD>(desiredAccess),
          baseAddress,
          writeSize,
          hexFromPtr(reinterpret_cast<const void*>(lpStartAddress)),
          true,
          targetSuspended,
          ERROR_ACCESS_DENIED,
          chain);
      if (targetSuspended && !reported) {
        /* VUL-052: 恢复失败时启动看门狗线程重试，防止目标永久冻结 */
        if (!resumeTargetProcessAfterReportFailure(hProcess, targetPid)) {
          launchResumeWatchdog(targetPid);
        }
      }
      {
        std::string diag;
        diag += "\"api\":\"";
        appendEscaped(diag, apiName ? std::string(apiName) : std::string("NtCreateThreadEx"));
        diag += "\",\"targetPid\":";
        diag += std::to_string(targetPid);
        diag += ",\"targetSuspended\":";
        diag += targetSuspended ? "true" : "false";
        diag += ",\"reported\":";
        diag += reported ? "true" : "false";
        diag += ",\"rolledBack\":";
        diag += (targetSuspended && !reported) ? "true" : "false";
        appendDetoursDiagnostic("remote_thread_block_result", diag);
      }
      std::cerr << "[file_hook_detours] blocked " << apiName
                << " targetPid=" << targetPid
                << " targetSuspended=" << (targetSuspended ? 1 : 0)
                << " reported=" << (reported ? 1 : 0)
                << std::endl;
      if (phThread) {
        *phThread = nullptr;
      }
      return static_cast<LONG>(0xC0000022L); // STATUS_ACCESS_DENIED
    }
  }

  LONG status = original
      ? original(
            phThread,
            desiredAccess,
            objectAttributes,
            hProcess,
            lpStartAddress,
            lpParameter,
            createFlags,
            zeroBits,
            stackSize,
            maximumStackSize,
            attributeList)
      : static_cast<LONG>(0xC0000001L);
  if (guard.entered() && status >= 0 && phThread && *phThread) {
    DWORD targetPid = targetPidFromProcessHandle(hProcess);
    sendProcessInjectionNotice(
        apiName,
        targetPid,
        static_cast<DWORD>(desiredAccess),
        {},
        0,
        hexFromPtr(reinterpret_cast<const void*>(lpStartAddress)),
        false,
        false,
        0,
        {});
  }
  return status;
}

LONG WINAPI HookNtCreateThreadEx(
    PHANDLE phThread,
    ACCESS_MASK desiredAccess,
    LPVOID objectAttributes,
    HANDLE hProcess,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    ULONG createFlags,
    SIZE_T zeroBits,
    SIZE_T stackSize,
    SIZE_T maximumStackSize,
    LPVOID attributeList) {
  return HookNtCreateThreadExImpl(
      gNtCreateThreadEx,
      "NtCreateThreadEx",
      phThread,
      desiredAccess,
      objectAttributes,
      hProcess,
      lpStartAddress,
      lpParameter,
      createFlags,
      zeroBits,
      stackSize,
      maximumStackSize,
      attributeList);
}

void attachDetours() {
  HMODULE kernelBase = ::GetModuleHandleW(L"KernelBase.dll");
  if (kernelBase) {
    gKernelBaseCreateFileW = reinterpret_cast<CreateFileWFn>(::GetProcAddress(kernelBase, "CreateFileW"));
    gKernelBaseCreateFileA = reinterpret_cast<CreateFileAFn>(::GetProcAddress(kernelBase, "CreateFileA"));
    gKernelBaseOpenProcess = reinterpret_cast<OpenProcessFn>(::GetProcAddress(kernelBase, "OpenProcess"));
    gKernelBaseVirtualAllocEx = reinterpret_cast<VirtualAllocExFn>(::GetProcAddress(kernelBase, "VirtualAllocEx"));
    gKernelBaseWriteProcessMemory = reinterpret_cast<WriteProcessMemoryFn>(::GetProcAddress(kernelBase, "WriteProcessMemory"));
    gKernelBaseCreateRemoteThread = reinterpret_cast<CreateRemoteThreadFn>(::GetProcAddress(kernelBase, "CreateRemoteThread"));
    gKernelBaseCreateRemoteThreadEx = reinterpret_cast<CreateRemoteThreadExFn>(::GetProcAddress(kernelBase, "CreateRemoteThreadEx"));
  }
  HMODULE kernel32 = ::GetModuleHandleW(L"kernel32.dll");
  if (kernel32) {
    gCreateRemoteThreadEx = reinterpret_cast<CreateRemoteThreadExFn>(::GetProcAddress(kernel32, "CreateRemoteThreadEx"));
  }
  gNtdll = ::GetModuleHandleW(L"ntdll.dll");
  if (gNtdll) {
    gNtCreateThreadEx = reinterpret_cast<NtCreateThreadExFn>(::GetProcAddress(gNtdll, "NtCreateThreadEx"));
    gNtSuspendProcess = reinterpret_cast<NtSuspendProcessFn>(::GetProcAddress(gNtdll, "NtSuspendProcess"));
    gNtResumeProcess = reinterpret_cast<NtResumeProcessFn>(::GetProcAddress(gNtdll, "NtResumeProcess"));
  }

  if (DetourTransactionBegin() != NO_ERROR) return;
  if (DetourUpdateThread(::GetCurrentThread()) != NO_ERROR) {
    DetourTransactionAbort();
    return;
  }

  DetourAttach(reinterpret_cast<PVOID*>(&gCreateFileW), HookCreateFileW);
  DetourAttach(reinterpret_cast<PVOID*>(&gCreateFileA), HookCreateFileA);
  DetourAttach(reinterpret_cast<PVOID*>(&gOpenProcess), HookOpenProcess);
  DetourAttach(reinterpret_cast<PVOID*>(&gVirtualAllocEx), HookVirtualAllocEx);
  DetourAttach(reinterpret_cast<PVOID*>(&gWriteProcessMemory), HookWriteProcessMemory);
  DetourAttach(reinterpret_cast<PVOID*>(&gCreateRemoteThread), HookCreateRemoteThread);
  if (gNtCreateThreadEx) {
    DetourAttach(reinterpret_cast<PVOID*>(&gNtCreateThreadEx), HookNtCreateThreadEx);
  }
  if (gCreateRemoteThreadEx) {
    DetourAttach(reinterpret_cast<PVOID*>(&gCreateRemoteThreadEx), HookCreateRemoteThreadEx);
  }
  if (gKernelBaseCreateFileW) {
    DetourAttach(reinterpret_cast<PVOID*>(&gKernelBaseCreateFileW), HookKernelBaseCreateFileW);
  }
  if (gKernelBaseCreateFileA) {
    DetourAttach(reinterpret_cast<PVOID*>(&gKernelBaseCreateFileA), HookKernelBaseCreateFileA);
  }
  if (gKernelBaseOpenProcess) {
    DetourAttach(reinterpret_cast<PVOID*>(&gKernelBaseOpenProcess), HookKernelBaseOpenProcess);
  }
  if (gKernelBaseVirtualAllocEx) {
    DetourAttach(reinterpret_cast<PVOID*>(&gKernelBaseVirtualAllocEx), HookKernelBaseVirtualAllocEx);
  }
  if (gKernelBaseWriteProcessMemory) {
    DetourAttach(reinterpret_cast<PVOID*>(&gKernelBaseWriteProcessMemory), HookKernelBaseWriteProcessMemory);
  }
  if (gKernelBaseCreateRemoteThread) {
    DetourAttach(reinterpret_cast<PVOID*>(&gKernelBaseCreateRemoteThread), HookKernelBaseCreateRemoteThread);
  }
  if (gKernelBaseCreateRemoteThreadEx) {
    DetourAttach(reinterpret_cast<PVOID*>(&gKernelBaseCreateRemoteThreadEx), HookKernelBaseCreateRemoteThreadEx);
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
  DetourDetach(reinterpret_cast<PVOID*>(&gOpenProcess), HookOpenProcess);
  DetourDetach(reinterpret_cast<PVOID*>(&gVirtualAllocEx), HookVirtualAllocEx);
  DetourDetach(reinterpret_cast<PVOID*>(&gWriteProcessMemory), HookWriteProcessMemory);
  DetourDetach(reinterpret_cast<PVOID*>(&gCreateRemoteThread), HookCreateRemoteThread);
  if (gNtCreateThreadEx) {
    DetourDetach(reinterpret_cast<PVOID*>(&gNtCreateThreadEx), HookNtCreateThreadEx);
  }
  if (gCreateRemoteThreadEx) {
    DetourDetach(reinterpret_cast<PVOID*>(&gCreateRemoteThreadEx), HookCreateRemoteThreadEx);
  }
  if (gKernelBaseCreateFileW) {
    DetourDetach(reinterpret_cast<PVOID*>(&gKernelBaseCreateFileW), HookKernelBaseCreateFileW);
  }
  if (gKernelBaseCreateFileA) {
    DetourDetach(reinterpret_cast<PVOID*>(&gKernelBaseCreateFileA), HookKernelBaseCreateFileA);
  }
  if (gKernelBaseOpenProcess) {
    DetourDetach(reinterpret_cast<PVOID*>(&gKernelBaseOpenProcess), HookKernelBaseOpenProcess);
  }
  if (gKernelBaseVirtualAllocEx) {
    DetourDetach(reinterpret_cast<PVOID*>(&gKernelBaseVirtualAllocEx), HookKernelBaseVirtualAllocEx);
  }
  if (gKernelBaseWriteProcessMemory) {
    DetourDetach(reinterpret_cast<PVOID*>(&gKernelBaseWriteProcessMemory), HookKernelBaseWriteProcessMemory);
  }
  if (gKernelBaseCreateRemoteThread) {
    DetourDetach(reinterpret_cast<PVOID*>(&gKernelBaseCreateRemoteThread), HookKernelBaseCreateRemoteThread);
  }
  if (gKernelBaseCreateRemoteThreadEx) {
    DetourDetach(reinterpret_cast<PVOID*>(&gKernelBaseCreateRemoteThreadEx), HookKernelBaseCreateRemoteThreadEx);
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
    {
      std::lock_guard<std::mutex> lock(gPipeWriteMutex);
      closeCachedPipeHandleLocked();
    }
    detachDetours();
  }
  return TRUE;
}
