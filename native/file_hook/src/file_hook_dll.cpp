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
using NtSuspendProcessFn = LONG(WINAPI*)(HANDLE);
using NtResumeProcessFn = LONG(WINAPI*)(HANDLE);

namespace {

constexpr wchar_t kDefaultPipeName[] = L"\\\\.\\pipe\\anxin_security_filehook";
constexpr wchar_t kPipeNameEnv[] = L"ANXIN_HOOK_PIPE";
constexpr DWORD kPipeConnectTimeoutMs = 200;
constexpr DWORD kPipeOpenRetryMs = 20;
constexpr int kPipeOpenRetries = 50;
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
NtSuspendProcessFn gNtSuspendProcess = nullptr;
NtResumeProcessFn gNtResumeProcess = nullptr;
thread_local bool gInsideHook = false;
HMODULE gSelfModule = nullptr;
HANDLE gHeartbeatThread = nullptr;
volatile LONG gHeartbeatStop = 0;
std::mutex gProcessStateMutex;
std::unordered_map<std::uintptr_t, DWORD> gProcessHandleTargets;
std::unordered_map<unsigned long long, NativeInjectionChain> gInjectionChains;

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
  HANDLE hPipe = openPipeHandle(pipeName, GENERIC_WRITE);
  if (hPipe == INVALID_HANDLE_VALUE) {
    if (lastError) *lastError = ::GetLastError();
    return false;
  }
  DWORD written = 0;
  BOOL ok = ::WriteFile(hPipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
  DWORD err = ok ? 0 : ::GetLastError();
  ::CloseHandle(hPipe);
  if (!ok || written != static_cast<DWORD>(payload.size())) {
    if (lastError) *lastError = ok ? ERROR_WRITE_FAULT : err;
    return false;
  }
  return true;
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
  gProcessHandleTargets[reinterpret_cast<std::uintptr_t>(hProcess)] = targetPid;
  if (gProcessHandleTargets.size() > kMaxTrackedProcessHandles) {
    gProcessHandleTargets.clear();
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
  chainSummary = "OpenProcess>VirtualAllocEx>WriteProcessMemory>CreateRemoteThread";
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
    if (shouldBlockRemoteThread(targetPid, chain, baseAddress, writeSize)) {
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
        resumeTargetProcessAfterReportFailure(hProcess, targetPid);
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
    if (shouldBlockRemoteThread(targetPid, chain, baseAddress, writeSize)) {
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
        resumeTargetProcessAfterReportFailure(hProcess, targetPid);
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
    detachDetours();
  }
  return TRUE;
}
