#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>

#include <string>
#include <unordered_set>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <cwctype>

namespace {

enum class ProcArch { unknown, x86, x64 };

std::wstring gInjectorX64;
std::wstring gInjectorX86;
std::wstring gDllX64;
std::wstring gDllX86;
int gIntervalMs = 100;
HANDLE gThread = nullptr;
HANDLE gInjectThread = nullptr;
volatile LONG gStop = 0;
CRITICAL_SECTION gLock;
bool gLockInited = false;
std::unordered_set<DWORD> gSeen;
std::mutex gQueueLock;
std::condition_variable gQueueCv;
std::vector<std::pair<DWORD, ProcArch>> gQueue;
std::mutex gSignLock;
std::unordered_map<std::wstring, bool> gSignCache;
std::mutex gPidLock;
std::vector<DWORD> gNewPids;

ProcArch processArch(HANDLE hProcess) {
  using FnIsWow64Process2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
  HMODULE hKernel = ::GetModuleHandleW(L"kernel32.dll");
  auto fn2 = hKernel ? reinterpret_cast<FnIsWow64Process2>(::GetProcAddress(hKernel, "IsWow64Process2")) : nullptr;
  if (fn2) {
    USHORT processMachine = 0;
    USHORT nativeMachine = 0;
    if (fn2(hProcess, &processMachine, &nativeMachine)) {
      if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN) {
        return nativeMachine == IMAGE_FILE_MACHINE_AMD64 ? ProcArch::x64 : ProcArch::x86;
      }
      return ProcArch::x86;
    }
  }
  BOOL wow64 = FALSE;
  if (!::IsWow64Process(hProcess, &wow64)) return ProcArch::unknown;
  SYSTEM_INFO si{};
  ::GetNativeSystemInfo(&si);
  if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64) {
    return wow64 ? ProcArch::x86 : ProcArch::x64;
  }
  if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL) {
    return ProcArch::x86;
  }
  return ProcArch::unknown;
}

bool queryProcessImagePath(DWORD pid, std::wstring& out) {
  out.clear();
  HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!hProcess) return false;
  wchar_t buf[4096]{};
  DWORD size = static_cast<DWORD>(std::size(buf));
  BOOL ok = ::QueryFullProcessImageNameW(hProcess, 0, buf, &size);
  ::CloseHandle(hProcess);
  if (!ok || size == 0) return false;
  out.assign(buf, buf + size);
  return true;
}

bool verifySigned(const std::wstring& path) {
  {
    std::lock_guard<std::mutex> guard(gSignLock);
    auto it = gSignCache.find(path);
    if (it != gSignCache.end()) return it->second;
  }
  WINTRUST_FILE_INFO fileInfo{};
  fileInfo.cbStruct = sizeof(fileInfo);
  fileInfo.pcwszFilePath = path.c_str();
  fileInfo.hFile = nullptr;
  fileInfo.pgKnownSubject = nullptr;

  WINTRUST_DATA winTrustData{};
  winTrustData.cbStruct = sizeof(winTrustData);
  winTrustData.dwUIChoice = WTD_UI_NONE;
  winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
  winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
  winTrustData.pFile = &fileInfo;
  winTrustData.dwStateAction = WTD_STATEACTION_VERIFY;
  winTrustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;
  winTrustData.dwUIContext = 0;

  GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
  LONG status = ::WinVerifyTrust(nullptr, &action, &winTrustData);
  winTrustData.dwStateAction = WTD_STATEACTION_CLOSE;
  ::WinVerifyTrust(nullptr, &action, &winTrustData);
  const bool ok = status == ERROR_SUCCESS;
  {
    std::lock_guard<std::mutex> guard(gSignLock);
    gSignCache[path] = ok;
  }
  return ok;
}

std::wstring trimWs(const std::wstring& s) {
  std::size_t start = 0;
  std::size_t end = s.size();
  while (start < end && std::iswspace(s[start])) start++;
  while (end > start && std::iswspace(s[end - 1])) end--;
  return s.substr(start, end - start);
}

int addSignedList(const wchar_t* data, int length) {
  if (!data || length <= 0) return 0;
  std::wstring payload(data, data + length);
  int added = 0;
  std::size_t pos = 0;
  while (pos < payload.size()) {
    std::size_t next = payload.find(L'\n', pos);
    if (next == std::wstring::npos) next = payload.size();
    std::wstring item = trimWs(payload.substr(pos, next - pos));
    if (!item.empty()) {
      std::lock_guard<std::mutex> guard(gSignLock);
      gSignCache[item] = true;
      added++;
    }
    pos = next + 1;
  }
  return added;
}

bool launchInjector(DWORD pid, ProcArch arch) {
  const std::wstring& injector = (arch == ProcArch::x86) ? gInjectorX86 : gInjectorX64;
  const std::wstring& dll = (arch == ProcArch::x86) ? gDllX86 : gDllX64;
  if (injector.empty() || dll.empty()) return false;

  std::wstring cmd = L"\"";
  cmd += injector;
  cmd += L"\" --pid ";
  cmd += std::to_wstring(pid);
  cmd += L" --dll \"";
  cmd += dll;
  cmd += L"\"";

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};
  std::wstring mutableCmd = cmd;
  BOOL ok = ::CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
  if (!ok) return false;
  ::WaitForSingleObject(pi.hProcess, 12000);
  DWORD exitCode = 1;
  ::GetExitCodeProcess(pi.hProcess, &exitCode);
  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);
  return exitCode == 0;
}

void ensureLock() {
  if (!gLockInited) {
    ::InitializeCriticalSection(&gLock);
    gLockInited = true;
  }
}

void collectCurrentPids(std::unordered_set<DWORD>& current) {
  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof(pe);
  if (::Process32FirstW(snap, &pe)) {
    do {
      current.insert(pe.th32ProcessID);
    } while (::Process32NextW(snap, &pe));
  }
  ::CloseHandle(snap);
}

void pruneSeen(const std::unordered_set<DWORD>& current) {
  if (!gLockInited) return;
  ::EnterCriticalSection(&gLock);
  for (auto it = gSeen.begin(); it != gSeen.end(); ) {
    if (current.find(*it) == current.end()) it = gSeen.erase(it);
    else ++it;
  }
  ::LeaveCriticalSection(&gLock);
}

bool markSeenIfNew(DWORD pid) {
  ensureLock();
  ::EnterCriticalSection(&gLock);
  const bool exists = gSeen.find(pid) != gSeen.end();
  if (!exists) gSeen.insert(pid);
  ::LeaveCriticalSection(&gLock);
  return !exists;
}

void enqueueInject(DWORD pid, ProcArch arch) {
  {
    std::lock_guard<std::mutex> guard(gQueueLock);
    gQueue.emplace_back(pid, arch);
  }
  gQueueCv.notify_one();
}

void pushNewPid(DWORD pid) {
  std::lock_guard<std::mutex> guard(gPidLock);
  gNewPids.push_back(pid);
}

DWORD WINAPI injectThreadProc(LPVOID) {
  while (::InterlockedCompareExchange(&gStop, 0, 0) == 0) {
    std::pair<DWORD, ProcArch> item{0, ProcArch::unknown};
    {
      std::unique_lock<std::mutex> lock(gQueueLock);
      if (gQueue.empty()) {
        gQueueCv.wait_for(lock, std::chrono::milliseconds(100));
      }
      if (!gQueue.empty()) {
        item = gQueue.front();
        gQueue.erase(gQueue.begin());
      }
    }
    if (item.first > 0 && item.second != ProcArch::unknown) {
      launchInjector(item.first, item.second);
    }
  }
  return 0;
}

DWORD WINAPI watcherThreadProc(LPVOID) {
  const DWORD selfPid = ::GetCurrentProcessId();
  while (::InterlockedCompareExchange(&gStop, 0, 0) == 0) {
    std::unordered_set<DWORD> current;
    collectCurrentPids(current);
    for (DWORD pid : current) {
      if (pid <= 4 || pid == selfPid) continue;
      if (!markSeenIfNew(pid)) continue;
      pushNewPid(pid);
      std::wstring imagePath;
      if (!queryProcessImagePath(pid, imagePath)) continue;
      if (imagePath.empty()) continue;
      if (verifySigned(imagePath)) continue;
      HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
      if (!hProcess) continue;
      ProcArch arch = processArch(hProcess);
      ::CloseHandle(hProcess);
      if (arch == ProcArch::unknown) continue;
      enqueueInject(pid, arch);
    }
    pruneSeen(current);
    int slept = 0;
    while (slept < gIntervalMs && ::InterlockedCompareExchange(&gStop, 0, 0) == 0) {
      ::Sleep(50);
      slept += 50;
    }
  }
  return 0;
}

} 

extern "C" __declspec(dllexport) int ProcessWatcher_Start(const wchar_t* injectorX64, const wchar_t* injectorX86, const wchar_t* dllX64, const wchar_t* dllX86, int intervalMs) {
  if (gThread) return 0;
  gInjectorX64 = injectorX64 ? injectorX64 : L"";
  gInjectorX86 = injectorX86 ? injectorX86 : L"";
  gDllX64 = dllX64 ? dllX64 : L"";
  gDllX86 = dllX86 ? dllX86 : L"";
  gIntervalMs = intervalMs > 100 ? intervalMs : 100;
  ::InterlockedExchange(&gStop, 0);
  gThread = ::CreateThread(nullptr, 0, watcherThreadProc, nullptr, 0, nullptr);
  gInjectThread = ::CreateThread(nullptr, 0, injectThreadProc, nullptr, 0, nullptr);
  if (!gThread || !gInjectThread) {
    ::InterlockedExchange(&gStop, 1);
    if (gThread) { ::CloseHandle(gThread); gThread = nullptr; }
    if (gInjectThread) { ::CloseHandle(gInjectThread); gInjectThread = nullptr; }
    return 0;
  }
  return gThread ? 1 : 0;
}

extern "C" __declspec(dllexport) void ProcessWatcher_Stop() {
  if (!gThread && !gInjectThread) return;
  ::InterlockedExchange(&gStop, 1);
  gQueueCv.notify_all();
  if (gThread) {
    ::WaitForSingleObject(gThread, 3000);
    ::CloseHandle(gThread);
    gThread = nullptr;
  }
  if (gInjectThread) {
    ::WaitForSingleObject(gInjectThread, 3000);
    ::CloseHandle(gInjectThread);
    gInjectThread = nullptr;
  }
}

extern "C" __declspec(dllexport) int ProcessWatcher_SetSignedList(const wchar_t* data, int length) {
  return addSignedList(data, length);
}

extern "C" __declspec(dllexport) int ProcessWatcher_PollNewPid() {
  std::lock_guard<std::mutex> guard(gPidLock);
  if (gNewPids.empty()) return 0;
  const DWORD pid = gNewPids.front();
  gNewPids.erase(gNewPids.begin());
  return static_cast<int>(pid);
}
