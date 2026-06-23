#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

constexpr wchar_t kDefaultPipeName[] = L"\\\\.\\pipe\\anxin_security_filehook";
constexpr wchar_t kPipeNameEnv[] = L"ANXIN_HOOK_PIPE";
constexpr wchar_t kSkipSelfHookEnv[] = L"ANXIN_FILE_HOOK_INJECTOR_SKIP_SELF_HOOK";
constexpr wchar_t kForceSelfHookEnv[] = L"ANXIN_FILE_HOOK_INJECTOR_SELF_HOOK";

enum class ProcArch {
  x86,
  x64,
  unknown
};

struct Args {
  DWORD pid{0};
  std::wstring dll;
  std::wstring dllX86;
  std::wstring dllX64;
};

std::wstring toLower(std::wstring s) {
  for (auto& ch : s) {
    if (ch >= L'A' && ch <= L'Z') ch = static_cast<wchar_t>(ch - L'A' + L'a');
  }
  return s;
}

bool fileExists(const std::wstring& p) {
  DWORD attrs = ::GetFileAttributesW(p.c_str());
  return attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool envFlagEnabled(const wchar_t* name) {
  wchar_t value[32]{};
  DWORD n = ::GetEnvironmentVariableW(name, value, static_cast<DWORD>(std::size(value)));
  if (n == 0 || n >= static_cast<DWORD>(std::size(value))) return false;
  std::wstring lowered = toLower(std::wstring(value, value + n));
  return lowered == L"1" || lowered == L"true" || lowered == L"yes" || lowered == L"on";
}

std::wstring executablePath() {
  wchar_t path[4096]{};
  DWORD n = ::GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
  if (n == 0 || n >= static_cast<DWORD>(std::size(path))) return {};
  return std::wstring(path, path + n);
}

std::wstring parentDir(const std::wstring& path) {
  std::size_t pos = path.find_last_of(L"\\/");
  if (pos == std::wstring::npos) return {};
  return path.substr(0, pos);
}

std::wstring joinPath(const std::wstring& left, const std::wstring& right) {
  if (left.empty()) return right;
  wchar_t tail = left.back();
  if (tail == L'\\' || tail == L'/') return left + right;
  return left + L"\\" + right;
}

ProcArch localArch() {
  return sizeof(void*) == 8 ? ProcArch::x64 : ProcArch::x86;
}

std::wstring localArchDir() {
  return localArch() == ProcArch::x64 ? L"win32-x64" : L"win32-x86";
}

std::wstring readHookPipeName() {
  wchar_t value[512]{};
  DWORD n = ::GetEnvironmentVariableW(kPipeNameEnv, value, static_cast<DWORD>(std::size(value)));
  if (n == 0 || n >= static_cast<DWORD>(std::size(value))) {
    return kDefaultPipeName;
  }
  return std::wstring(value, value + n);
}

bool hookPipeLooksReady() {
  std::wstring pipe = readHookPipeName();
  if (pipe.empty()) return false;
  for (int i = 0; i < 3; ++i) {
    if (::WaitNamedPipeW(pipe.c_str(), 80)) return true;
    if (::GetLastError() == ERROR_PIPE_BUSY) {
      ::Sleep(30);
      continue;
    }
    ::Sleep(30);
  }
  return false;
}

std::vector<std::wstring> selfHookDllCandidates() {
  std::vector<std::wstring> candidates;
  std::wstring exe = executablePath();
  std::wstring dir = parentDir(exe);
  if (dir.empty()) return candidates;

  candidates.push_back(joinPath(dir, L"file_hook_detours.dll"));

  // Common dev layout:
  // native/file_hook/build-.../Release/file_hook_injector.exe
  // native/bin/win32-x64|win32-x86/file_hook_detours.dll
  std::wstring p1 = parentDir(dir);
  std::wstring p2 = parentDir(p1);
  std::wstring p3 = parentDir(p2);
  if (!p3.empty()) {
    candidates.push_back(joinPath(joinPath(joinPath(p3, L"bin"), localArchDir()), L"file_hook_detours.dll"));
  }

  return candidates;
}

void maybeEnableSelfHookForManualProbe() {
  if (envFlagEnabled(kSkipSelfHookEnv)) return;
  if (!envFlagEnabled(kForceSelfHookEnv) && !hookPipeLooksReady()) return;

  for (const auto& dll : selfHookDllCandidates()) {
    if (!fileExists(dll)) continue;
    HMODULE module = ::LoadLibraryW(dll.c_str());
    if (module) {
      std::wcerr << L"[file_hook_injector] self APIHook enabled: " << dll << L"\n";
      return;
    }
  }
  std::wcerr << L"[file_hook_injector] self APIHook requested but file_hook_detours.dll was not found\n";
}

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

bool parseArgs(int argc, wchar_t** argv, Args& out) {
  for (int i = 1; i < argc; i++) {
    std::wstring key = toLower(argv[i] ? argv[i] : L"");
    if ((key == L"--pid" || key == L"-p") && i + 1 < argc) {
      out.pid = static_cast<DWORD>(wcstoul(argv[++i], nullptr, 10));
      continue;
    }
    if (key == L"--dll" && i + 1 < argc) {
      out.dll = argv[++i];
      continue;
    }
    if (key == L"--dll-x86" && i + 1 < argc) {
      out.dllX86 = argv[++i];
      continue;
    }
    if (key == L"--dll-x64" && i + 1 < argc) {
      out.dllX64 = argv[++i];
      continue;
    }
  }
  return out.pid > 0;
}

std::wstring pickDllForTarget(const Args& args, ProcArch targetArch) {
  if (!args.dll.empty()) return args.dll;
  if (targetArch == ProcArch::x64 && !args.dllX64.empty()) return args.dllX64;
  if (targetArch == ProcArch::x86 && !args.dllX86.empty()) return args.dllX86;
  return {};
}

int injectByLoadLibrary(HANDLE hProcess, const std::wstring& dllPath) {
  const std::size_t bytes = (dllPath.size() + 1) * sizeof(wchar_t);
  LPVOID remoteMem = ::VirtualAllocEx(hProcess, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!remoteMem) {
    std::wcerr << L"VirtualAllocEx failed, error=" << ::GetLastError() << L"\n";
    return 20;
  }

  if (!::WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), bytes, nullptr)) {
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    std::wcerr << L"WriteProcessMemory failed, error=" << ::GetLastError() << L"\n";
    return 21;
  }

  HMODULE hKernel = ::GetModuleHandleW(L"kernel32.dll");
  if (!hKernel) {
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    std::wcerr << L"GetModuleHandleW(kernel32.dll) failed, error=" << ::GetLastError() << L"\n";
    return 22;
  }

  auto loadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(::GetProcAddress(hKernel, "LoadLibraryW"));
  if (!loadLibraryW) {
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    std::wcerr << L"GetProcAddress(LoadLibraryW) failed, error=" << ::GetLastError() << L"\n";
    return 23;
  }

  HANDLE hThread = ::CreateRemoteThread(hProcess, nullptr, 0, loadLibraryW, remoteMem, 0, nullptr);
  if (!hThread) {
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    std::wcerr << L"CreateRemoteThread failed, error=" << ::GetLastError() << L"\n";
    return 24;
  }

  DWORD waitRes = ::WaitForSingleObject(hThread, 10000);
  if (waitRes != WAIT_OBJECT_0) {
    ::CloseHandle(hThread);
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    std::wcerr << L"WaitForSingleObject failed, result=" << waitRes << L", error=" << ::GetLastError() << L"\n";
    return 25;
  }

  DWORD exitCode = 0;
  if (!::GetExitCodeThread(hThread, &exitCode)) {
    ::CloseHandle(hThread);
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    std::wcerr << L"GetExitCodeThread failed, error=" << ::GetLastError() << L"\n";
    return 26;
  }

  ::CloseHandle(hThread);
  ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
  return exitCode == 0 ? 27 : 0;
}

int wmain(int argc, wchar_t** argv) {
  Args args{};
  if (!parseArgs(argc, argv, args)) {
    std::wcerr << L"usage: file_hook_injector --pid <pid> [--dll <path>] [--dll-x86 <path>] [--dll-x64 <path>]\n";
    return 2;
  }

  maybeEnableSelfHookForManualProbe();

  HANDLE hProcess = ::OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
      FALSE,
      args.pid);
  if (!hProcess) {
    DWORD err = ::GetLastError();
    std::wcerr << L"open process failed: " << args.pid << L", error=" << err << L"\n";
    return 10;
  }

  ProcArch target = processArch(hProcess);
  ProcArch local = localArch();
  if (target == ProcArch::unknown) {
    ::CloseHandle(hProcess);
    std::wcerr << L"target architecture unknown\n";
    return 11;
  }
  if (target != local) {
    ::CloseHandle(hProcess);
    std::wcerr << L"injector arch mismatch target arch\n";
    return 12;
  }

  std::wstring dllPath = pickDllForTarget(args, target);
  if (dllPath.empty()) {
    ::CloseHandle(hProcess);
    std::wcerr << L"dll path not provided for target arch\n";
    return 13;
  }
  if (!fileExists(dllPath)) {
    ::CloseHandle(hProcess);
    std::wcerr << L"dll file not found: " << dllPath << L"\n";
    return 14;
  }

  int rc = injectByLoadLibrary(hProcess, dllPath);
  ::CloseHandle(hProcess);
  if (rc != 0) {
    std::wcerr << L"inject failed, code=" << rc << L", lastError=" << ::GetLastError() << L"\n";
    return rc;
  }

  std::wcout << L"inject success pid=" << args.pid << L"\n";
  return 0;
}
