#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

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

ProcArch localArch() {
  return sizeof(void*) == 8 ? ProcArch::x64 : ProcArch::x86;
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
  if (!remoteMem) return 20;

  if (!::WriteProcessMemory(hProcess, remoteMem, dllPath.c_str(), bytes, nullptr)) {
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return 21;
  }

  HMODULE hKernel = ::GetModuleHandleW(L"kernel32.dll");
  if (!hKernel) {
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return 22;
  }

  auto loadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(::GetProcAddress(hKernel, "LoadLibraryW"));
  if (!loadLibraryW) {
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return 23;
  }

  HANDLE hThread = ::CreateRemoteThread(hProcess, nullptr, 0, loadLibraryW, remoteMem, 0, nullptr);
  if (!hThread) {
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return 24;
  }

  DWORD waitRes = ::WaitForSingleObject(hThread, 10000);
  if (waitRes != WAIT_OBJECT_0) {
    ::CloseHandle(hThread);
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    return 25;
  }

  DWORD exitCode = 0;
  if (!::GetExitCodeThread(hThread, &exitCode)) {
    ::CloseHandle(hThread);
    ::VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
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

  HANDLE hProcess = ::OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
      FALSE,
      args.pid);
  if (!hProcess) {
    std::wcerr << L"open process failed: " << args.pid << L"\n";
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
    std::wcerr << L"inject failed, code=" << rc << L"\n";
    return rc;
  }

  std::wcout << L"inject success pid=" << args.pid << L"\n";
  return 0;
}
