#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

// 这个 DLL 是防护链路验证用的“可观测样本”，不是隐藏样本：
// 1. 启动 calc.exe，给人工观察一个明确信号；
// 2. 保留线程 10 分钟，方便 Process Explorer / WinDBG / AnXinSecurity 采样；
// 3. 在目标进程内放置一个 MEM_PRIVATE + PAGE_EXECUTE_READ 的 PE-like marker，
//    用来验证内存异常检测能否发现“私有可执行内存里出现 MZ/PE 结构”。
//
// This is an observable defensive probe, not a stealth payload.
constexpr DWORD kCalcProbeHoldMs = 10 * 60 * 1000;
constexpr SIZE_T kProbeRegionSize = 0x4000;

LPVOID g_probe_region = nullptr;

void write_u16(std::array<std::uint8_t, kProbeRegionSize>& buffer, SIZE_T offset, std::uint16_t value) {
  if (offset + sizeof(value) > buffer.size()) return;
  buffer[offset + 0] = static_cast<std::uint8_t>(value & 0xff);
  buffer[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
}

void write_u32(std::array<std::uint8_t, kProbeRegionSize>& buffer, SIZE_T offset, std::uint32_t value) {
  if (offset + sizeof(value) > buffer.size()) return;
  buffer[offset + 0] = static_cast<std::uint8_t>(value & 0xff);
  buffer[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
  buffer[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xff);
  buffer[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xff);
}

void copy_bytes(std::array<std::uint8_t, kProbeRegionSize>& buffer, SIZE_T offset, const char* text) {
  if (!text) return;
  const SIZE_T len = std::strlen(text);
  if (offset >= buffer.size()) return;
  const SIZE_T writable = std::min<SIZE_T>(len, buffer.size() - offset);
  std::memcpy(buffer.data() + offset, text, writable);
}

void allocate_private_executable_probe_region() {
  if (g_probe_region) {
    return;
  }

  std::array<std::uint8_t, kProbeRegionSize> buffer{};

  // DOS header marker: MZ + e_lfanew.
  write_u16(buffer, 0x00, 0x5A4D);
  write_u32(buffer, 0x3C, 0x100);

  // NT header marker: PE\0\0 + minimal COFF/optional-header-looking fields.
  write_u32(buffer, 0x100, 0x00004550);
  write_u16(buffer, 0x104, sizeof(void*) == 8 ? 0x8664 : 0x014c);
  write_u16(buffer, 0x106, 1);
  write_u16(buffer, 0x114, sizeof(void*) == 8 ? 0x00F0 : 0x00E0);
  write_u16(buffer, 0x116, 0x210E);
  write_u16(buffer, 0x118, sizeof(void*) == 8 ? 0x20B : 0x10B);
  write_u32(buffer, 0x128, 0x1000);
  write_u32(buffer, 0x138, static_cast<std::uint32_t>(kProbeRegionSize));

  copy_bytes(buffer, 0x200, "ANXIN_CALC_PROBE_MEM_PRIVATE_EXECUTE_PE_MARKER");
  copy_bytes(buffer, 0x300, "This region is intentionally non-runnable and exists only for defensive detection validation.");

  LPVOID region = ::VirtualAlloc(nullptr, buffer.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!region) {
    return;
  }

  std::memcpy(region, buffer.data(), buffer.size());

  DWORD oldProtect = 0;
  if (!::VirtualProtect(region, buffer.size(), PAGE_EXECUTE_READ, &oldProtect)) {
    ::VirtualFree(region, 0, MEM_RELEASE);
    return;
  }

  g_probe_region = region;
}

DWORD WINAPI launch_calc_thread(LPVOID) {
  allocate_private_executable_probe_region();

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  PROCESS_INFORMATION pi{};

  wchar_t systemDir[MAX_PATH]{};
  UINT len = ::GetSystemDirectoryW(systemDir, MAX_PATH);
  if (len == 0 || len >= MAX_PATH) {
    return 1;
  }

  std::wstring calcPath(systemDir);
  calcPath += L"\\calc.exe";
  std::wstring commandLine = calcPath;

  // Visual-only probe: launch Calculator to prove that this DLL was loaded.
  if (!::CreateProcessW(
          nullptr,
          commandLine.data(),
          nullptr,
          nullptr,
          FALSE,
          0,
          nullptr,
          nullptr,
          &si,
          &pi)) {
    return 3;
  }

  ::CloseHandle(pi.hThread);
  ::CloseHandle(pi.hProcess);

  // 让这个测试线程多保留一会儿，方便在 Process Explorer 里观察到注入后的模块和线程。
  // Keep the worker thread alive for a while so Process Explorer has time to observe the injected module/thread.
  ::Sleep(kCalcProbeHoldMs);
  return 0;
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    ::DisableThreadLibraryCalls(hinstDLL);
    HANDLE thread = ::CreateThread(nullptr, 0, launch_calc_thread, nullptr, 0, nullptr);
    if (thread) {
      ::CloseHandle(thread);
    }
  }
  return TRUE;
}
