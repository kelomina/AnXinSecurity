// peb_unlink_real_dll.cpp — Real PEB Unlink Detection Probe
//
// 这个 DLL 实现真实的 PEB（进程环境块）断链技术，用于测试安芯安全软件
// 的「模块链一致性检测」能力。
//
// 与 peb_unlink_probe_dll.cpp（仅构造模拟内存文物）不同，本 DLL 支持
// 通过环境变量 ANXIN_PEB_REAL_PROBE_MODE 选择三种模式：
//   simulate — 仅构造模拟内存文物（与旧 probe 行为一致）
//   real     — 实际从 PEB 的 InLoadOrder/InMemoryOrder/InInitializationOrder
//              三个链表中移除自身模块，提供真实检测窗口
//   both     — 同时执行 simulate 和 real
//
// 真实断链流程：
//   1. 通过 NtQueryInformationProcess 获取 PEB 地址
//   2. 遍历 InLoadOrderModuleList 找到自己的 LDR_DATA_TABLE_ENTRY
//   3. 保存原始 Flink/Blink（六组指针）
//   4. 从三个链表中执行 RemoveEntryList 操作
//   5. 将自身 Flink/Blink 设为自指向（标准断链标记）
//   6. OutputDebugString 输出断链状态
//   7. Sleep(hold_ms) — 为安芯提供检测窗口
//   8. 恢复原始链接
//   9. OutputDebugString 输出恢复状态
//
// 安全机制：
//   - 所有环境变量控制，默认 simulate 模式（安全）
//   - 断链前保存原始状态，线程退出前必须恢复
//   - 恢复失败或未找到自身时不操作 PEB
//   - 代码中明确标记 DEFENSIVE_TEST_ARTIFACT
//
// This DLL implements real PEB (Process Environment Block) unlinking
// to test AnXinSecurity's "module chain consistency" detection.
//
// Unlike peb_unlink_probe_dll.cpp (simulated artifacts only), this DLL
// supports three modes via ANXIN_PEB_REAL_PROBE_MODE:
//   simulate — Construct simulated memory artifacts only
//   real     — Actually unlink from all three PEB module lists
//   both     — Execute both simulate and real

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>

#include "test_config.h"

namespace {

// ── 常量 ──────────────────────────────────────────────────────────────

constexpr DWORD kDefaultHoldMs = 10 * 60 * 1000;   // 10 分钟
constexpr wchar_t kModeEnvVar[] = L"ANXIN_PEB_REAL_PROBE_MODE";
constexpr wchar_t kHoldEnvVar[] = L"ANXIN_PEB_REAL_PROBE_HOLD_MS";

// 模拟模式下的内存区域大小
constexpr SIZE_T kSimulatedRegionSize = 0x8000;  // 32 KB

LPVOID g_simulated_region = nullptr;

// ── 模拟文物辅助写入函数（复用旧 probe 的布局逻辑） ──────────────────

void sim_write_u16(std::array<std::uint8_t, kSimulatedRegionSize>& buf,
                   SIZE_T off, std::uint16_t v) {
  if (off + sizeof(v) > buf.size()) return;
  buf[off + 0] = static_cast<std::uint8_t>(v & 0xff);
  buf[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
}

void sim_write_u32(std::array<std::uint8_t, kSimulatedRegionSize>& buf,
                   SIZE_T off, std::uint32_t v) {
  if (off + sizeof(v) > buf.size()) return;
  buf[off + 0] = static_cast<std::uint8_t>(v & 0xff);
  buf[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
  buf[off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xff);
  buf[off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xff);
}

void sim_write_u64(std::array<std::uint8_t, kSimulatedRegionSize>& buf,
                   SIZE_T off, std::uint64_t v) {
  if (off + sizeof(v) > buf.size()) return;
  for (int i = 0; i < 8; ++i) {
    buf[off + i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xff);
  }
}

void sim_copy_bytes(std::array<std::uint8_t, kSimulatedRegionSize>& buf,
                    SIZE_T off, const char* text) {
  if (!text) return;
  const SIZE_T len = std::strlen(text);
  if (off >= buf.size()) return;
  const SIZE_T n = std::min<SIZE_T>(len, buf.size() - off);
  std::memcpy(buf.data() + off, text, n);
}

void sim_copy_wide(std::array<std::uint8_t, kSimulatedRegionSize>& buf,
                   SIZE_T off, const wchar_t* text) {
  if (!text) return;
  const SIZE_T blen = (std::wcslen(text) + 1) * sizeof(wchar_t);
  if (off >= buf.size()) return;
  const SIZE_T n = std::min<SIZE_T>(blen, buf.size() - off);
  std::memcpy(buf.data() + off, text, n);
}

// ── 构建模拟 PEB 断链文物 ────────────────────────────────────────────

void build_simulated_peb_unlink_artifacts(
    std::array<std::uint8_t, kSimulatedRegionSize>& buf) {
  // DOS Header
  sim_write_u16(buf, 0x00, 0x5A4D);
  sim_write_u32(buf, 0x3C, 0x100);

  // NT Headers
  sim_write_u32(buf, 0x100, 0x00004550);
  sim_write_u16(buf, 0x104, sizeof(void*) == 8 ? 0x8664 : 0x014C);
  sim_write_u16(buf, 0x106, 1);
  sim_write_u16(buf, 0x114, sizeof(void*) == 8 ? 0x00F0 : 0x00E0);
  sim_write_u16(buf, 0x116, 0x210E);
  sim_write_u16(buf, 0x118, sizeof(void*) == 8 ? 0x20B : 0x10B);
  sim_write_u32(buf, 0x128, 0x1000);
  sim_write_u32(buf, 0x138,
                static_cast<std::uint32_t>(kSimulatedRegionSize));

  sim_copy_bytes(buf, 0x80, "ANXIN_PEB_UNLINK_REAL_PROBE");

  // 模拟 LDR_DATA_TABLE_ENTRY（偏移 0x400）
  constexpr std::uint64_t kSelfPtr = 0xDEAD000000000400ULL;
  constexpr std::uint64_t kNullPtr = 0;

  sim_write_u64(buf, 0x400, kSelfPtr);  // Flink -> 自身
  sim_write_u64(buf, 0x408, kSelfPtr);  // Blink -> 自身
  sim_write_u64(buf, 0x410, kSelfPtr);
  sim_write_u64(buf, 0x418, kSelfPtr);
  sim_write_u64(buf, 0x420, kNullPtr);
  sim_write_u64(buf, 0x428, kNullPtr);
  sim_write_u64(buf, 0x430, kNullPtr);
  sim_write_u64(buf, 0x438, kNullPtr);
  sim_write_u64(buf, 0x440, 0x1000);

  constexpr std::uint16_t kPathChars = 40;
  sim_write_u16(buf, 0x448, kPathChars * 2);
  sim_write_u16(buf, 0x44A, (kPathChars + 2) * 2);
  sim_write_u64(buf, 0x450, 0xDEAD000000000600ULL);

  constexpr std::uint16_t kBaseChars = 22;
  sim_write_u16(buf, 0x458, kBaseChars * 2);
  sim_write_u16(buf, 0x45A, (kBaseChars + 2) * 2);
  sim_write_u64(buf, 0x460, 0xDEAD000000000630ULL);

  sim_copy_bytes(buf, 0x480, "ANXIN_PEB_UNLINK_SIMULATED_LDR_ENTRY");

  // 前节点断链标记（偏移 0x500）
  sim_write_u64(buf, 0x500, kSelfPtr);
  sim_write_u64(buf, 0x508, kSelfPtr);
  sim_copy_bytes(buf, 0x520, "ANXIN_PEB_UNLINK_BROKEN_CHAIN_MARKER");

  // 模拟模块路径（偏移 0x600）
  sim_copy_wide(buf, 0x600, L"C:\\AnXinSecurity\\peb_unlink_real_probe.dll");
  sim_copy_wide(buf, 0x630, L"peb_unlink_real_probe.dll");

  // 诊断信息
  sim_copy_bytes(buf, 0x800,
                 anxin_test::kDefensiveTestMarker);
  sim_copy_bytes(buf, 0x900,
                 "PEB unlinking artifacts for detection validation.");
}

// ── 模拟区域分配 ─────────────────────────────────────────────────────

void allocate_simulated_region() {
  if (g_simulated_region) return;

  std::array<std::uint8_t, kSimulatedRegionSize> buf{};
  build_simulated_peb_unlink_artifacts(buf);

  LPVOID region = ::VirtualAlloc(nullptr, buf.size(),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!region) return;

  std::memcpy(region, buf.data(), buf.size());

  DWORD old = 0;
  if (!::VirtualProtect(region, buf.size(), PAGE_EXECUTE_READ, &old)) {
    ::VirtualFree(region, 0, MEM_RELEASE);
    return;
  }

  g_simulated_region = region;
  char msg[256]{};
  wsprintfA(msg,
            "[ANXIN_PEB_REAL_PROBE] simulated region allocated at %p",
            region);
  ::OutputDebugStringA(msg);
}

void free_simulated_region() {
  if (g_simulated_region) {
    ::VirtualFree(g_simulated_region, 0, MEM_RELEASE);
    g_simulated_region = nullptr;
  }
}

// ── 真实 PEB 断链所需结构定义 ─────────────────────────────────────────
//
// 以下结构属于 Windows 内部未公开结构（undocumented），仅在此测试工具中
// 用于安全防御验证，不用作生产功能。
//
// The following structures are Windows internal/undocumented, used only
// in this test tool for security defense validation.

#ifndef CONTAINING_RECORD
#define CONTAINING_RECORD(address, type, field) \
  ((type*)((PCHAR)(address) - (ULONG_PTR)(&((type*)0)->field)))
#endif

typedef LONG NTSTATUS;

typedef struct _ANXIN_UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} ANXIN_UNICODE_STRING, *PANXIN_UNICODE_STRING;

typedef struct _ANXIN_LIST_ENTRY {
  struct _ANXIN_LIST_ENTRY* Flink;
  struct _ANXIN_LIST_ENTRY* Blink;
} ANXIN_LIST_ENTRY, *PANXIN_LIST_ENTRY;

typedef struct _ANXIN_PEB_LDR_DATA {
  ULONG          Length;
  BOOLEAN        Initialized;
  PVOID          SsHandle;
  ANXIN_LIST_ENTRY InLoadOrderModuleList;
  ANXIN_LIST_ENTRY InMemoryOrderModuleList;
  ANXIN_LIST_ENTRY InInitializationOrderModuleList;
} ANXIN_PEB_LDR_DATA, *PANXIN_PEB_LDR_DATA;

typedef struct _ANXIN_LDR_DATA_TABLE_ENTRY {
  ANXIN_LIST_ENTRY  InLoadOrderLinks;
  ANXIN_LIST_ENTRY  InMemoryOrderLinks;
  ANXIN_LIST_ENTRY  InInitializationOrderLinks;
  PVOID             DllBase;
  PVOID             EntryPoint;
  ULONG             SizeOfImage;
  ANXIN_UNICODE_STRING FullDllName;
  ANXIN_UNICODE_STRING BaseDllName;
} ANXIN_LDR_DATA_TABLE_ENTRY, *PANXIN_LDR_DATA_TABLE_ENTRY;

typedef struct _ANXIN_PEB {
  BOOLEAN              InheritedAddressSpace;
  BOOLEAN              ReadImageFileExecOptions;
  BOOLEAN              BeingDebugged;
  BOOLEAN              SpareBool;
  HANDLE               Mutant;
  PVOID                ImageBaseAddress;
  PANXIN_PEB_LDR_DATA  Ldr;
} ANXIN_PEB, *PANXIN_PEB;

typedef struct _ANXIN_PROCESS_BASIC_INFORMATION {
  NTSTATUS  ExitStatus;
  PANXIN_PEB PebBaseAddress;
  ULONG_PTR AffinityMask;
  LONG      BasePriority;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR InheritedFromUniqueProcessId;
} ANXIN_PROCESS_BASIC_INFORMATION;

typedef NTSTATUS (NTAPI* NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    DWORD  ProcessInformationClass,  // 0 = ProcessBasicInformation
    PVOID  ProcessInformation,
    ULONG  ProcessInformationLength,
    PULONG ReturnLength);

// ── 保存的原始链接 ────────────────────────────────────────────────────

struct SavedLinks {
  PANXIN_LIST_ENTRY load_flink;
  PANXIN_LIST_ENTRY load_blink;
  PANXIN_LIST_ENTRY mem_flink;
  PANXIN_LIST_ENTRY mem_blink;
  PANXIN_LIST_ENTRY init_flink;
  PANXIN_LIST_ENTRY init_blink;
  bool valid = false;
};

// ── NtQueryInformationProcess 动态获取 ───────────────────────────────

NtQueryInformationProcessFn get_nt_query_info() {
  HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
  if (!ntdll) return nullptr;
  return reinterpret_cast<NtQueryInformationProcessFn>(
      ::GetProcAddress(ntdll, "NtQueryInformationProcess"));
}

// ── 获取 PEB 地址 ─────────────────────────────────────────────────────

PANXIN_PEB get_peb() {
  auto NtQueryInformationProcess = get_nt_query_info();
  if (!NtQueryInformationProcess) {
    ::OutputDebugStringA(
        "[ANXIN_PEB_REAL_PROBE] NtQueryInformationProcess not found");
    return nullptr;
  }

  ANXIN_PROCESS_BASIC_INFORMATION pbi{};
  NTSTATUS status = NtQueryInformationProcess(
      ::GetCurrentProcess(), 0 /* ProcessBasicInformation */,
      &pbi, sizeof(pbi), nullptr);

  if (status < 0 || !pbi.PebBaseAddress) {
    char msg[128]{};
    wsprintfA(msg,
              "[ANXIN_PEB_REAL_PROBE] failed to get PEB, NTSTATUS=0x%08lX",
              static_cast<unsigned long>(status));
    ::OutputDebugStringA(msg);
    return nullptr;
  }
  return pbi.PebBaseAddress;
}

// ── 在加载顺序链表中查找自身的 LDR 条目 ──────────────────────────────

PANXIN_LDR_DATA_TABLE_ENTRY find_own_ldr_entry(PANXIN_PEB peb) {
  if (!peb || !peb->Ldr) {
    ::OutputDebugStringA(
        "[ANXIN_PEB_REAL_PROBE] PEB or PEB_LDR_DATA is null");
    return nullptr;
  }

  HMODULE self_base = nullptr;
  // 使用 GetModuleHandleEx 获取自身 HMODULE（即 DllBase）
  if (!::GetModuleHandleExW(
          GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
              GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
          reinterpret_cast<LPCWSTR>(&find_own_ldr_entry),
          &self_base)) {
    ::OutputDebugStringA(
        "[ANXIN_PEB_REAL_PROBE] GetModuleHandleExW failed");
    return nullptr;
  }

  PANXIN_LIST_ENTRY head = &peb->Ldr->InLoadOrderModuleList;
  PANXIN_LIST_ENTRY cur = head->Flink;

  while (cur != head) {
    PANXIN_LDR_DATA_TABLE_ENTRY entry =
        CONTAINING_RECORD(cur, ANXIN_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
    if (entry->DllBase == self_base) {
      return entry;
    }
    cur = cur->Flink;
  }

  ::OutputDebugStringA(
      "[ANXIN_PEB_REAL_PROBE] own LDR entry not found in load order list");
  return nullptr;
}

// ── 从 PEB 链表中断链 ─────────────────────────────────────────────────

bool unlink_peb_module(PANXIN_LDR_DATA_TABLE_ENTRY entry,
                       SavedLinks& saved) {
  if (!entry) return false;

  // 保存原始链接
  saved.load_flink = entry->InLoadOrderLinks.Flink;
  saved.load_blink = entry->InLoadOrderLinks.Blink;
  saved.mem_flink  = entry->InMemoryOrderLinks.Flink;
  saved.mem_blink  = entry->InMemoryOrderLinks.Blink;
  saved.init_flink = entry->InInitializationOrderLinks.Flink;
  saved.init_blink = entry->InInitializationOrderLinks.Blink;
  saved.valid = true;

  // 从 InLoadOrderLinks 移除
  entry->InLoadOrderLinks.Blink->Flink = entry->InLoadOrderLinks.Flink;
  entry->InLoadOrderLinks.Flink->Blink = entry->InLoadOrderLinks.Blink;

  // 从 InMemoryOrderLinks 移除
  entry->InMemoryOrderLinks.Blink->Flink = entry->InMemoryOrderLinks.Flink;
  entry->InMemoryOrderLinks.Flink->Blink = entry->InMemoryOrderLinks.Blink;

  // 从 InInitializationOrderLinks 移除
  entry->InInitializationOrderLinks.Blink->Flink =
      entry->InInitializationOrderLinks.Flink;
  entry->InInitializationOrderLinks.Flink->Blink =
      entry->InInitializationOrderLinks.Blink;

  // 标记自身为断链（Flink/Blink 自指向）
  entry->InLoadOrderLinks.Flink = &entry->InLoadOrderLinks;
  entry->InLoadOrderLinks.Blink = &entry->InLoadOrderLinks;
  entry->InMemoryOrderLinks.Flink = &entry->InMemoryOrderLinks;
  entry->InMemoryOrderLinks.Blink = &entry->InMemoryOrderLinks;
  entry->InInitializationOrderLinks.Flink = &entry->InInitializationOrderLinks;
  entry->InInitializationOrderLinks.Blink = &entry->InInitializationOrderLinks;

  ::OutputDebugStringA(
      "[ANXIN_PEB_REAL_PROBE] module unlinked from PEB — "
      "detection window open");
  return true;
}

// ── 恢复 PEB 链接 ─────────────────────────────────────────────────────

bool relink_peb_module(PANXIN_LDR_DATA_TABLE_ENTRY entry,
                       const SavedLinks& saved) {
  if (!entry || !saved.valid) {
    ::OutputDebugStringA(
        "[ANXIN_PEB_REAL_PROBE] skip relink: entry null or no saved state");
    return false;
  }

  // 恢复 InLoadOrderLinks
  saved.load_blink->Flink = &entry->InLoadOrderLinks;
  saved.load_flink->Blink = &entry->InLoadOrderLinks;
  entry->InLoadOrderLinks.Flink = saved.load_flink;
  entry->InLoadOrderLinks.Blink = saved.load_blink;

  // 恢复 InMemoryOrderLinks
  saved.mem_blink->Flink = &entry->InMemoryOrderLinks;
  saved.mem_flink->Blink = &entry->InMemoryOrderLinks;
  entry->InMemoryOrderLinks.Flink = saved.mem_flink;
  entry->InMemoryOrderLinks.Blink = saved.mem_blink;

  // 恢复 InInitializationOrderLinks
  saved.init_blink->Flink = &entry->InInitializationOrderLinks;
  saved.init_flink->Blink = &entry->InInitializationOrderLinks;
  entry->InInitializationOrderLinks.Flink = saved.init_flink;
  entry->InInitializationOrderLinks.Blink = saved.init_blink;

  ::OutputDebugStringA(
      "[ANXIN_PEB_REAL_PROBE] module relinked to PEB — "
      "detection window closed");
  return true;
}

// ── 主工作线程 ────────────────────────────────────────────────────────

DWORD WINAPI peb_unlink_real_worker(LPVOID) {
  anxin_test::ProbeMode mode =
      anxin_test::read_probe_mode_from_env(kModeEnvVar);
  DWORD hold_ms = anxin_test::read_hold_time_ms(kHoldEnvVar, kDefaultHoldMs);

  char msg[256]{};

  // ── 模拟模式 ──
  if (anxin_test::should_run_simulate(mode)) {
    ::OutputDebugStringA(
        "[ANXIN_PEB_REAL_PROBE] running simulate mode");
    allocate_simulated_region();
  }

  // ── 真实模式 ──
  if (anxin_test::should_run_real(mode)) {
    ::OutputDebugStringA(
        "[ANXIN_PEB_REAL_PROBE] running real PEB unlink mode");

    PANXIN_PEB peb = get_peb();
    if (!peb) {
      wsprintfA(msg,
                "[ANXIN_PEB_REAL_PROBE] failed to get PEB, "
                "holding %lu ms for observation anyway",
                hold_ms);
      ::OutputDebugStringA(msg);
      ::Sleep(hold_ms);
      free_simulated_region();
      return 0;
    }

    PANXIN_LDR_DATA_TABLE_ENTRY entry = find_own_ldr_entry(peb);
    if (!entry) {
      wsprintfA(msg,
                "[ANXIN_PEB_REAL_PROBE] failed to find own LDR entry, "
                "holding %lu ms",
                hold_ms);
      ::OutputDebugStringA(msg);
      ::Sleep(hold_ms);
      free_simulated_region();
      return 0;
    }

    SavedLinks saved{};
    if (!unlink_peb_module(entry, saved)) {
      ::OutputDebugStringA(
          "[ANXIN_PEB_REAL_PROBE] PEB unlink operation failed");
      free_simulated_region();
      return 1;
    }

    wsprintfA(msg,
              "[ANXIN_PEB_REAL_PROBE] holding unlinked state for %lu ms "
              "— detection window active",
              hold_ms);
    ::OutputDebugStringA(msg);

    ::Sleep(hold_ms);

    if (!relink_peb_module(entry, saved)) {
      ::OutputDebugStringA(
          "[ANXIN_PEB_REAL_PROBE] WARNING: PEB relink failed! "
          "Process may have stale module list state.");
    }
  } else if (!anxin_test::should_run_simulate(mode)) {
    // 既不是 simulate 也不是 real — 不应该发生，但做安全处理
    ::OutputDebugStringA(
        "[ANXIN_PEB_REAL_PROBE] no mode selected, holding default time");
    ::Sleep(hold_ms);
  } else {
    // 仅模拟模式：等待以提供采样窗口
    wsprintfA(msg,
              "[ANXIN_PEB_REAL_PROBE] simulate-only mode, "
              "holding %lu ms for observation",
              hold_ms);
    ::OutputDebugStringA(msg);
    ::Sleep(hold_ms);
  }

  ::OutputDebugStringA(
      "[ANXIN_PEB_REAL_PROBE] probe thread exiting");

  free_simulated_region();
  return 0;
}

}  // namespace

// ── DllMain ────────────────────────────────────────────────────────────
//
// 入口点 (Entry point): 在 DLL_PROCESS_ATTACH 时创建工作线程并分离，
// 遵循项目已有 probe DLL 的统一模式。
//
// Creates a detached worker thread on DLL_PROCESS_ATTACH,
// following the existing probe DLL convention.

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    ::DisableThreadLibraryCalls(hinstDLL);
    HANDLE thread = ::CreateThread(nullptr, 0, peb_unlink_real_worker,
                                   nullptr, 0, nullptr);
    if (thread) {
      ::CloseHandle(thread);
    }
  }
  return TRUE;
}
