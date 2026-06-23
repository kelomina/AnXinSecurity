// peb_unlink_probe_dll.cpp — PEB Unlink Detection Probe
//
// 这个 DLL 是防护链路验证用的"可观测样本"，不是隐藏样本：
// 1. 分配一块 MEM_PRIVATE + PAGE_EXECUTE_READ 的内存区域；
// 2. 在该区域内写入模拟的 DOS/NT Header 和 LDR_DATA_TABLE_ENTRY 结构，
//    包括 PEB unlink 后典型的"断链"特征（Flink/Blink 指向自身）；
// 3. 保留线程一段时间，方便 Process Explorer / WinDBG / AnXinSecurity 采样；
// 4. 不实际操纵 PEB，不修改任何系统链表，不执行分配区域中的代码。
//
// This is an observable defensive probe, not a stealth payload.
// It simulates PEB unlinking memory artifacts for detection validation only.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

// 默认保持时间 10 分钟，可通过环境变量 ANXIN_PEB_PROBE_HOLD_MS 覆盖。
constexpr DWORD kPebProbeHoldMsDefault = 10 * 60 * 1000;
constexpr SIZE_T kProbeRegionSize = 0x8000;  // 32 KB
constexpr wchar_t kHoldEnvVar[] = L"ANXIN_PEB_PROBE_HOLD_MS";

LPVOID g_probe_region = nullptr;

// ── 辅助写入函数 ────────────────────────────────────────────────────

void write_u16(std::array<std::uint8_t, kProbeRegionSize>& buffer,
               SIZE_T offset, std::uint16_t value) {
  if (offset + sizeof(value) > buffer.size()) return;
  buffer[offset + 0] = static_cast<std::uint8_t>(value & 0xff);
  buffer[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
}

void write_u32(std::array<std::uint8_t, kProbeRegionSize>& buffer,
               SIZE_T offset, std::uint32_t value) {
  if (offset + sizeof(value) > buffer.size()) return;
  buffer[offset + 0] = static_cast<std::uint8_t>(value & 0xff);
  buffer[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xff);
  buffer[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xff);
  buffer[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xff);
}

void write_u64(std::array<std::uint8_t, kProbeRegionSize>& buffer,
               SIZE_T offset, std::uint64_t value) {
  if (offset + sizeof(value) > buffer.size()) return;
  for (int i = 0; i < 8; ++i) {
    buffer[offset + i] = static_cast<std::uint8_t>((value >> (i * 8)) & 0xff);
  }
}

void copy_bytes(std::array<std::uint8_t, kProbeRegionSize>& buffer,
                SIZE_T offset, const char* text) {
  if (!text) return;
  const SIZE_T len = std::strlen(text);
  if (offset >= buffer.size()) return;
  const SIZE_T writable = std::min<SIZE_T>(len, buffer.size() - offset);
  std::memcpy(buffer.data() + offset, text, writable);
}

// 写入宽字符串（用于模拟 UNICODE_STRING 的 Buffer 内容）。
void copy_wide_bytes(std::array<std::uint8_t, kProbeRegionSize>& buffer,
                     SIZE_T offset, const wchar_t* text) {
  if (!text) return;
  const SIZE_T byte_len = (std::wcslen(text) + 1) * sizeof(wchar_t);
  if (offset >= buffer.size()) return;
  const SIZE_T writable = std::min<SIZE_T>(byte_len, buffer.size() - offset);
  std::memcpy(buffer.data() + offset, text, writable);
}

// ── 环境变量读取 ────────────────────────────────────────────────────

DWORD get_hold_time_ms() {
  wchar_t value[32]{};
  DWORD n = ::GetEnvironmentVariableW(kHoldEnvVar, value,
                                      static_cast<DWORD>(std::size(value)));
  if (n > 0 && n < static_cast<DWORD>(std::size(value))) {
    unsigned long ms = std::wcstoul(value, nullptr, 10);
    if (ms > 0) return static_cast<DWORD>(ms);
  }
  return kPebProbeHoldMsDefault;
}

// ── 构建 PEB 断链模拟结构 ───────────────────────────────────────────
//
// 内存布局：
//   0x0000 - 0x00FF  DOS Header（MZ + e_lfanew）
//   0x0100 - 0x02FF  NT Headers（PE + COFF + Optional Header）
//   0x0400 - 0x04FF  模拟 LDR_DATA_TABLE_ENTRY（含断链特征）
//   0x0500 - 0x05FF  模拟"前一个节点"的断链标记
//   0x0600 - 0x06FF  模拟模块路径（宽字符串）
//   0x0800+          诊断信息

void build_peb_unlink_artifacts(
    std::array<std::uint8_t, kProbeRegionSize>& buffer) {
  // ─ DOS Header ─
  write_u16(buffer, 0x00, 0x5A4D);       // e_magic = "MZ"
  write_u32(buffer, 0x3C, 0x100);         // e_lfanew -> NT Headers

  // ─ NT Headers ─
  write_u32(buffer, 0x100, 0x00004550);   // Signature = "PE\0\0"
  write_u16(buffer, 0x104,
            sizeof(void*) == 8 ? 0x8664 : 0x014C);  // Machine
  write_u16(buffer, 0x106, 1);            // NumberOfSections
  write_u16(buffer, 0x114,
            sizeof(void*) == 8 ? 0x00F0 : 0x00E0);  // SizeOfOptionalHeader
  write_u16(buffer, 0x116, 0x210E);       // Characteristics (DLL, etc.)
  write_u16(buffer, 0x118,
            sizeof(void*) == 8 ? 0x20B : 0x10B);    // Optional header magic
  write_u32(buffer, 0x128, 0x1000);       // AddressOfEntryPoint
  write_u32(buffer, 0x138,
            static_cast<std::uint32_t>(kProbeRegionSize));  // SizeOfImage

  // ─ DOS 区域标记 ─
  copy_bytes(buffer, 0x80, "ANXIN_PEB_UNLINK_PROBE");

  // ── 模拟 LDR_DATA_TABLE_ENTRY（偏移 0x400） ──
  //
  // PEB unlink 后，被移除模块的 LDR entry 的 Flink/Blink 通常指向自身
  // 或无效地址，这是安全工具可以检测的典型特征。

  // 使用 0xDEAD000000000000 系列值作为模拟指针，便于检测工具识别。
  constexpr std::uint64_t kSelfPtr = 0xDEAD000000000400ULL;
  constexpr std::uint64_t kNullPtr = 0;

  // InLoadOrderLinks
  write_u64(buffer, 0x400, kSelfPtr);     // Flink -> 自身（断链特征）
  write_u64(buffer, 0x408, kSelfPtr);     // Blink -> 自身（断链特征）

  // InMemoryOrderLinks
  write_u64(buffer, 0x410, kSelfPtr);     // Flink -> 自身
  write_u64(buffer, 0x418, kSelfPtr);     // Blink -> 自身

  // InInitializationOrderLinks
  write_u64(buffer, 0x420, kNullPtr);     // Flink = NULL
  write_u64(buffer, 0x428, kNullPtr);     // Blink = NULL

  // DllBase / EntryPoint / SizeOfImage
  write_u64(buffer, 0x430, kNullPtr);     // DllBase = 0（无实际基址）
  write_u64(buffer, 0x438, kNullPtr);     // EntryPoint = 0
  write_u64(buffer, 0x440, 0x1000);       // SizeOfImage

  // FullDllName (UNICODE_STRING: Length, MaximumLength, Buffer)
  constexpr std::uint16_t kPathChars = 40;  // 包含 null terminator
  write_u16(buffer, 0x448, kPathChars * 2);       // Length (bytes)
  write_u16(buffer, 0x44A, (kPathChars + 2) * 2); // MaximumLength
  write_u64(buffer, 0x450, 0xDEAD000000000600ULL);  // Buffer -> 0x600

  // BaseDllName (UNICODE_STRING)
  constexpr std::uint16_t kBaseChars = 22;
  write_u16(buffer, 0x458, kBaseChars * 2);
  write_u16(buffer, 0x45A, (kBaseChars + 2) * 2);
  write_u64(buffer, 0x460, 0xDEAD000000000630ULL);  // Buffer -> 0x630

  // LDR entry 标记
  copy_bytes(buffer, 0x480, "ANXIN_PEB_UNLINK_SIMULATED_LDR_ENTRY");

  // ── 模拟前一个节点的断链特征（偏移 0x500） ──
  //
  // 当一个模块从 PEB 链表中被 unlink 后，它的前驱和后继节点的
  // Flink/Blink 会被修改为跳过该模块，形成"断链"。

  write_u64(buffer, 0x500, kSelfPtr);     // prev->Flink = prev（跳过被移除模块）
  write_u64(buffer, 0x508, kSelfPtr);     // prev->Blink = prev（断链特征）
  copy_bytes(buffer, 0x520, "ANXIN_PEB_UNLINK_BROKEN_CHAIN_MARKER");

  // ── 模拟模块路径字符串（偏移 0x600） ──
  copy_wide_bytes(buffer, 0x600,
                  L"C:\\AnXinSecurity\\peb_unlink_probe.dll");
  copy_wide_bytes(buffer, 0x630,
                  L"peb_unlink_probe.dll");

  // ── 诊断信息 ──
  copy_bytes(buffer, 0x800, "DEFENSIVE_TEST_ARTIFACT_NOT_MALICIOUS");
  copy_bytes(buffer, 0x900,
             "This region simulates PEB unlinking artifacts for "
             "detection validation only.");
}

// ── 内存区域分配 ────────────────────────────────────────────────────

void allocate_peb_unlink_probe_region() {
  if (g_probe_region) return;

  std::array<std::uint8_t, kProbeRegionSize> buffer{};
  build_peb_unlink_artifacts(buffer);

  LPVOID region = ::VirtualAlloc(nullptr, buffer.size(),
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!region) return;

  std::memcpy(region, buffer.data(), buffer.size());

  DWORD oldProtect = 0;
  if (!::VirtualProtect(region, buffer.size(), PAGE_EXECUTE_READ,
                        &oldProtect)) {
    ::VirtualFree(region, 0, MEM_RELEASE);
    return;
  }

  g_probe_region = region;
}

// ── 工作线程 ────────────────────────────────────────────────────────

DWORD WINAPI peb_unlink_probe_thread(LPVOID) {
  allocate_peb_unlink_probe_region();

  char msg[256]{};
  wsprintfA(msg,
            "[ANXIN_PEB_UNLINK_PROBE] probe region allocated at %p",
            g_probe_region);
  ::OutputDebugStringA(msg);

  DWORD hold_ms = get_hold_time_ms();
  wsprintfA(msg, "[ANXIN_PEB_UNLINK_PROBE] holding for %lu ms", hold_ms);
  ::OutputDebugStringA(msg);

  ::Sleep(hold_ms);

  ::OutputDebugStringA("[ANXIN_PEB_UNLINK_PROBE] probe thread exiting");

  if (g_probe_region) {
    ::VirtualFree(g_probe_region, 0, MEM_RELEASE);
    g_probe_region = nullptr;
  }

  return 0;
}

}  // namespace

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    ::DisableThreadLibraryCalls(hinstDLL);
    HANDLE thread = ::CreateThread(nullptr, 0, peb_unlink_probe_thread,
                                   nullptr, 0, nullptr);
    if (thread) {
      ::CloseHandle(thread);
    }
  }
  return TRUE;
}
