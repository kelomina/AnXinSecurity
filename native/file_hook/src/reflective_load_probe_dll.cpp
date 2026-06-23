// reflective_load_probe_dll.cpp — Reflective DLL Load Detection Probe
//
// 这个 DLL 是防护链路验证用的"可观测样本"，不是隐藏样本：
// 1. 分配一块 MEM_PRIVATE + PAGE_EXECUTE_READ 的内存区域；
// 2. 在该区域内写入更完整的 PE 结构，包括 DOS/NT Headers、3 个 Section
//    Headers（.text/.data/.rdata）和模拟导入表，模拟 reflective DLL loading
//    手动映射后在内存中留下的痕迹；
// 3. 保留线程一段时间，方便 Process Explorer / WinDBG / AnXinSecurity 采样；
// 4. 不实际加载或执行任何 DLL，不修改任何系统结构。
//
// This is an observable defensive probe, not a stealth payload.
// It simulates reflective DLL loading memory artifacts for detection
// validation only.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>

namespace {

// 默认保持时间 10 分钟，可通过环境变量 ANXIN_REFLECTIVE_PROBE_HOLD_MS 覆盖。
constexpr DWORD kReflectiveProbeHoldMsDefault = 10 * 60 * 1000;
constexpr SIZE_T kProbeRegionSize = 0x10000;  // 64 KB
constexpr wchar_t kHoldEnvVar[] = L"ANXIN_REFLECTIVE_PROBE_HOLD_MS";

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

// ── 环境变量读取 ────────────────────────────────────────────────────

DWORD get_hold_time_ms() {
  wchar_t value[32]{};
  DWORD n = ::GetEnvironmentVariableW(kHoldEnvVar, value,
                                      static_cast<DWORD>(std::size(value)));
  if (n > 0 && n < static_cast<DWORD>(std::size(value))) {
    unsigned long ms = std::wcstoul(value, nullptr, 10);
    if (ms > 0) return static_cast<DWORD>(ms);
  }
  return kReflectiveProbeHoldMsDefault;
}

// ── Section Header 写入辅助 ─────────────────────────────────────────
//
// IMAGE_SECTION_HEADER 是 40 字节结构：
//   [0..7]   Name (8 bytes, null-padded)
//   [8..11]  VirtualSize
//   [12..15] VirtualAddress
//   [16..19] SizeOfRawData
//   [20..23] PointerToRawData
//   [24..27] PointerToRelocations
//   [28..31] PointerToLinenumbers
//   [32..33] NumberOfRelocations
//   [34..35] NumberOfLinenumbers
//   [36..39] Characteristics

constexpr std::uint32_t kScnCntCode         = 0x00000020;
constexpr std::uint32_t kScnCntInitData     = 0x00000040;
constexpr std::uint32_t kScnMemExecute      = 0x20000000;
constexpr std::uint32_t kScnMemRead         = 0x40000000;
constexpr std::uint32_t kScnMemWrite        = 0x80000000;

void write_section_header(std::array<std::uint8_t, kProbeRegionSize>& buffer,
                          SIZE_T offset,
                          const char name[8],
                          std::uint32_t virtual_size,
                          std::uint32_t virtual_address,
                          std::uint32_t raw_size,
                          std::uint32_t raw_pointer,
                          std::uint32_t characteristics) {
  if (offset + 40 > buffer.size()) return;
  // Name (8 bytes)
  for (int i = 0; i < 8; ++i) {
    buffer[offset + i] = static_cast<std::uint8_t>(
        (name && name[i]) ? name[i] : '\0');
  }
  write_u32(buffer, offset + 8,  virtual_size);
  write_u32(buffer, offset + 12, virtual_address);
  write_u32(buffer, offset + 16, raw_size);
  write_u32(buffer, offset + 20, raw_pointer);
  write_u32(buffer, offset + 24, 0);  // PointerToRelocations
  write_u32(buffer, offset + 28, 0);  // PointerToLinenumbers
  write_u16(buffer, offset + 32, 0);  // NumberOfRelocations
  write_u16(buffer, offset + 34, 0);  // NumberOfLinenumbers
  write_u32(buffer, offset + 36, characteristics);
}

// ── 构建 Reflective Load 模拟结构 ───────────────────────────────────
//
// 内存布局：
//   0x0000 - 0x00FF  DOS Header（MZ + e_lfanew）
//   0x0100 - 0x02FF  NT Headers（PE + COFF + Optional Header）
//   0x0300 - 0x03FF  Section Headers（.text / .data / .rdata）
//   0x1000 - 0x1FFF  模拟 .text 段（0xCC 填充 + 标记）
//   0x2000 - 0x2FFF  模拟 .data 段（标记）
//   0x3000 - 0x3FFF  模拟 .rdata 段（模拟导入表）
//   0x4000+          诊断信息

void build_reflective_load_artifacts(
    std::array<std::uint8_t, kProbeRegionSize>& buffer) {
  // ── DOS Header ──
  write_u16(buffer, 0x00, 0x5A4D);       // e_magic = "MZ"
  write_u32(buffer, 0x3C, 0x100);         // e_lfanew -> NT Headers

  copy_bytes(buffer, 0x80, "ANXIN_REFLECTIVE_LOAD_PROBE");

  // ── NT Headers ──
  // PE Signature
  write_u32(buffer, 0x100, 0x00004550);   // "PE\0\0"

  // COFF File Header (20 bytes at 0x104)
  write_u16(buffer, 0x104,
            sizeof(void*) == 8 ? 0x8664 : 0x014C);  // Machine
  write_u16(buffer, 0x106, 3);            // NumberOfSections = 3
  write_u32(buffer, 0x108, 0x65A3B1C2);   // TimeDateStamp (arbitrary)
  write_u32(buffer, 0x10C, 0);            // PointerToSymbolTable = 0
  write_u32(buffer, 0x110, 0);            // NumberOfSymbols = 0
  write_u16(buffer, 0x114,
            sizeof(void*) == 8 ? 0x00F0 : 0x00E0);  // SizeOfOptionalHeader
  write_u16(buffer, 0x116, 0x210E);       // Characteristics (DLL, etc.)

  // Optional Header (at 0x118)
  write_u16(buffer, 0x118,
            sizeof(void*) == 8 ? 0x20B : 0x10B);  // Magic (PE32+ / PE32)
  buffer[0x11A] = 14;   // MajorLinkerVersion
  buffer[0x11B] = 0;    // MinorLinkerVersion
  write_u32(buffer, 0x11C, 0x1000);       // SizeOfCode
  write_u32(buffer, 0x120, 0x1000);       // SizeOfInitializedData
  write_u32(buffer, 0x124, 0);            // SizeOfUninitializedData
  write_u32(buffer, 0x128, 0x1000);       // AddressOfEntryPoint

  if (sizeof(void*) == 8) {
    // PE32+ specific fields
    write_u64(buffer, 0x130, 0);          // ImageBase = 0（reflective load 特征）
    write_u32(buffer, 0x12C, 0);          // BaseOfCode (kept 0 for simplicity)
    // SectionAlignment & FileAlignment
    write_u32(buffer, 0x138, 0x1000);     // SectionAlignment
    write_u32(buffer, 0x13C, 0x200);      // FileAlignment
    write_u16(buffer, 0x140, 6);          // MajorOperatingSystemVersion
    write_u16(buffer, 0x142, 0);          // MinorOperatingSystemVersion
    write_u32(buffer, 0x150,
              static_cast<std::uint32_t>(kProbeRegionSize));  // SizeOfImage
    write_u32(buffer, 0x154, 0x400);      // SizeOfHeaders
    write_u32(buffer, 0x158, 0);          // CheckSum = 0
    write_u16(buffer, 0x15C, 2);          // Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI
    write_u16(buffer, 0x15E, 0x8160);     // DllCharacteristics
    write_u32(buffer, 0x16C, 16);         // NumberOfRvaAndSizes
    // Import Directory RVA -> 0x3000 (in .rdata)
    write_u32(buffer, 0x178, 0x3000);     // Import Directory RVA
    write_u32(buffer, 0x17C, 0x100);      // Import Directory Size
  } else {
    // PE32 specific fields
    write_u32(buffer, 0x11C, 0x1000);     // SizeOfCode (already set)
    write_u32(buffer, 0x12C, 0);          // BaseOfCode
    write_u32(buffer, 0x130, 0);          // BaseOfData
    write_u32(buffer, 0x134, 0);          // ImageBase = 0（reflective load 特征）
    write_u32(buffer, 0x138, 0x1000);     // SectionAlignment
    write_u32(buffer, 0x13C, 0x200);      // FileAlignment
    write_u32(buffer, 0x148,
              static_cast<std::uint32_t>(kProbeRegionSize));  // SizeOfImage
    write_u32(buffer, 0x14C, 0x400);      // SizeOfHeaders
    write_u32(buffer, 0x150, 0);          // CheckSum = 0
    write_u16(buffer, 0x154, 2);          // Subsystem
    write_u16(buffer, 0x156, 0x8160);     // DllCharacteristics
    write_u32(buffer, 0x160, 16);         // NumberOfRvaAndSizes
    // Import Directory RVA
    write_u32(buffer, 0x168, 0x3000);
    write_u32(buffer, 0x16C, 0x100);
  }

  // ── Section Headers（偏移 0x300） ──
  //
  // 每个 IMAGE_SECTION_HEADER 为 40 字节。

  // .text (偏移 0x300)
  write_section_header(buffer, 0x300,
                       ".text\0\0\0",
                       0x1000,   // VirtualSize
                       0x1000,   // VirtualAddress
                       0x1000,   // SizeOfRawData
                       0x1000,   // PointerToRawData
                       kScnCntCode | kScnMemExecute | kScnMemRead);

  // .data (偏移 0x328)
  write_section_header(buffer, 0x328,
                       ".data\0\0\0",
                       0x1000,   // VirtualSize
                       0x2000,   // VirtualAddress
                       0x1000,   // SizeOfRawData
                       0x2000,   // PointerToRawData
                       kScnCntInitData | kScnMemRead | kScnMemWrite);

  // .rdata (偏移 0x350)
  write_section_header(buffer, 0x350,
                       ".rdata\0\0",
                       0x1000,   // VirtualSize
                       0x3000,   // VirtualAddress
                       0x1000,   // SizeOfRawData
                       0x3000,   // PointerToRawData
                       kScnCntInitData | kScnMemRead);

  copy_bytes(buffer, 0x380, "ANXIN_REFLECTIVE_SECTION_HEADERS_MARKER");

  // ── 模拟 .text 段（偏移 0x1000） ──
  //
  // 填充 0xCC (INT3) 模拟未初始化代码区域，这是手动映射 DLL
  // 的一个常见检测信号。

  for (SIZE_T i = 0x1000; i < 0x1100 && i < buffer.size(); ++i) {
    buffer[i] = 0xCC;  // INT3
  }
  copy_bytes(buffer, 0x1100, "ANXIN_REFLECTIVE_LOAD_PROBE_CODE_SECTION");
  copy_bytes(buffer, 0x1200, "DEFENSIVE_TEST_ARTIFACT_NO_REAL_CODE_HERE");

  // ── 模拟 .data 段（偏移 0x2000） ──
  copy_bytes(buffer, 0x2000, "ANXIN_REFLECTIVE_LOAD_PROBE_DATA_SECTION");
  // 模拟全局变量区域（全 0，buffer 初始化已为 0）

  // ── 模拟 .rdata 段（偏移 0x3000）── 模拟导入表 ──
  //
  // IMAGE_IMPORT_DESCRIPTOR 结构（20 字节）：
  //   [0..3]   OriginalFirstThunk (RVA to Import Name Table)
  //   [4..7]   TimeDateStamp
  //   [8..11]  ForwarderChain
  //   [12..15] Name (RVA to DLL name string)
  //   [16..19] FirstThunk (RVA to Import Address Table)
  //
  // 我们只写结构特征，不填充实际 IAT 地址。

  // Import Descriptor 1: KERNEL32.dll
  write_u32(buffer, 0x3000, 0x3100);   // OriginalFirstThunk -> INT at 0x3100
  write_u32(buffer, 0x3004, 0);        // TimeDateStamp
  write_u32(buffer, 0x3008, 0);        // ForwarderChain
  write_u32(buffer, 0x300C, 0x3200);   // Name -> "KERNEL32.dll"
  write_u32(buffer, 0x3010, 0x3300);   // FirstThunk -> IAT at 0x3300

  // Null terminator descriptor (全 0，buffer 已初始化)

  // 模拟 Import Name Table (INT) at 0x3100
  // 每个条目是 RVA 指向 IMAGE_IMPORT_BY_NAME（前 2 字节为 Hint）
  write_u32(buffer, 0x3100, 0x3400);   // -> LoadLibraryW
  write_u32(buffer, 0x3104, 0x3420);   // -> VirtualAlloc
  write_u32(buffer, 0x3108, 0x3440);   // -> GetProcAddress
  write_u32(buffer, 0x310C, 0);        // null terminator

  // DLL 名称 at 0x3200
  copy_bytes(buffer, 0x3200, "KERNEL32.dll");

  // 模拟 IAT at 0x3300（全部置 0，表示未解析）
  write_u64(buffer, 0x3300, 0);
  write_u64(buffer, 0x3308, 0);
  write_u64(buffer, 0x3310, 0);
  write_u64(buffer, 0x3318, 0);  // null terminator

  // IMAGE_IMPORT_BY_NAME 条目（Hint + Name）
  // LoadLibraryW at 0x3400
  write_u16(buffer, 0x3400, 0);  // Hint = 0
  copy_bytes(buffer, 0x3402, "LoadLibraryW");

  // VirtualAlloc at 0x3420
  write_u16(buffer, 0x3420, 0);
  copy_bytes(buffer, 0x3422, "VirtualAlloc");

  // GetProcAddress at 0x3440
  write_u16(buffer, 0x3440, 0);
  copy_bytes(buffer, 0x3442, "GetProcAddress");

  // 导入表标记
  copy_bytes(buffer, 0x3500,
             "ANXIN_REFLECTIVE_LOAD_PROBE_IMPORT_TABLE_MARKER");

  // .rdata 段标记
  copy_bytes(buffer, 0x3600,
             "ANXIN_REFLECTIVE_LOAD_PROBE_RDATA_SECTION");

  // ── 诊断信息 ──
  copy_bytes(buffer, 0x4000, "DEFENSIVE_TEST_ARTIFACT_NOT_MALICIOUS");
  copy_bytes(buffer, 0x4100,
             "This region simulates reflective DLL loading artifacts "
             "for detection validation only.");
}

// ── 内存区域分配 ────────────────────────────────────────────────────

void allocate_reflective_load_probe_region() {
  if (g_probe_region) return;

  std::array<std::uint8_t, kProbeRegionSize> buffer{};
  build_reflective_load_artifacts(buffer);

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

DWORD WINAPI reflective_load_probe_thread(LPVOID) {
  allocate_reflective_load_probe_region();

  char msg[256]{};
  wsprintfA(msg,
            "[ANXIN_REFLECTIVE_LOAD_PROBE] probe region allocated at %p",
            g_probe_region);
  ::OutputDebugStringA(msg);

  ::OutputDebugStringA(
      "[ANXIN_REFLECTIVE_LOAD_PROBE] PE structure with 3 sections written");

  DWORD hold_ms = get_hold_time_ms();
  wsprintfA(msg,
            "[ANXIN_REFLECTIVE_LOAD_PROBE] holding for %lu ms", hold_ms);
  ::OutputDebugStringA(msg);

  ::Sleep(hold_ms);

  ::OutputDebugStringA(
      "[ANXIN_REFLECTIVE_LOAD_PROBE] probe thread exiting");

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
    HANDLE thread = ::CreateThread(nullptr, 0,
                                   reflective_load_probe_thread,
                                   nullptr, 0, nullptr);
    if (thread) {
      ::CloseHandle(thread);
    }
  }
  return TRUE;
}
