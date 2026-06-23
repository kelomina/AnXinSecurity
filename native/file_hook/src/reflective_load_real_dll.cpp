// reflective_load_real_dll.cpp — Real Reflective DLL Load Detection Probe
//
// 这个 DLL 实现真实的反射式 DLL 加载技术，用于测试安芯安全软件
// 是否能够检测从不触发 LoadLibrary 事件的「手动映射」注入。
//
// 与 reflective_load_probe_dll.cpp（仅构造模拟内存文物）不同，本 DLL
// 支持通过环境变量 ANXIN_REFLECTIVE_REAL_PROBE_MODE 选择三种模式：
//   simulate — 仅构造模拟内存文物（与旧 probe 行为一致）
//   real     — 内嵌一个最小化 x64 DLL，完成完整的反射加载流程
//   both     — 同时执行 simulate 和 real
//
// 真实反射加载流程：
//   1. 在内存中构造一个最小化 x64 PE DLL 文件
//   2. VirtualAlloc 分配 MEM_PRIVATE + PAGE_READWRITE 内存
//   3. 复制 PE 头到分配内存
//   4. 遍历 Section Headers，将各节映射到正确 RVA
//   5. 解析 Base Relocation 目录，修正重定位地址
//   6. 解析 Import Directory，在 kernel32.dll 导出表中查找函数
//   7. 填充 IAT（Import Address Table）
//   8. VirtualProtect 各区段到对应保护属性
//   9. 调用 DllMain(hModule, DLL_PROCESS_ATTACH, NULL)
//   10. Sleep(hold_ms) — 提供检测窗口
//   11. 调用 DllMain(hModule, DLL_PROCESS_DETACH, NULL)
//   12. VirtualFree 释放内存
//
// 关键检测信号（安芯应能捕捉）:
//   - MEM_PRIVATE + PAGE_EXECUTE_* 内存中存在完整 MZ/PE 结构
//   - 无 LoadLibrary ETW 事件（文件不会被映射为 MEM_MAPPED）
//   - 模块不出现在 PEB 模块列表中
//   - 与安芯的「模块链一致性检测」直接对应
//
// This DLL implements real reflective DLL loading to test AnXinSecurity's
// detection of manual-mapped DLL injection (no LoadLibrary event).
//
// Supports three modes via ANXIN_REFLECTIVE_REAL_PROBE_MODE.
// Real mode embeds a minimal x64 DLL and performs full reflective loading:
// manual mapping, import resolution, relocation, DllMain invocation.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>
#include <winternl.h>  // IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, etc.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <string>
#include <vector>

#include "test_config.h"

namespace {

// ── 常量 ──────────────────────────────────────────────────────────────

constexpr DWORD kDefaultHoldMs = 10 * 60 * 1000;   // 10 分钟
constexpr wchar_t kModeEnvVar[] = L"ANXIN_REFLECTIVE_REAL_PROBE_MODE";
constexpr wchar_t kHoldEnvVar[] = L"ANXIN_REFLECTIVE_REAL_PROBE_HOLD_MS";

// 模拟模式内存区域大小
constexpr SIZE_T kSimulatedRegionSize = 0x10000;  // 64 KB

LPVOID g_simulated_region = nullptr;

// ── 模拟文物辅助写入函数 ──────────────────────────────────────────────

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

void sim_write_section_header(
    std::array<std::uint8_t, kSimulatedRegionSize>& buf,
    SIZE_T off, const char name[8],
    std::uint32_t virtual_size, std::uint32_t virtual_address,
    std::uint32_t raw_size, std::uint32_t raw_pointer,
    std::uint32_t characteristics) {
  if (off + 40 > buf.size()) return;
  for (int i = 0; i < 8; ++i) {
    buf[off + i] = static_cast<std::uint8_t>(name[i]);
  }
  sim_write_u32(buf, off + 8,  virtual_size);
  sim_write_u32(buf, off + 12, virtual_address);
  sim_write_u32(buf, off + 16, raw_size);
  sim_write_u32(buf, off + 20, raw_pointer);
  sim_write_u32(buf, off + 24, 0);
  sim_write_u32(buf, off + 28, 0);
  sim_write_u16(buf, off + 32, 0);
  sim_write_u16(buf, off + 34, 0);
  sim_write_u32(buf, off + 36, characteristics);
}

// ── 构建模拟反射加载文物 ─────────────────────────────────────────────

void build_simulated_reflective_load_artifacts(
    std::array<std::uint8_t, kSimulatedRegionSize>& buf) {
  // DOS Header
  sim_write_u16(buf, 0x00, 0x5A4D);
  sim_write_u32(buf, 0x3C, 0x100);
  sim_copy_bytes(buf, 0x80, "ANXIN_REFLECTIVE_LOAD_REAL_PROBE");

  // PE Signature + COFF Header
  sim_write_u32(buf, 0x100, 0x00004550);
  sim_write_u16(buf, 0x104, sizeof(void*) == 8 ? 0x8664 : 0x014C);
  sim_write_u16(buf, 0x106, 3);
  sim_write_u32(buf, 0x108, 0x65A3B1C2);
  sim_write_u16(buf, 0x114, sizeof(void*) == 8 ? 0x00F0 : 0x00E0);
  sim_write_u16(buf, 0x116, 0x210E);

  // Optional Header PE32+
  sim_write_u16(buf, 0x118, sizeof(void*) == 8 ? 0x20B : 0x10B);
  buf[0x11A] = 14;
  buf[0x11B] = 0;
  sim_write_u32(buf, 0x11C, 0x1000);
  sim_write_u32(buf, 0x120, 0x1000);
  sim_write_u32(buf, 0x128, 0x1000);

  if (sizeof(void*) == 8) {
    sim_write_u64(buf, 0x130, 0);
    sim_write_u32(buf, 0x138, 0x1000);
    sim_write_u32(buf, 0x13C, 0x200);
    sim_write_u32(buf, 0x150,
                  static_cast<std::uint32_t>(kSimulatedRegionSize));
    sim_write_u32(buf, 0x154, 0x400);
    sim_write_u16(buf, 0x15C, 2);
    sim_write_u16(buf, 0x15E, 0x8160);
    sim_write_u32(buf, 0x16C, 16);
    sim_write_u32(buf, 0x178, 0x3000);
    sim_write_u32(buf, 0x17C, 0x100);
  }

  // Section Headers
  sim_write_section_header(buf, 0x300, ".text\0\0\0",
                           0x1000, 0x1000, 0x1000, 0x1000,
                           0x60000020);
  sim_write_section_header(buf, 0x328, ".data\0\0\0",
                           0x1000, 0x2000, 0x1000, 0x2000,
                           0xC0000040);
  sim_write_section_header(buf, 0x350, ".rdata\0\0",
                           0x1000, 0x3000, 0x1000, 0x3000,
                           0x40000040);

  sim_copy_bytes(buf, 0x380, "ANXIN_REFLECTIVE_SECTION_HEADERS_MARKER");

  // .text 段（0xCC 填充）
  for (SIZE_T i = 0x1000; i < 0x1100 && i < buf.size(); ++i) buf[i] = 0xCC;
  sim_copy_bytes(buf, 0x1100, "ANXIN_REFLECTIVE_LOAD_REAL_CODE_SECTION");
  sim_copy_bytes(buf, 0x1200, anxin_test::kDefensiveTestMarker);

  // .data 段
  sim_copy_bytes(buf, 0x2000, "ANXIN_REFLECTIVE_LOAD_REAL_DATA_SECTION");

  // .rdata 段（模拟导入表结构）
  sim_write_u32(buf, 0x3000, 0x3100);
  sim_write_u32(buf, 0x300C, 0x3200);
  sim_write_u32(buf, 0x3010, 0x3300);
  sim_write_u32(buf, 0x3100, 0x3400);
  sim_write_u32(buf, 0x3104, 0x3420);
  sim_write_u32(buf, 0x3108, 0x3440);
  sim_copy_bytes(buf, 0x3200, "KERNEL32.dll");
  sim_write_u16(buf, 0x3400, 0);
  sim_copy_bytes(buf, 0x3402, "LoadLibraryW");
  sim_write_u16(buf, 0x3420, 0);
  sim_copy_bytes(buf, 0x3422, "VirtualAlloc");
  sim_write_u16(buf, 0x3440, 0);
  sim_copy_bytes(buf, 0x3442, "GetProcAddress");
  sim_copy_bytes(buf, 0x3500,
                 "ANXIN_REFLECTIVE_LOAD_REAL_IMPORT_TABLE_MARKER");

  // 诊断信息
  sim_copy_bytes(buf, 0x4000, anxin_test::kDefensiveTestMarker);
  sim_copy_bytes(buf, 0x4100,
                 "Reflective DLL loading artifacts for detection validation.");
}

// ── 模拟区域分配与释放 ───────────────────────────────────────────────

void allocate_simulated_region() {
  if (g_simulated_region) return;

  std::array<std::uint8_t, kSimulatedRegionSize> buf{};
  build_simulated_reflective_load_artifacts(buf);

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
            "[ANXIN_REFLECTIVE_REAL_PROBE] simulated region allocated at %p",
            region);
  ::OutputDebugStringA(msg);
}

void free_simulated_region() {
  if (g_simulated_region) {
    ::VirtualFree(g_simulated_region, 0, MEM_RELEASE);
    g_simulated_region = nullptr;
  }
}

// ──────────────────────────────────────────────────────────────────────
//  真实反射加载：构建最小化 x64 DLL
// ──────────────────────────────────────────────────────────────────────
//
// 构建一个最小化的 PE32+ DLL 字节数组，包含：
//  - DOS Header + PE/COFF/Optional Headers
//  - .text  段：DllMain(return TRUE) 的最小实现（6 字节机器码）
//  - .rdata 段：导入 kernel32!OutputDebugStringA 的完整导入表结构
//  - .reloc 段：一个 Base Relocation 块（用于修正 IA64 指针）
//
// Constructs a minimal PE32+ DLL byte array.
//
// File layout:
//   Offset    Size  Content
//   0x000     0x80  DOS Header + Stub
//   0x080     0x108 PE Signature + COFF + Optional Header + Data Dirs
//   0x188     0x78  3 Section Headers
//   0x200     0x200 .text raw data (6 bytes code + padding)
//   0x400     0x200 .rdata raw data (import tables + strings + padding)
//   0x600     0x200 .reloc raw data (base relocation block + padding)
//   Total:    0x800 (2048 bytes)
//
// Memory layout (SectionAlignment = 0x1000):
//   0x0000    0x400 Headers
//   0x1000    0x1000 .text section
//   0x2000    0x1000 .rdata section
//   0x3000    0x1000 .reloc section
//   SizeOfImage = 0x4000

// PE section flag constants
constexpr std::uint32_t kScnMemExecute  = 0x20000000;
constexpr std::uint32_t kScnMemRead     = 0x40000000;
constexpr std::uint32_t kScnMemWrite    = 0x80000000;
constexpr std::uint32_t kScnCntCode     = 0x00000020;
constexpr std::uint32_t kScnCntInitData = 0x00000040;
constexpr std::uint32_t kCharacteristicsDll =
    0x2022;  // IMAGE_FILE_DLL | IMAGE_FILE_EXECUTABLE | LARGE_ADDRESS_AWARE
constexpr std::uint16_t kDllCharacteristics = 0x8160;
constexpr std::uint16_t kSubsystemWindowsGui = 2;

// ── PE 结构偏移常量（文件内偏移，非 RVA） ────────────────────────────

constexpr size_t kDosSize         = 0x40;   // 64 bytes
constexpr size_t kStubSize        = 0x40;   // 64 bytes (total = 0x80)
constexpr size_t kPeSigOff        = 0x80;   // PE signature offset
constexpr size_t kCoffHdrOff      = 0x84;
constexpr size_t kOptHdrOff       = 0x98;   // Optional header offset
constexpr size_t kSectionHdrOff   = 0x188;  // Section headers offset
constexpr size_t kFileAlign       = 0x200;
constexpr size_t kSectionAlign    = 0x1000;

// Section VAs and raw offsets
constexpr std::uint32_t kTextVA   = 0x1000;
constexpr std::uint32_t kRdataVA  = 0x2000;
constexpr std::uint32_t kRelocVA  = 0x3000;
constexpr size_t kTextRaw         = 0x200;
constexpr size_t kRdataRaw        = 0x400;
constexpr size_t kRelocRaw        = 0x600;
constexpr size_t kDllFileSize     = 0x800;  // Total file size: 2048

// RVAs within .rdata (relative to image base)
// Import Descriptor at RVA 0x2000 (offset 0 in .rdata)
constexpr std::uint32_t kImportDescRVA      = 0x2000;
constexpr std::uint32_t kIAT_RVA            = 0x2028;
constexpr std::uint32_t kDllNameRVA         = 0x2038;
constexpr std::uint32_t kILT_RVA            = 0x2050;
constexpr std::uint32_t kImportByNameRVA    = 0x2068;
constexpr std::uint32_t kFuncNameRVA        = 0x206A;

// ── 字节写入辅助 ─────────────────────────────────────────────────────

void pe_w8(std::vector<std::uint8_t>& buf, size_t off, std::uint8_t v) {
  if (off < buf.size()) buf[off] = v;
}
void pe_w16(std::vector<std::uint8_t>& buf, size_t off, std::uint16_t v) {
  if (off + 2 <= buf.size()) std::memcpy(&buf[off], &v, 2);
}
void pe_w32(std::vector<std::uint8_t>& buf, size_t off, std::uint32_t v) {
  if (off + 4 <= buf.size()) std::memcpy(&buf[off], &v, 4);
}
void pe_w64(std::vector<std::uint8_t>& buf, size_t off, std::uint64_t v) {
  if (off + 8 <= buf.size()) std::memcpy(&buf[off], &v, 8);
}
void pe_wstr(std::vector<std::uint8_t>& buf, size_t off, const char* s) {
  size_t len = std::strlen(s);
  if (off + len <= buf.size()) std::memcpy(&buf[off], s, len);
}

// ── 写入 IMAGE_SECTION_HEADER ─────────────────────────────────────────

void write_section(std::vector<std::uint8_t>& buf, size_t off,
                   const char name[8],
                   std::uint32_t vsize, std::uint32_t vaddr,
                   std::uint32_t rsize, std::uint32_t rptr,
                   std::uint32_t chars) {
  if (off + 40 > buf.size()) return;
  for (int i = 0; i < 8; ++i) buf[off + i] = static_cast<std::uint8_t>(name[i]);
  pe_w32(buf, off + 8,  vsize);
  pe_w32(buf, off + 12, vaddr);
  pe_w32(buf, off + 16, rsize);
  pe_w32(buf, off + 20, rptr);
  // PointerToRelocations, PointerToLinenumbers, NumberOfRelocations, NumberOfLinenumbers = 0
  pe_w32(buf, off + 36, chars);
}

// ── 构建最小化 x64 DLL 字节数组 ───────────────────────────────────────
//
// 函数名称: build_minimal_reflective_stub_dll
//
// 函数作用:
//   在内存中程序化构建一个最小 PE32+ DLL 文件，作为反射加载的目标。
//   DLL 包含一个导入项 kernel32!OutputDebugStringA（供 import resolver 测试），
//   DllMain 仅返回 TRUE（6 字节位置无关代码）。
//
// Purpose:
//   Programmatically constructs a minimal PE32+ DLL byte array
//   to serve as the target for reflective loading.
//
// 调用方 (Called by): reflectively_load_and_run
// 被调用方 (Calls): pe_w8, pe_w16, pe_w32, pe_w64, pe_wstr, write_section
//
// 返回值 (Returns):
//   std::vector<std::uint8_t> — 完整 DLL 文件字节，大小 = kDllFileSize
//   Complete DLL file bytes, size = kDllFileSize
//
// 副作用 (Side effects): 无（纯内存构造）
// 并发与幂等 (Concurrency): 线程安全，可重复调用

std::vector<std::uint8_t> build_minimal_reflective_stub_dll() {
  std::vector<std::uint8_t> dll(kDllFileSize, 0);

  // ═══════════════════════════════════════════════════════════════════
  //  DOS Header (0x00 – 0x3F)
  // ═══════════════════════════════════════════════════════════════════
  pe_w16(dll, 0x00, 0x5A4D);       // e_magic = "MZ"
  pe_w16(dll, 0x02, 0x0090);       // e_cblp
  pe_w16(dll, 0x04, 0x0003);       // e_cp
  pe_w16(dll, 0x06, 0x0000);       // e_crlc
  pe_w16(dll, 0x08, 0x0004);       // e_cparhdr
  pe_w16(dll, 0x0A, 0x0000);       // e_minalloc
  pe_w16(dll, 0x0C, 0xFFFF);       // e_maxalloc
  pe_w16(dll, 0x0E, 0x0000);       // e_ss
  pe_w16(dll, 0x10, 0x00B8);       // e_sp
  pe_w16(dll, 0x12, 0x0000);       // e_csum
  pe_w16(dll, 0x14, 0x0000);       // e_ip
  pe_w16(dll, 0x16, 0x0000);       // e_cs
  pe_w16(dll, 0x18, 0x0040);       // e_lfarlc
  pe_w16(dll, 0x1A, 0x0000);       // e_ovno
  pe_w32(dll, 0x3C, 0x00000080);   // e_lfanew → PE signature at 0x80

  // DOS Stub (0x40 – 0x7F)
  pe_wstr(dll, 0x40, "This program cannot be run in DOS mode.\r\n$");

  // ═══════════════════════════════════════════════════════════════════
  //  PE Signature (0x80)
  // ═══════════════════════════════════════════════════════════════════
  pe_w32(dll, kPeSigOff, 0x00004550);  // "PE\0\0"

  // ═══════════════════════════════════════════════════════════════════
  //  COFF File Header (0x84 – 0x97, 20 bytes)
  // ═══════════════════════════════════════════════════════════════════
  pe_w16(dll, 0x84, 0x8664);           // Machine = AMD64
  pe_w16(dll, 0x86, 3);                 // NumberOfSections
  pe_w32(dll, 0x88, 0);                 // TimeDateStamp = 0
  pe_w32(dll, 0x8C, 0);                 // PointerToSymbolTable
  pe_w32(dll, 0x90, 0);                 // NumberOfSymbols
  pe_w16(dll, 0x94, 0x00F0);            // SizeOfOptionalHeader (PE32+ = 240)
  pe_w16(dll, 0x96, kCharacteristicsDll);

  // ═══════════════════════════════════════════════════════════════════
  //  Optional Header PE32+ (0x98 – 0x187, 240 bytes)
  // ═══════════════════════════════════════════════════════════════════
  pe_w16(dll, 0x98, 0x020B);            // Magic = PE32+
  pe_w8 (dll, 0x9A, 14);                // MajorLinkerVersion
  pe_w8 (dll, 0x9B, 0);                 // MinorLinkerVersion
  pe_w32(dll, 0x9C, 0x200);             // SizeOfCode
  pe_w32(dll, 0xA0, 0x200);             // SizeOfInitializedData
  pe_w32(dll, 0xA4, 0);                 // SizeOfUninitializedData
  pe_w32(dll, 0xA8, kTextVA);           // AddressOfEntryPoint = .text VA
  pe_w32(dll, 0xAC, kTextVA);           // BaseOfCode = .text VA

  // PE32+ specific
  pe_w64(dll, 0xB0, 0);                 // ImageBase = 0
  pe_w32(dll, 0xB8, kSectionAlign);     // SectionAlignment = 0x1000
  pe_w32(dll, 0xBC, kFileAlign);        // FileAlignment = 0x200
  pe_w16(dll, 0xC0, 6);                 // MajorOSVersion
  pe_w16(dll, 0xC2, 0);                 // MinorOSVersion
  pe_w16(dll, 0xC4, 0);                 // MajorImageVersion
  pe_w16(dll, 0xC6, 0);                 // MinorImageVersion
  pe_w16(dll, 0xC8, 6);                 // MajorSubsystemVersion
  pe_w16(dll, 0xCA, 0);                 // MinorSubsystemVersion
  pe_w32(dll, 0xCC, 0);                 // Win32VersionValue
  pe_w32(dll, 0xD0, 0x4000);            // SizeOfImage = 4 pages
  pe_w32(dll, 0xD4, 0x200);             // SizeOfHeaders (DOS+PE+COFF+Optional+Section aligned to FileAlignment)
  pe_w32(dll, 0xD8, 0);                 // CheckSum = 0
  pe_w16(dll, 0xDC, kSubsystemWindowsGui);
  pe_w16(dll, 0xDE, kDllCharacteristics);
  pe_w64(dll, 0xE0, 0x100000);          // SizeOfStackReserve = 1MB
  pe_w64(dll, 0xE8, 0x1000);            // SizeOfStackCommit
  pe_w64(dll, 0xF0, 0x100000);          // SizeOfHeapReserve = 1MB
  pe_w64(dll, 0xF8, 0x1000);            // SizeOfHeapCommit
  pe_w32(dll, 0x100, 0);                // LoaderFlags
  pe_w32(dll, 0x104, 16);               // NumberOfRvaAndSizes

  // Data Directories (16 × 8 bytes at 0x108):
  //   [0] Export: empty
  //   [1] Import: RVA=0x2000, Size=0x50
  pe_w32(dll, 0x110, kImportDescRVA);
  pe_w32(dll, 0x114, 0x50);
  //   [2..4] Resource, Exception, Security: empty
  //   [5] Base Reloc: RVA=0x3000, Size=0x0C
  pe_w32(dll, 0x130, kRelocVA);
  pe_w32(dll, 0x134, 0x0C);
  //   [6..15] empty

  // ═══════════════════════════════════════════════════════════════════
  //  Section Headers (0x188, 3 × 40 bytes)
  // ═══════════════════════════════════════════════════════════════════

  // .text:  code
  write_section(dll, 0x188,
                ".text\0\0\0",
                0x006,                     // VirtualSize = 6 bytes (code)
                kTextVA,                   // VA = 0x1000
                0x200,                     // SizeOfRawData
                kTextRaw,                  // PointerToRawData
                kScnCntCode | kScnMemExecute | kScnMemRead);

  // .rdata:  initialized data (imports, strings)
  write_section(dll, 0x1B0,
                ".rdata\0\0",
                0x080,                     // VirtualSize = ~128 bytes
                kRdataVA,                  // VA = 0x2000
                0x200,                     // SizeOfRawData
                kRdataRaw,                 // PointerToRawData
                kScnCntInitData | kScnMemRead);

  // .reloc:  base relocations
  write_section(dll, 0x1D8,
                ".reloc\0\0",
                0x00C,                     // VirtualSize = 12 bytes
                kRelocVA,                  // VA = 0x3000
                0x200,                     // SizeOfRawData
                kRelocRaw,                 // PointerToRawData
                kScnCntInitData | kScnMemRead);

  // ═══════════════════════════════════════════════════════════════════
  //  .text Section Raw Data (file offset 0x200)
  // ═══════════════════════════════════════════════════════════════════
  //
  // DllMain machine code (x64, position-independent):
  //   B8 01 00 00 00    mov eax, 1
  //   C3                ret

  const std::uint8_t dllmain_code[] = {
      0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
      0xC3                           // ret
  };
  std::memcpy(&dll[kTextRaw], dllmain_code, sizeof(dllmain_code));

  // ═══════════════════════════════════════════════════════════════════
  //  .rdata Section Raw Data (file offset 0x400)
  // ═══════════════════════════════════════════════════════════════════

  // IMAGE_IMPORT_DESCRIPTOR for kernel32.dll
  // OriginalFirstThunk (RVA 0x2000): RVA of ILT = 0x2050
  pe_w32(dll, kRdataRaw, kILT_RVA);
  // TimeDateStamp (RVA +4): 0
  // ForwarderChain (RVA +8): 0
  // Name (RVA +12): RVA of "KERNEL32.dll" string = 0x2038
  pe_w32(dll, kRdataRaw + 12, kDllNameRVA);
  // FirstThunk (RVA +16): RVA of IAT = 0x2028
  pe_w32(dll, kRdataRaw + 16, kIAT_RVA);
  // IMAGE_IMPORT_DESCRIPTOR terminator (next 20 bytes) is already zero

  // ── DLL Name at RVA 0x2038 (file offset 0x400 + 0x38 = 0x438) ──
  pe_wstr(dll, 0x438, "KERNEL32.dll");

  // ── IAT (Import Address Table) at RVA 0x2028 ──
  // (file offset 0x400 + 0x28 = 0x428)
  // Entries will be filled by the reflective loader.
  // First entry (for OutputDebugStringA) is currently 0.
  // Terminator is already 0.

  // ── ILT (Import Lookup Table) at RVA 0x2050 ──
  // (file offset 0x400 + 0x50 = 0x450)
  // Entry: IMAGE_IMPORT_BY_NAME RVA = 0x2068
  pe_w64(dll, 0x450, kImportByNameRVA);
  // ILT terminator is already 0

  // ── IMAGE_IMPORT_BY_NAME at RVA 0x2068 ──
  // (file offset 0x400 + 0x68 = 0x468)
  pe_w16(dll, 0x468, 0);             // Hint = 0
  pe_wstr(dll, 0x46A, "OutputDebugStringA");  // Name

  // Diagnostic marker in .rdata
  pe_wstr(dll, 0x480, anxin_test::kDefensiveTestMarker);

  // ═══════════════════════════════════════════════════════════════════
  //  .reloc Section Raw Data (file offset 0x600)
  // ═══════════════════════════════════════════════════════════════════
  //
  // IMAGE_BASE_RELOCATION block for page RVA 0x2000:
  //   - Page RVA: 0x2000
  //   - Block Size: 0x0C (8 bytes header + 4 bytes for one entry)
  //   - Entry: type=IMAGE_REL_BASED_DIR64 (0xA), offset=0x28
  //     → (0xA << 12) | 0x28 = 0xA028
  //   This relocates the IAT entry at RVA 0x2028.

  pe_w32(dll, kRelocRaw,     0x2000);  // Page RVA
  pe_w32(dll, kRelocRaw + 4, 0x000C);  // Block Size
  pe_w16(dll, kRelocRaw + 8, 0xA028);  // DIR64 at offset 0x28
  // Remaining entries are zero (padding)

  return dll;
}

// ──────────────────────────────────────────────────────────────────────
//  真实反射加载：导入表解析
// ──────────────────────────────────────────────────────────────────────
//
// 函数名称: resolve_reflective_imports
//
// 函数作用:
//   解析反射加载 DLL 的导入表。通过 kernel32.dll 的导出表查找函数地址，
//   然后填充目标 DLL 的 IAT。
//   当前实现仅解析 kernel32.dll 的导入（始终在线程中），可扩展为遍历所有导入 DLL。
//
// Purpose:
//   Resolves the import table of the reflectively loaded DLL.
//   Looks up function addresses in kernel32.dll's export table
//   and fills the target DLL's IAT.
//
// 调用方 (Called by): reflectively_load_and_run
// 被调用方 (Calls):
//   - GetModuleHandleW → 获取 kernel32.dll 基址
//   - PE 头部解析 (IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, IMAGE_EXPORT_DIRECTORY)
//
// 参数 (Parameters):
//   - dll_base: std::uint8_t*, 目标 DLL 的加载基址
//               Base address of the loaded DLL.
//
// 返回值 (Returns):
//   bool — 成功/失败。Fail-safe: 失败时记录日志但不停止整个流程。
//
// 副作用 (Side effects):
//   修改目标 DLL 的 IAT 条目（写入解析后的函数地址）
//   Modifies IAT entries in the target DLL.
//
// 错误处理 (Error handling):
//   PE 解析失败、导出表为空、未找到函数 → OutputDebugStringA + return false
//
// 中文关键词:
//   反射加载, 导入表解析, IAT, 导出表, kernel32, GetProcAddress, PE 解析, 手动映射, 安全测试, 防御验证
//
// 英文关键词:
//   reflective loading, import resolution, IAT, export table, kernel32,
//   GetProcAddress, PE parsing, manual mapping, security test, defense probe

bool resolve_reflective_imports(std::uint8_t* dll_base) {
  if (!dll_base) return false;

  IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(dll_base);
  IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
      dll_base + dos->e_lfanew);

  IMAGE_DATA_DIRECTORY& import_dir =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (import_dir.VirtualAddress == 0) {
    ::OutputDebugStringA(
        "[ANXIN_REFLECTIVE_REAL_PROBE] no import directory — skipping import resolution");
    return true;  // 无导入表不是错误
  }

  IMAGE_IMPORT_DESCRIPTOR* desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
      dll_base + import_dir.VirtualAddress);

  while (desc->Name != 0) {
    const char* dll_name =
        reinterpret_cast<const char*>(dll_base + desc->Name);

    // 获取目标 DLL 基址
    // Get base address of the import DLL.
    // 注意：不使用 LoadLibrary 作为回退方案，因为反射加载的核心目的
    // 就是避免产生 LoadLibrary ETW 事件。当前仅解析 kernel32.dll
    // （始终已加载），若未来扩展需确保目标 DLL 已在线程中加载。
    // Note: No LoadLibrary fallback – the purpose of reflective loading
    // is precisely to avoid generating LoadLibrary ETW events.
    HMODULE hModule = ::GetModuleHandleA(dll_name);
    if (!hModule) {
      char msg[256]{};
      wsprintfA(msg,
                "[ANXIN_REFLECTIVE_REAL_PROBE] import DLL not found: %s",
                dll_name);
      ::OutputDebugStringA(msg);
      ++desc;
      continue;
    }

    // 解析导出表
    // Parse the export table of the import DLL
    IMAGE_DOS_HEADER* mod_dos =
        reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
    IMAGE_NT_HEADERS* mod_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<std::uint8_t*>(hModule) + mod_dos->e_lfanew);

    IMAGE_DATA_DIRECTORY& exp_dir =
        mod_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.VirtualAddress == 0) {
      ++desc;
      continue;
    }

    IMAGE_EXPORT_DIRECTORY* exports =
        reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
            reinterpret_cast<std::uint8_t*>(hModule) + exp_dir.VirtualAddress);

    std::uint32_t* names = reinterpret_cast<std::uint32_t*>(
        reinterpret_cast<std::uint8_t*>(hModule) + exports->AddressOfNames);
    std::uint16_t* ordinals = reinterpret_cast<std::uint16_t*>(
        reinterpret_cast<std::uint8_t*>(hModule) +
        exports->AddressOfNameOrdinals);
    std::uint32_t* functions = reinterpret_cast<std::uint32_t*>(
        reinterpret_cast<std::uint8_t*>(hModule) +
        exports->AddressOfFunctions);

    // 遍历 IMAGE_THUNK_DATA（ILT）和 IAT
    // Walk the Import Lookup Table (ILT) and fill IAT
    std::uint64_t* ilt = reinterpret_cast<std::uint64_t*>(
        dll_base + desc->OriginalFirstThunk);
    std::uint64_t* iat = reinterpret_cast<std::uint64_t*>(
        dll_base + desc->FirstThunk);

    // 如果 OriginalFirstThunk 为 0，使用 FirstThunk
    if (desc->OriginalFirstThunk == 0) {
      ilt = iat;
    }

    for (size_t i = 0; ilt[i] != 0; ++i) {
      std::uint64_t thunk = ilt[i];
      void* func_addr = nullptr;

      if (thunk & 0x8000000000000000ULL) {
        // 按序号导入 (import by ordinal)
        // PE 导出表的 Base 字段指示起始序号，functions 数组从 Base 开始索引。
        // Export ordinal base: functions[ordinal - Base]
        std::uint16_t ordinal = static_cast<std::uint16_t>(thunk & 0xFFFF);
        if (ordinal >= exports->Base &&
            ordinal - exports->Base < exports->NumberOfFunctions) {
          std::uint32_t func_rva =
              functions[ordinal - exports->Base];
          func_addr = reinterpret_cast<std::uint8_t*>(hModule) + func_rva;
        }
      } else {
        // 按名称导入 (import by name)
        IMAGE_IMPORT_BY_NAME* import_name =
            reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(dll_base + (thunk & 0xFFFFFFFF));
        const char* func_name = reinterpret_cast<const char*>(import_name->Name);

        for (std::uint32_t j = 0; j < exports->NumberOfNames; ++j) {
          const char* export_name =
              reinterpret_cast<const char*>(
                  reinterpret_cast<std::uint8_t*>(hModule) + names[j]);
          if (std::strcmp(export_name, func_name) == 0) {
            std::uint32_t func_rva = functions[ordinals[j]];
            func_addr =
                reinterpret_cast<std::uint8_t*>(hModule) + func_rva;
            break;
          }
        }
      }

      if (func_addr) {
        iat[i] = reinterpret_cast<std::uint64_t>(func_addr);
        char msg[256]{};
        wsprintfA(msg,
                  "[ANXIN_REFLECTIVE_REAL_PROBE] resolved import IAT[%zu] → %p",
                  i, func_addr);
        ::OutputDebugStringA(msg);
      } else {
        char msg[256]{};
        wsprintfA(msg,
                  "[ANXIN_REFLECTIVE_REAL_PROBE] FAILED to resolve import IAT[%zu]",
                  i);
        ::OutputDebugStringA(msg);
      }
    }

    ++desc;
  }

  ::OutputDebugStringA(
      "[ANXIN_REFLECTIVE_REAL_PROBE] import resolution complete");
  return true;
}

// ──────────────────────────────────────────────────────────────────────
//  真实反射加载：基址重定位
// ──────────────────────────────────────────────────────────────────────
//
// 函数名称: apply_reflective_relocations
//
// 函数作用:
//   遍历反射加载 DLL 的 Base Relocation 目录，根据实际加载基址与 ImageBase
//   的差值 delta 修正所有重定位地址。
//
// Purpose:
//   Walks the Base Relocation directory and applies delta (actual base -
//   ImageBase) to all relocated addresses.
//
// 调用方 (Called by): reflectively_load_and_run
// 被调用方 (Calls): PE 头部解析
//
// 参数 (Parameters):
//   - dll_base: std::uint8_t*, 目标 DLL 加载基址
//   - delta:    std::uint64_t, 实际基址 − ImageBase
//
// 返回值 (Returns): bool
//
// 副作用 (Side effects): 修改目标 DLL 内存中的被重定位地址

bool apply_reflective_relocations(std::uint8_t* dll_base,
                                   std::uint64_t delta) {
  if (!dll_base || delta == 0) return true;  // delta=0 无需重定位

  IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(dll_base);
  IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
      dll_base + dos->e_lfanew);

  IMAGE_DATA_DIRECTORY& reloc_dir =
      nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
  if (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0) {
    return true;  // 无重定位表
  }

  IMAGE_BASE_RELOCATION* block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
      dll_base + reloc_dir.VirtualAddress);

  while (block->VirtualAddress != 0 && block->SizeOfBlock > 0) {
    size_t entry_count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION))
                         / sizeof(std::uint16_t);
    std::uint16_t* entries = reinterpret_cast<std::uint16_t*>(
        reinterpret_cast<std::uint8_t*>(block) +
        sizeof(IMAGE_BASE_RELOCATION));

    for (size_t i = 0; i < entry_count; ++i) {
      std::uint16_t entry = entries[i];
      int type = (entry >> 12) & 0xF;
      std::uint16_t offset = entry & 0xFFF;

      if (type == IMAGE_REL_BASED_DIR64) {
        std::uint64_t* addr = reinterpret_cast<std::uint64_t*>(
            dll_base + block->VirtualAddress + offset);
        *addr += delta;
      } else if (type == IMAGE_REL_BASED_HIGHLOW) {
        std::uint32_t* addr = reinterpret_cast<std::uint32_t*>(
            dll_base + block->VirtualAddress + offset);
        *addr += static_cast<std::uint32_t>(delta);
      }
      // IMAGE_REL_BASED_ABSOLUTE (type 0) — skip
    }

    block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
        reinterpret_cast<std::uint8_t*>(block) + block->SizeOfBlock);
  }

  ::OutputDebugStringA(
      "[ANXIN_REFLECTIVE_REAL_PROBE] base relocations applied");
  return true;
}

// ──────────────────────────────────────────────────────────────────────
//  真实反射加载：主流程
// ──────────────────────────────────────────────────────────────────────
//
// 函数名称: reflectively_load_and_run
//
// 函数作用:
//   执行完整的反射式 DLL 加载流程：构建最小 DLL → 分配内存 → 映射节区
//   → 重定位 → 导入解析 → 保护变更 → 调用 DllMain → 等待 → 卸载。
//
// Purpose:
//   Performs the complete reflective DLL loading flow: build minimal DLL
//   → allocate memory → map sections → relocate → resolve imports
//   → set protections → call DllMain → wait → unload.
//
// 调用方 (Called by): reflective_load_real_worker
// 被调用方 (Calls):
//   - build_minimal_reflective_stub_dll
//   - VirtualAlloc, memcpy, VirtualProtect
//   - apply_reflective_relocations
//   - resolve_reflective_imports
//   - OutputDebugStringA, Sleep, VirtualFree
//
// 参数 (Parameters):
//   - hold_ms: DWORD, DLL 加载后保持的毫秒数
//
// 返回值 (Returns): void
//
// 副作用 (Side effects):
//   - 分配/释放私有可执行内存
//   - 调用嵌入 DLL 的 DllMain（产生 PROCESS_ATTACH/DETACH 通知）
//   - 不产生 LoadLibrary ETW 事件
//
// 错误处理 (Error handling):
//   各阶段失败时 OutputDebugStringA + 清理已分配资源 + 返回
//
// 中文关键词:
//   反射加载, 手动映射, DllMain, 重定位, 导入解析, IAT, PE解析, 内存分配,
//   安全测试, 防御验证

void reflectively_load_and_run(DWORD hold_ms) {
  ::OutputDebugStringA(
      "[ANXIN_REFLECTIVE_REAL_PROBE] building minimal stub DLL...");

  std::vector<std::uint8_t> raw_dll = build_minimal_reflective_stub_dll();

  IMAGE_DOS_HEADER* raw_dos =
      reinterpret_cast<IMAGE_DOS_HEADER*>(raw_dll.data());
  IMAGE_NT_HEADERS* raw_nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
      raw_dll.data() + raw_dos->e_lfanew);

  std::uint32_t image_size = raw_nt->OptionalHeader.SizeOfImage;
  std::uint32_t header_size = raw_nt->OptionalHeader.SizeOfHeaders;

  char msg[256]{};

  // ── 1. 分配内存 ──
  // Allocate memory for the DLL image
  wsprintfA(msg,
            "[ANXIN_REFLECTIVE_REAL_PROBE] allocating %lu bytes "
            "(MEM_PRIVATE | MEM_RESERVE | MEM_COMMIT)",
            image_size);
  ::OutputDebugStringA(msg);

  std::uint8_t* image_base = static_cast<std::uint8_t*>(::VirtualAlloc(
      nullptr, image_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
  if (!image_base) {
    wsprintfA(msg,
              "[ANXIN_REFLECTIVE_REAL_PROBE] VirtualAlloc failed, error=%lu",
              ::GetLastError());
    ::OutputDebugStringA(msg);
    return;
  }

  wsprintfA(msg,
            "[ANXIN_REFLECTIVE_REAL_PROBE] image base = %p", image_base);
  ::OutputDebugStringA(msg);

  // ── 2. 复制 PE 头部 ──
  // Copy PE headers
  std::memcpy(image_base, raw_dll.data(), header_size);

  // ── 3. 映射各节区 ──
  // Map sections
  IMAGE_SECTION_HEADER* section =
      IMAGE_FIRST_SECTION(reinterpret_cast<IMAGE_NT_HEADERS*>(
          image_base + raw_dos->e_lfanew));

  for (WORD i = 0; i < raw_nt->FileHeader.NumberOfSections; ++i) {
    if (section[i].SizeOfRawData > 0) {
      std::memcpy(image_base + section[i].VirtualAddress,
                  raw_dll.data() + section[i].PointerToRawData,
                  section[i].SizeOfRawData);
      wsprintfA(msg,
                "[ANXIN_REFLECTIVE_REAL_PROBE] mapped section %d: %s "
                "(VA=0x%08lX, size=%lu)",
                i,
                reinterpret_cast<const char*>(section[i].Name),
                section[i].VirtualAddress,
                section[i].SizeOfRawData);
      ::OutputDebugStringA(msg);
    }
  }

  // ── 4. 基址重定位 ──
  // Apply base relocations
  std::uint64_t delta = reinterpret_cast<std::uint64_t>(image_base) -
                        raw_nt->OptionalHeader.ImageBase;
  wsprintfA(msg,
            "[ANXIN_REFLECTIVE_REAL_PROBE] relocation delta = 0x%016llX",
            delta);
  ::OutputDebugStringA(msg);

  if (!apply_reflective_relocations(image_base, delta)) {
    ::OutputDebugStringA(
        "[ANXIN_REFLECTIVE_REAL_PROBE] WARNING: relocation failed");
  }

  // ── 5. 导入表解析 ──
  // Resolve imports
  if (!resolve_reflective_imports(image_base)) {
    ::OutputDebugStringA(
        "[ANXIN_REFLECTIVE_REAL_PROBE] WARNING: import resolution incomplete");
  }

  // ── 6. 设置节区保护属性 ──
  // Set section protections
  for (WORD i = 0; i < raw_nt->FileHeader.NumberOfSections; ++i) {
    DWORD prot = PAGE_READWRITE;
    std::uint32_t chars = section[i].Characteristics;

    if (chars & IMAGE_SCN_MEM_EXECUTE) {
      prot = (chars & IMAGE_SCN_MEM_WRITE)
                 ? PAGE_EXECUTE_READWRITE
                 : PAGE_EXECUTE_READ;
    } else if (chars & IMAGE_SCN_MEM_WRITE) {
      prot = PAGE_READWRITE;
    } else {
      prot = PAGE_READONLY;
    }

    DWORD old = 0;
    if (!::VirtualProtect(image_base + section[i].VirtualAddress,
                          section[i].Misc.VirtualSize, prot, &old)) {
      wsprintfA(msg,
                "[ANXIN_REFLECTIVE_REAL_PROBE] VirtualProtect "
                "section %d failed, error=%lu",
                i, ::GetLastError());
      ::OutputDebugStringA(msg);
    }
  }

  // ── 7. 调用 DllMain(DLL_PROCESS_ATTACH) ──
  // Call DllMain with DLL_PROCESS_ATTACH
  using DllMainFn = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
  DllMainFn entry = reinterpret_cast<DllMainFn>(
      image_base + raw_nt->OptionalHeader.AddressOfEntryPoint);

  ::OutputDebugStringA(
      "[ANXIN_REFLECTIVE_REAL_PROBE] calling DllMain(DLL_PROCESS_ATTACH)...");

  BOOL attach_result = entry(
      reinterpret_cast<HINSTANCE>(image_base),
      DLL_PROCESS_ATTACH,
      nullptr);

  wsprintfA(msg,
            "[ANXIN_REFLECTIVE_REAL_PROBE] DllMain(PROCESS_ATTACH) "
            "returned %s",
            attach_result ? "TRUE" : "FALSE");
  ::OutputDebugStringA(msg);

  // ── 8. 保持检测窗口 ──
  // Hold for detection window
  wsprintfA(msg,
            "[ANXIN_REFLECTIVE_REAL_PROBE] reflectively loaded DLL "
            "active at %p, holding %lu ms for detection",
            image_base, hold_ms);
  ::OutputDebugStringA(msg);

  ::Sleep(hold_ms);

  // ── 9. 调用 DllMain(DLL_PROCESS_DETACH) 并释放 ──
  // Call DllMain(DLL_PROCESS_DETACH) and free
  ::OutputDebugStringA(
      "[ANXIN_REFLECTIVE_REAL_PROBE] calling DllMain(DLL_PROCESS_DETACH)...");
  entry(reinterpret_cast<HINSTANCE>(image_base),
        DLL_PROCESS_DETACH, nullptr);

  ::VirtualFree(image_base, 0, MEM_RELEASE);
  ::OutputDebugStringA(
      "[ANXIN_REFLECTIVE_REAL_PROBE] reflective DLL unloaded and freed");
}

// ── 主工作线程 ────────────────────────────────────────────────────────

DWORD WINAPI reflective_load_real_worker(LPVOID) {
  anxin_test::ProbeMode mode =
      anxin_test::read_probe_mode_from_env(kModeEnvVar);
  DWORD hold_ms =
      anxin_test::read_hold_time_ms(kHoldEnvVar, kDefaultHoldMs);

  char msg[256]{};
  wsprintfA(msg,
            "[ANXIN_REFLECTIVE_REAL_PROBE] probe mode = %d, hold = %lu ms",
            static_cast<int>(mode), hold_ms);
  ::OutputDebugStringA(msg);

  // ── 模拟模式 ──
  if (anxin_test::should_run_simulate(mode)) {
    ::OutputDebugStringA(
        "[ANXIN_REFLECTIVE_REAL_PROBE] running simulate mode");
    allocate_simulated_region();
  }

  // ── 真实模式 ──
  if (anxin_test::should_run_real(mode)) {
    ::OutputDebugStringA(
        "[ANXIN_REFLECTIVE_REAL_PROBE] running real reflective load mode");
    reflectively_load_and_run(hold_ms);
  } else if (!anxin_test::should_run_simulate(mode)) {
    // 兜底
    ::OutputDebugStringA(
        "[ANXIN_REFLECTIVE_REAL_PROBE] no mode selected, holding default time");
    ::Sleep(hold_ms);
  } else {
    // 仅模拟模式
    wsprintfA(msg,
              "[ANXIN_REFLECTIVE_REAL_PROBE] simulate-only mode, "
              "holding %lu ms for observation",
              hold_ms);
    ::OutputDebugStringA(msg);
    ::Sleep(hold_ms);
  }

  ::OutputDebugStringA(
      "[ANXIN_REFLECTIVE_REAL_PROBE] probe thread exiting");

  free_simulated_region();
  return 0;
}

}  // namespace

// ── DllMain ────────────────────────────────────────────────────────────
//
// 入口点 (Entry point): 在 DLL_PROCESS_ATTACH 时创建工作线程并分离。
// Creates a detached worker thread on DLL_PROCESS_ATTACH.

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    ::DisableThreadLibraryCalls(hinstDLL);
    HANDLE thread = ::CreateThread(nullptr, 0,
                                   reflective_load_real_worker,
                                   nullptr, 0, nullptr);
    if (thread) {
      ::CloseHandle(thread);
    }
  }
  return TRUE;
}
