// test_config.h — Shared Test Probe Configuration
//
// 为 PEB 断链和反射加载等安全测试探测 DLL 提供统一的模式枚举和环境变量读取。
// 沿用项目已有的 ANXIN_XXX 环境变量命名约定，支持 simulate / real / both 三种模式。
//
// Provides a unified ProbeMode enum and environment variable reading helpers
// for security test probe DLLs (PEB unlinking, reflective loading, etc.).
// Follows the existing ANXIN_XXX environment variable naming convention.
//
// 调用方 (Called by):
//   - peb_unlink_real_dll.cpp 工作线程
//   - reflective_load_real_dll.cpp 工作线程
//
// 被调用方 (Calls):
//   - ::GetEnvironmentVariableW (kernel32)
//   - ::_wcsicmp (CRT)
//   - std::wcstoul (CRT)
//
// 接入方式 (Integration):
//   头文件直接 #include，所有函数为 inline；无需链接额外 lib。
//   Should be included by probe DLL source files; all functions are inline,
//   no additional library linking required.

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>

#include <cstdint>
#include <cstdlib>
#include <cwchar>
#include <iterator>

namespace anxin_test {

// ── ProbeMode 枚举 ────────────────────────────────────────────────────
//
// 安全测试探测的运行模式。
// Probe operation mode for security test probes.
//
// Simulate: 仅构造内存假文物，不实际操纵系统（最安全，默认行为）
//           Only construct simulated memory artifacts, no real system manipulation.
// Real:     执行真实攻击技术（PEB 断链 / 反射加载）
//           Perform the actual attack technique.
// Both:     同时执行模拟和真实两种模式
//           Execute both simulate and real modes.

enum class ProbeMode : std::uint8_t {
  Simulate = 0,  // 仅模拟 (Default safe mode)
  Real     = 1,  // 真实技术 (Real technique)
  Both     = 2   // 两者均执行 (Both simulate and real)
};

// ── 环境变量读取 ──────────────────────────────────────────────────────

/// 从环境变量读取探测模式。
/// Read probe mode from an environment variable.
///
/// 参数 (Parameters):
///   - env_var_name: const wchar_t*, 环境变量名称，不能为空
///                   Environment variable name, must not be null.
///
/// 返回值 (Returns):
///   ProbeMode — 解析结果；未设置或无法识别时返回 ProbeMode::Simulate（安全默认）
///   Parsed mode; returns ProbeMode::Simulate if env var is absent or invalid.
///
/// 识别值 (Recognized values, case-insensitive):
///   L"simulate" → ProbeMode::Simulate
///   L"real"     → ProbeMode::Real
///   L"both"     → ProbeMode::Both
///
/// 副作用 (Side effects): 无。仅读取进程环境块，不修改任何状态。
/// Thread safety: 线程安全（只读环境变量）。
inline ProbeMode read_probe_mode_from_env(const wchar_t* env_var_name) {
  if (!env_var_name) return ProbeMode::Simulate;

  wchar_t value[32]{};
  DWORD n = ::GetEnvironmentVariableW(
      env_var_name, value, static_cast<DWORD>(std::size(value)));

  if (n == 0 || n >= static_cast<DWORD>(std::size(value))) {
    return ProbeMode::Simulate;  // 未设置或缓冲区不足 → 安全默认
  }

  if (_wcsicmp(value, L"real") == 0) return ProbeMode::Real;
  if (_wcsicmp(value, L"both") == 0) return ProbeMode::Both;
  // "simulate" 或任何无法识别的值 → 安全默认
  return ProbeMode::Simulate;
}

/// 从环境变量读取探测保持时间（毫秒）。
/// Read probe hold time (milliseconds) from an environment variable.
///
/// 参数 (Parameters):
///   - env_var_name: const wchar_t*, 环境变量名称
///                   Environment variable name.
///   - default_ms:   DWORD, 环境变量未设置或无效时使用的默认值
///                   Default value when env var is absent or invalid.
///
/// 返回值 (Returns):
///   DWORD — 保持时间毫秒数；最小 1ms，失败回退到 default_ms
///   Hold time in milliseconds; minimum 1ms, falls back to default_ms on failure.
///
/// 副作用 (Side effects): 无。
/// Thread safety: 线程安全。
inline DWORD read_hold_time_ms(const wchar_t* env_var_name, DWORD default_ms) {
  if (!env_var_name) return default_ms;

  wchar_t value[32]{};
  DWORD n = ::GetEnvironmentVariableW(
      env_var_name, value, static_cast<DWORD>(std::size(value)));

  if (n > 0 && n < static_cast<DWORD>(std::size(value))) {
    wchar_t* end = nullptr;
    unsigned long ms = std::wcstoul(value, &end, 10);
    if (end != value && ms > 0 && ms <= 3600000) {  // 上限 1 小时
      return static_cast<DWORD>(ms);
    }
  }
  return default_ms;
}

/// 判断当前模式是否应执行模拟路径。
/// Check whether the simulate path should be executed for the given mode.
inline bool should_run_simulate(ProbeMode mode) {
  return mode == ProbeMode::Simulate || mode == ProbeMode::Both;
}

/// 判断当前模式是否应执行真实技术路径。
/// Check whether the real technique path should be executed for the given mode.
inline bool should_run_real(ProbeMode mode) {
  return mode == ProbeMode::Real || mode == ProbeMode::Both;
}

// ── 诊断标记 ──────────────────────────────────────────────────────────
//
// 在所有内存工件和 OutputDebugString 中统一使用的前缀标记，
// 方便安全工具和调试器识别为防御测试产物。
//
// Unified marker prefix used in all memory artifacts and OutputDebugString
// messages, allowing security tools and debuggers to recognize them as
// defensive test artifacts.

constexpr const char* kDefensiveTestMarker =
    "DEFENSIVE_TEST_ARTIFACT_NOT_MALICIOUS";

}  // namespace anxin_test
