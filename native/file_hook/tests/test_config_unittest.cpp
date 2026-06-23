// test_config_unittest.cpp — Unit Tests for test_config.h
//
// 测试 test_config.h 中的 ProbeMode 枚举和环境变量读取函数。
// 本测试不依赖任何外部测试框架，仅使用 OutputDebugStringA 输出结果
// 和简单断言进行自检。
//
// Unit tests for ProbeMode enum and environment variable reading in test_config.h.
// No external test framework dependency; uses OutputDebugStringA for output
// and simple assertions for self-validation.
//
// 构建方式 (Build):
//   本文件可编译为独立控制台测试程序。
//   This file can be compiled as a standalone console test program.

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX

#include <windows.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cwchar>

#include "../src/test_config.h"

namespace {

int g_failures = 0;
int g_total = 0;

void log_test(const char* name) {
  char msg[256]{};
  wsprintfA(msg, "[TEST] %s", name);
  ::OutputDebugStringA(msg);
  ++g_total;
}

void log_pass(const char* name) {
  char msg[256]{};
  wsprintfA(msg, "[TEST] PASS: %s", name);
  ::OutputDebugStringA(msg);
  ::OutputDebugStringA("  PASS");
}

void log_fail(const char* name, const char* reason) {
  char msg[512]{};
  wsprintfA(msg, "[TEST] FAIL: %s — %s", name, reason);
  ::OutputDebugStringA(msg);
  ++g_failures;
}

// ── ProbeMode 测试 ────────────────────────────────────────────────────

void test_probe_mode_default() {
  const wchar_t* test_name = L"ProbeMode default returns Simulate";
  log_test("ProbeMode default returns Simulate");

  // 删除环境变量以确保默认行为
  // Clear env var to ensure default behavior
  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_DEFAULT", nullptr);

  anxin_test::ProbeMode mode =
      anxin_test::read_probe_mode_from_env(L"ANXIN_TEST_MODE_DEFAULT");

  if (mode == anxin_test::ProbeMode::Simulate) {
    log_pass("ProbeMode default returns Simulate");
  } else {
    log_fail("ProbeMode default returns Simulate",
             "expected Simulate but got different value");
  }
}

void test_probe_mode_real() {
  log_test("ProbeMode recognizes 'real'");

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_REAL", L"real");

  anxin_test::ProbeMode mode =
      anxin_test::read_probe_mode_from_env(L"ANXIN_TEST_MODE_REAL");

  if (mode == anxin_test::ProbeMode::Real) {
    log_pass("ProbeMode recognizes 'real'");
  } else {
    log_fail("ProbeMode recognizes 'real'",
             "expected Real but got different value");
  }

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_REAL", nullptr);
}

void test_probe_mode_both() {
  log_test("ProbeMode recognizes 'both'");

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_BOTH", L"both");

  anxin_test::ProbeMode mode =
      anxin_test::read_probe_mode_from_env(L"ANXIN_TEST_MODE_BOTH");

  if (mode == anxin_test::ProbeMode::Both) {
    log_pass("ProbeMode recognizes 'both'");
  } else {
    log_fail("ProbeMode recognizes 'both'",
             "expected Both but got different value");
  }

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_BOTH", nullptr);
}

void test_probe_mode_simulate_explicit() {
  log_test("ProbeMode recognizes 'simulate'");

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_SIM", L"simulate");

  anxin_test::ProbeMode mode =
      anxin_test::read_probe_mode_from_env(L"ANXIN_TEST_MODE_SIM");

  if (mode == anxin_test::ProbeMode::Simulate) {
    log_pass("ProbeMode recognizes 'simulate'");
  } else {
    log_fail("ProbeMode recognizes 'simulate'",
             "expected Simulate but got different value");
  }

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_SIM", nullptr);
}

void test_probe_mode_case_insensitive() {
  log_test("ProbeMode is case insensitive");

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_CASE", L"REAL");

  anxin_test::ProbeMode mode =
      anxin_test::read_probe_mode_from_env(L"ANXIN_TEST_MODE_CASE");

  if (mode == anxin_test::ProbeMode::Real) {
    log_pass("ProbeMode is case insensitive");
  } else {
    log_fail("ProbeMode is case insensitive",
             "expected Real for 'REAL' but got different value");
  }

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_CASE", nullptr);
}

void test_probe_mode_invalid_fallback() {
  log_test("ProbeMode invalid value falls back to Simulate");

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_INVALID", L"garbage");

  anxin_test::ProbeMode mode =
      anxin_test::read_probe_mode_from_env(L"ANXIN_TEST_MODE_INVALID");

  if (mode == anxin_test::ProbeMode::Simulate) {
    log_pass("ProbeMode invalid value falls back to Simulate");
  } else {
    log_fail("ProbeMode invalid value falls back to Simulate",
             "expected Simulate fallback but got different value");
  }

  ::SetEnvironmentVariableW(L"ANXIN_TEST_MODE_INVALID", nullptr);
}

void test_probe_mode_null_name() {
  log_test("ProbeMode null env name returns Simulate");

  anxin_test::ProbeMode mode = anxin_test::read_probe_mode_from_env(nullptr);

  if (mode == anxin_test::ProbeMode::Simulate) {
    log_pass("ProbeMode null env name returns Simulate");
  } else {
    log_fail("ProbeMode null env name returns Simulate",
             "expected Simulate for null");
  }
}

// ── Hold Time 测试 ────────────────────────────────────────────────────

void test_hold_time_default() {
  log_test("Hold time returns default when env var is absent");

  ::SetEnvironmentVariableW(L"ANXIN_TEST_HOLD_DEFAULT", nullptr);

  DWORD ms = anxin_test::read_hold_time_ms(L"ANXIN_TEST_HOLD_DEFAULT", 9999);

  if (ms == 9999) {
    log_pass("Hold time returns default when env var is absent");
  } else {
    log_fail("Hold time returns default when env var is absent",
             "expected 9999 but got different value");
  }
}

void test_hold_time_explicit() {
  log_test("Hold time reads explicit value");

  ::SetEnvironmentVariableW(L"ANXIN_TEST_HOLD_EXPLICIT", L"30000");

  DWORD ms =
      anxin_test::read_hold_time_ms(L"ANXIN_TEST_HOLD_EXPLICIT", 600000);

  if (ms == 30000) {
    log_pass("Hold time reads explicit value");
  } else {
    log_fail("Hold time reads explicit value",
             "expected 30000 but got different value");
  }

  ::SetEnvironmentVariableW(L"ANXIN_TEST_HOLD_EXPLICIT", nullptr);
}

void test_hold_time_zero_fallback() {
  log_test("Hold time zero falls back to default");

  ::SetEnvironmentVariableW(L"ANXIN_TEST_HOLD_ZERO", L"0");

  DWORD ms = anxin_test::read_hold_time_ms(L"ANXIN_TEST_HOLD_ZERO", 55555);

  if (ms == 55555) {
    log_pass("Hold time zero falls back to default");
  } else {
    log_fail("Hold time zero falls back to default",
             "expected 55555 but got different value");
  }

  ::SetEnvironmentVariableW(L"ANXIN_TEST_HOLD_ZERO", nullptr);
}

void test_hold_time_negative_fallback() {
  log_test("Hold time negative falls back to default");

  ::SetEnvironmentVariableW(L"ANXIN_TEST_HOLD_NEG", L"-100");

  DWORD ms = anxin_test::read_hold_time_ms(L"ANXIN_TEST_HOLD_NEG", 77777);

  if (ms == 77777) {
    log_pass("Hold time negative falls back to default");
  } else {
    log_fail("Hold time negative falls back to default",
             "expected 77777 but got different value");
  }

  ::SetEnvironmentVariableW(L"ANXIN_TEST_HOLD_NEG", nullptr);
}

void test_hold_time_exceeds_max() {
  log_test("Hold time exceeds max (3600000) falls back to default");

  // 超过 3600000（1小时）应回退
  ::SetEnvironmentVariableW(L"ANXIN_TEST_HOLD_MAX", L"9999999");

  DWORD ms = anxin_test::read_hold_time_ms(L"ANXIN_TEST_HOLD_MAX", 88888);

  if (ms == 88888) {
    log_pass("Hold time exceeds max falls back to default");
  } else {
    log_fail("Hold time exceeds max falls back to default",
             "expected 88888 but got different value");
  }

  ::SetEnvironmentVariableW(L"ANXIN_TEST_HOLD_MAX", nullptr);
}

void test_hold_time_null_name() {
  log_test("Hold time null env name returns default");

  DWORD ms = anxin_test::read_hold_time_ms(nullptr, 66666);

  if (ms == 66666) {
    log_pass("Hold time null env name returns default");
  } else {
    log_fail("Hold time null env name returns default",
             "expected 66666 but got different value");
  }
}

// ── Mode Helper 测试 ──────────────────────────────────────────────────

void test_should_run_simulate() {
  log_test("should_run_simulate helpers");

  bool ok = true;
  ok = ok && anxin_test::should_run_simulate(anxin_test::ProbeMode::Simulate);
  ok = ok && !anxin_test::should_run_simulate(anxin_test::ProbeMode::Real);
  ok = ok && anxin_test::should_run_simulate(anxin_test::ProbeMode::Both);

  if (ok) {
    log_pass("should_run_simulate helpers");
  } else {
    log_fail("should_run_simulate helpers", "unexpected helper result");
  }
}

void test_should_run_real() {
  log_test("should_run_real helpers");

  bool ok = true;
  ok = ok && !anxin_test::should_run_real(anxin_test::ProbeMode::Simulate);
  ok = ok && anxin_test::should_run_real(anxin_test::ProbeMode::Real);
  ok = ok && anxin_test::should_run_real(anxin_test::ProbeMode::Both);

  if (ok) {
    log_pass("should_run_real helpers");
  } else {
    log_fail("should_run_real helpers", "unexpected helper result");
  }
}

}  // namespace

// ── wmain 入口 ────────────────────────────────────────────────────────
//
// 运行所有测试并输出摘要。
// Runs all tests and outputs summary.

int wmain() {
  ::OutputDebugStringA("=== test_config_unittest START ===");

  test_probe_mode_default();
  test_probe_mode_real();
  test_probe_mode_both();
  test_probe_mode_simulate_explicit();
  test_probe_mode_case_insensitive();
  test_probe_mode_invalid_fallback();
  test_probe_mode_null_name();

  test_hold_time_default();
  test_hold_time_explicit();
  test_hold_time_zero_fallback();
  test_hold_time_negative_fallback();
  test_hold_time_exceeds_max();
  test_hold_time_null_name();

  test_should_run_simulate();
  test_should_run_real();

  char summary[256]{};
  wsprintfA(summary,
            "=== test_config_unittest DONE: %d total, %d failures ===",
            g_total, g_failures);
  ::OutputDebugStringA(summary);

  // 同时输出到 stdout，方便命令行运行时查看
  // Also output to stdout for command-line visibility
  wprintf(L"\n=== test_config_unittest DONE ===\n");
  wprintf(L"Total: %d, Failures: %d\n", g_total, g_failures);

  return (g_failures == 0) ? 0 : 1;
}
