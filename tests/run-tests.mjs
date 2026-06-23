import { pathToFileURL } from 'node:url';
import path from 'node:path';

/**
 * 函数名称：runFrontendTests
 * 函数作用：顺序加载前端 Node 测试文件，避免 node --test 在受限 Windows 环境中派生子进程触发 spawn EPERM。
 * Purpose: Sequentially loads frontend Node test files, avoiding node --test worker process spawning that can trigger spawn EPERM in restricted Windows environments.
 * 调用方：package.json 的 npm test 脚本。
 * Called by: npm test script in package.json.
 * 被调用方：import，pathToFileURL。
 * Calls: import, pathToFileURL.
 * 参数说明：无；测试文件列表在本文件中集中维护。
 * Parameters: none; the test file list is maintained in this file.
 * 返回值说明：测试失败时由 node:test 设置进程退出码；加载失败时抛出错误。
 * Returns: node:test sets the process exit code on test failures; loading failures are thrown.
 * 错误处理：动态 import 失败会让进程非零退出，不吞掉错误。
 * Error handling: dynamic import failures make the process exit non-zero; errors are not swallowed.
 * 中文关键词：前端测试，顺序运行，spawn EPERM，Node 测试
 * English keywords: frontend tests, sequential run, spawn EPERM, Node tests
 */
async function runFrontendTests() {
  const testFiles = [
    'frontend_stores_i18n.test.mjs',
    'frontend_stores_quarantine.test.mjs',
    'frontend_stores_scanner.test.mjs',
    'frontend_stores_theme.test.mjs',
    'frontend_stores_toast.test.mjs',
    'monitoring_runtime_control.test.mjs',
    'pure_logic_functions.test.mjs',
    'recent_fixes.test.mjs',
    'scan_page_threat_actions.test.mjs',
    'startup_phase_screen.test.mjs',
    'startup_snapshot_phase_split.test.mjs',
  ];

  for (const fileName of testFiles) {
    const fileUrl = pathToFileURL(path.join(import.meta.dirname, fileName));
    await import(fileUrl.href);
  }
}

await runFrontendTests();
