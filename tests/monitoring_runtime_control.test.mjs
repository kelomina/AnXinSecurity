import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')
const behaviorApiSource = readFileSync(resolve(projectRoot, 'src/api/behavior.ts'), 'utf8')
const logsApiSource = readFileSync(resolve(projectRoot, 'src/api/logs.ts'), 'utf8')
const processApiSource = readFileSync(resolve(projectRoot, 'src/api/process.ts'), 'utf8')
const configStoreSource = readFileSync(resolve(projectRoot, 'src/stores/configStore.ts'), 'utf8')
const settingsPageSource = readFileSync(resolve(projectRoot, 'src/components/SettingsPage.tsx'), 'utf8')
const overviewPageSource = readFileSync(resolve(projectRoot, 'src/components/OverviewPage.tsx'), 'utf8')
const behaviorPageSource = readFileSync(resolve(projectRoot, 'src/components/BehaviorPage.tsx'), 'utf8')
const etwServiceSource = readFileSync(resolve(projectRoot, 'src-tauri/src/services/etw_service.rs'), 'utf8')
const logsCommandSource = readFileSync(resolve(projectRoot, 'src-tauri/src/commands/logs.rs'), 'utf8')
const configCommandSource = readFileSync(resolve(projectRoot, 'src-tauri/src/commands/config.rs'), 'utf8')

test('process API exposes typed process watcher control commands', () => {
  assert.match(processApiSource, /export interface ProcessWatcherStartOptions/)
  assert.match(processApiSource, /injectorX64: string/)
  assert.match(processApiSource, /dllX86: string/)
  assert.match(processApiSource, /intervalMs: number/)
  assert.match(processApiSource, /export async function startProcessWatcher\(options: ProcessWatcherStartOptions\): Promise<boolean>/)
  assert.match(processApiSource, /await invoke\('start_process_watcher', \{[\s\S]*injectorX64: options\.injectorX64[\s\S]*intervalMs: options\.intervalMs[\s\S]*\}\)/)
  assert.match(processApiSource, /export async function stopProcessWatcher\(\): Promise<boolean> \{[\s\S]*await invoke\('stop_process_watcher'\)/)
  assert.match(processApiSource, /export async function getProcessWatcherStatus\(\): Promise<boolean> \{[\s\S]*await invoke\('get_process_watcher_status'\)/)
  assert.match(processApiSource, /export async function pollNewPids\(\): Promise<number\[]> \{[\s\S]*await invoke\('poll_new_pids'\)/)
})

test('behavior API exposes monitoring runtime status and dedicated file hook listener', () => {
  assert.match(behaviorApiSource, /export interface EtwRuntimeStatus/)
  assert.match(behaviorApiSource, /etwCollecting: boolean/)
  assert.match(behaviorApiSource, /processWatcherRunning: boolean/)
  assert.match(behaviorApiSource, /export async function getEtwStatus\(\): Promise<EtwRuntimeStatus> \{[\s\S]*await invoke\('get_etw_status'\)/)
  assert.match(behaviorApiSource, /export interface EtwDiagnosticsSnapshot/)
  assert.match(behaviorApiSource, /export async function getEtwDiagnosticsSnapshot\(\): Promise<EtwDiagnosticsSnapshot> \{[\s\S]*await invoke\('get_etw_diagnostics_snapshot'\)/)
  assert.match(behaviorApiSource, /export async function clearEtwDiagnostics\(\): Promise<boolean> \{[\s\S]*await invoke\('clear_etw_diagnostics'\)/)
  assert.match(behaviorApiSource, /export async function exportEtwDiagnostics\(\): Promise<string> \{[\s\S]*await invoke\('export_etw_diagnostics'\)/)
  assert.match(behaviorApiSource, /export interface FileHookEvent extends EtwEvent/)
  assert.match(behaviorApiSource, /export async function getHookStatus\(\): Promise<boolean> \{[\s\S]*await invoke\('get_hook_status'\)/)
  assert.match(behaviorApiSource, /export async function startHookService\(pipeName\?: string\): Promise<boolean> \{[\s\S]*await invoke\('start_hook_service', \{ pipeName \}\)/)
  assert.match(behaviorApiSource, /export async function stopHookService\(\): Promise<boolean> \{[\s\S]*await invoke\('stop_hook_service'\)/)
  assert.match(behaviorApiSource, /Promise\.all\(\[[\s\S]*getEtwStatus\(\)[\s\S]*getProcessWatcherStatus\(\)[\s\S]*getHookStatus\(\)/)
  assert.match(behaviorApiSource, /listen<FileHookEvent>\('file-hook-event'/)
})

test('configStore monitoring toggles use backend config commands and roll back on failure', () => {
  assert.match(configStoreSource, /setBehaviorMonitoring: \(enabled: boolean\) => Promise<void>/)
  assert.match(configStoreSource, /setProcessMonitoring: \(enabled: boolean\) => Promise<void>/)
  assert.match(configStoreSource, /setFileMonitoring: \(enabled: boolean\) => Promise<void>/)
  assert.match(configStoreSource, /await setBehaviorMonitoringEnabled\(enabled\)[\s\S]*await get\(\)\.refreshMonitoringRuntimeStatus\(\)/)
  assert.match(configStoreSource, /await setProcessMonitoringEnabled\(enabled\)[\s\S]*await get\(\)\.refreshMonitoringRuntimeStatus\(\)/)
  assert.match(configStoreSource, /await setFileMonitoringEnabled\(enabled\)[\s\S]*await get\(\)\.refreshMonitoringRuntimeStatus\(\)/)
  assert.doesNotMatch(configStoreSource, /await resumeEtw\(\)|await pauseEtw\(\)/)
  assert.doesNotMatch(configStoreSource, /await startProcessWatcher\(|await stopProcessWatcher\(\)/)
  assert.doesNotMatch(configStoreSource, /await startHookService\(|await stopHookService\(\)/)
  assert.match(configStoreSource, /set\(\{ config: previousConfig, monitoringControlError: message \}\)/)
  assert.match(configCommandSource, /try_state::<ProcessScannerService>\(\)/)
  assert.match(configCommandSource, /process_scanner\.start\(/)
  assert.match(configCommandSource, /process_scanner\.stop\(\)/)
})

test('SettingsPage waits for monitoring runtime controls and displays runtime errors', () => {
  assert.match(settingsPageSource, /monitoringRuntimeStatus[\s\S]*monitoringControlPending[\s\S]*monitoringControlError/)
  assert.match(settingsPageSource, /refreshMonitoringRuntimeStatus\(\)/)
  assert.match(settingsPageSource, /const handleMonitoringToggle = async/)
  assert.match(settingsPageSource, /await setBehaviorMonitoring\(enabled\)/)
  assert.match(settingsPageSource, /await setProcessMonitoring\(enabled\)/)
  assert.match(settingsPageSource, /await setFileMonitoring\(enabled\)/)
  assert.match(settingsPageSource, /monitoringControlError &&/)
  assert.match(settingsPageSource, /t\('settings_monitoring_status'\)/)
  assert.match(settingsPageSource, /APIHook \{monitoringRuntimeStatus \? \(monitoringRuntimeStatus\.processWatcherRunning \? t\('settings_monitoring_running'\) : t\('settings_monitoring_stopped'\)\) : t\('settings_monitoring_loading'\)\}/)
  assert.match(settingsPageSource, /disabled=\{monitoringControlPending !== null\}/)
})

test('OverviewPage and BehaviorPage consume typed runtime event listeners', () => {
  assert.match(logsApiSource, /export function onLogEvent\(callback: \(line: string\) => void\): \(\) => void/)
  assert.match(logsApiSource, /listen<string>\('log-event'/)
  assert.match(overviewPageSource, /getRecentLogs, clearLogs, onLogEvent/)
  assert.match(overviewPageSource, /const unlisten = onLogEvent\(\(line\) => \{[\s\S]*setLogs/)
  assert.match(overviewPageSource, /refreshMonitoringRuntimeStatus\(\)/)
  assert.match(overviewPageSource, /config\?\.behaviorMonitoring\?\.enabled/)
  assert.match(overviewPageSource, /fileHookEventCount/)
  assert.match(overviewPageSource, /const unlisten = onFileHookEvent\(\([^)]*\) => \{[\s\S]*setFileHookEventCount/)
  assert.match(behaviorPageSource, /onFileHookEvent/)
  assert.match(behaviorPageSource, /const \[fileHookEventCount, setFileHookEventCount\] = useState\(0\)/)
  assert.match(behaviorPageSource, /behavior_diag_title/)
  assert.match(behaviorPageSource, /getEtwDiagnosticsSnapshot/)
  assert.match(behaviorPageSource, /clearEtwDiagnostics/)
  assert.match(behaviorPageSource, /exportEtwDiagnostics/)
  assert.match(behaviorPageSource, /behavior_diag_hot_buckets/)
  assert.match(behaviorPageSource, /Hook: \{fileHookEventCount\}/)
})

// ETW 服务已从 Tauri 运行时解耦（服务进程里没有 Tauri 运行时，只有自己的 Tokio runtime），
// 后台任务改用 tokio::spawn。断言锁的仍是「设置触发的后台任务跑在真实存在的异步运行时上、
// 且轮询循环与风险分析都在其中」这一实质要求，只是表达方式随服务化改变。
//  The ETW service is decoupled from the Tauri runtime (the service process has no Tauri runtime,
//  only its own Tokio runtime), so background tasks use tokio::spawn. These assertions still lock
//  the real requirement - settings-triggered background work runs on a runtime that actually
//  exists, and both the poll loop and risk analysis live there.
test('ETW service spawns settings-triggered background tasks on the ambient async runtime', () => {
  assert.doesNotMatch(etwServiceSource, /tauri::async_runtime::spawn\(/)
  assert.match(etwServiceSource, /tokio::spawn\(async move \{[\s\S]*while running\.load/)
  assert.doesNotMatch(etwServiceSource, /behavior\.ingest_event/)
  assert.match(etwServiceSource, /EtwResponseGate::new/)
  assert.match(etwServiceSource, /behavior_db_gate\.should_record/)
  assert.match(etwServiceSource, /tokio::spawn\(async move \{[\s\S]*analyze_event/)
})

test('log buffer emits dedicated realtime log events', () => {
  // 日志推送已泛型化到 AppContext：AppHandle 与 ServiceContext 都实现该 trait，
  // UI 进程与服务进程共用同一实现。断言锁的是「实时 log-event 仍被推送」和
  // 「系统 PID 噪音在写入前被过滤」这两条实质要求。
  //  Log emission is generic over AppContext - both AppHandle and ServiceContext implement it, so
  //  the UI and service processes share one implementation. These assertions lock the real
  //  requirements: the realtime log-event is still pushed, and system-PID noise is filtered first.
  assert.match(logsCommandSource, /pub fn append_log_and_emit<C: AppContext>\(ctx: &C, entry: String\)/)
  assert.match(logsCommandSource, /ctx\.emit_event\("log-event", entry\)/)
  assert.match(logsCommandSource, /fn should_drop_system_log_event\(value: &serde_json::Value\) -> bool/)
  assert.match(logsCommandSource, /match event_pid\(value\) \{[\s\S]*Some\(0 \| 4\) => true,[\s\S]*Some\(pid\) => pid == INVALID_WINDOWS_PID_U32_MAX/)
  assert.match(etwServiceSource, /logs::append_event_log_and_emit\(&ctx_clone, &app_event\)/)
})
