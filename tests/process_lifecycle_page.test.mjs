import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')
const appSource = readFileSync(resolve(projectRoot, 'src/App.tsx'), 'utf8')
const sidebarSource = readFileSync(resolve(projectRoot, 'src/components/Sidebar.tsx'), 'utf8')
const pageSource = readFileSync(resolve(projectRoot, 'src/components/ProcessLifecyclePage.tsx'), 'utf8')
const apiSource = readFileSync(resolve(projectRoot, 'src/api/processLifecycle.ts'), 'utf8')
const zhI18nSource = readFileSync(resolve(projectRoot, 'config/i18n/zh-CN.json'), 'utf8')
const enI18nSource = readFileSync(resolve(projectRoot, 'config/i18n/en-US.json'), 'utf8')
const i18nStoreSource = readFileSync(resolve(projectRoot, 'src/stores/i18nStore.ts'), 'utf8')

test('ProcessLifecyclePage is wired into routing and sidebar', () => {
  assert.match(appSource, /const ProcessLifecyclePage = lazy\(\(\) => import\('\.\/components\/ProcessLifecyclePage'\)\)/)
  assert.match(appSource, /case 'process-lifecycle':/)
  assert.match(appSource, /<ProcessLifecyclePage \/>/)
  assert.match(sidebarSource, /\{ id: 'process-lifecycle', labelKey: 'nav_process_lifecycle'/)
})

test('process lifecycle API exposes the three §4.6 commands and both events', () => {
  assert.match(apiSource, /invoke<ProcMonitorHealth>\('get_proc_monitor_health'\)/)
  assert.match(apiSource, /invoke<ProcessTreeNode\[\]>\('get_process_tree'\)/)
  assert.match(apiSource, /invoke<LifecycleEvent\[\]>\('list_lifecycle_events'/)
  assert.match(apiSource, /listen<LifecyclePush>\('process-lifecycle-event'/)
  assert.match(apiSource, /listen<TamperedAlert>\('process-monitor-tampered'/)
  assert.match(apiSource, /export interface ProcMonitorHealth/)
  assert.match(apiSource, /export interface ProcessTreeNode/)
  assert.match(apiSource, /export interface LifecycleEvent/)
  assert.match(apiSource, /export interface TamperedAlert/)
})

test('page consumes health, tree, events and the tampered alert', () => {
  assert.match(pageSource, /getProcMonitorHealth\(\)/)
  assert.match(pageSource, /getProcessTree\(\)/)
  assert.match(pageSource, /listLifecycleEvents\(500\)/)
  assert.match(pageSource, /onProcessLifecycleEvent\(/)
  assert.match(pageSource, /onProcessMonitorTampered\(/)
  assert.match(pageSource, /process_lifecycle_tampered_title/)
  assert.match(pageSource, /process_lifecycle_probe_card/)
  assert.match(pageSource, /process_lifecycle_health_card/)
  assert.match(pageSource, /process_lifecycle_tree_title/)
  assert.match(pageSource, /process_lifecycle_events_title/)
  // 探针统计字段必须展示（§13.7 探针可视性）
  assert.match(pageSource, /probeTotal/)
  assert.match(pageSource, /probeReportedOk/)
  assert.match(pageSource, /probeMissedRounds/)
  assert.match(pageSource, /tamperedAlerts/)
  // 进程树必须有存活/纠偏标记
  assert.match(pageSource, /process_lifecycle_restored/)
  assert.match(pageSource, /process_lifecycle_alive/)
})

test('process lifecycle text is available in zh-CN, en-US, and built-in fallback', () => {
  const requiredKeys = [
    'nav_process_lifecycle',
    'process_lifecycle_title',
    'process_lifecycle_subtitle',
    'process_lifecycle_refresh',
    'process_lifecycle_load_error',
    'process_lifecycle_health_card',
    'process_lifecycle_status',
    'process_lifecycle_connected',
    'process_lifecycle_disconnected',
    'process_lifecycle_driver_version',
    'process_lifecycle_table_size',
    'process_lifecycle_queue_depth',
    'process_lifecycle_dropped',
    'process_lifecycle_last_callback',
    'process_lifecycle_probe_card',
    'process_lifecycle_probe_total',
    'process_lifecycle_probe_reported',
    'process_lifecycle_probe_missed',
    'process_lifecycle_probe_alerts',
    'process_lifecycle_probe_reconciled',
    'process_lifecycle_tampered_title',
    'process_lifecycle_tampered_detail',
    'process_lifecycle_tampered_reconciled',
    'process_lifecycle_tree_title',
    'process_lifecycle_tree_empty',
    'process_lifecycle_events_title',
    'process_lifecycle_events_empty',
    'process_lifecycle_restored',
    'process_lifecycle_alive',
    'process_lifecycle_exited',
    'process_lifecycle_event_create',
    'process_lifecycle_event_exit',
  ]

  for (const key of requiredKeys) {
    assert.match(zhI18nSource, new RegExp(`"${key}"`))
    assert.match(enI18nSource, new RegExp(`"${key}"`))
    // i18nStore fallback：普通键无引号（key:），含连字符的键带引号（'key':）
    assert.match(i18nStoreSource, new RegExp(`['"]?${key}['"]?\\s*:`))
  }

  // 双语一致性：中英文案都在
  assert.match(zhI18nSource, /进程监控采集/)
  assert.match(enI18nSource, /Process Monitor Collector/)
})

test('whitelists include the process monitor events for service-mode forwarding', () => {
  const windowsServiceSource = readFileSync(resolve(projectRoot, 'src-tauri/crates/anxin-core/src/services/windows_service.rs'), 'utf8')
  const ipcBridgeSource = readFileSync(resolve(projectRoot, 'src-tauri/crates/anxin-core/src/services/ipc_bridge_service.rs'), 'utf8')
  assert.match(windowsServiceSource, /"process-lifecycle-event"/)
  assert.match(windowsServiceSource, /"process-monitor-tampered"/)
  assert.match(ipcBridgeSource, /"process-lifecycle-event"/)
  assert.match(ipcBridgeSource, /"process-monitor-tampered"/)
})
