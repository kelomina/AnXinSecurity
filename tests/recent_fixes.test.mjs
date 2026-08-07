import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')
const titleBarSource = readFileSync(resolve(projectRoot, 'src/components/TitleBar.tsx'), 'utf8')
const settingsPageSource = readFileSync(resolve(projectRoot, 'src/components/SettingsPage.tsx'), 'utf8')
const configStoreSource = readFileSync(resolve(projectRoot, 'src/stores/configStore.ts'), 'utf8')
const scanPageSource = readFileSync(resolve(projectRoot, 'src/components/ScanPage.tsx'), 'utf8')
const trayCommandSource = readFileSync(resolve(projectRoot, 'src-tauri/src/commands/tray.rs'), 'utf8')

test('TitleBar has proper error handling on window controls', () => {
  // 验证是否使用了 try/catch 包裹窗口操作
  assert.match(titleBarSource, /const handleMinimize = async \(\) => \{[\s\S]*try \{[\s\S]*await appWindow\.minimize\(\)[\s\S]*\} catch \(e\) \{[\s\S]*console\.error\(\'\[TitleBar\] Minimize failed:\', e\)[\s\S]*\}/)
  assert.match(titleBarSource, /const handleMaximize = async \(\) => \{[\s\S]*try \{[\s\S]*await appWindow\.toggleMaximize\(\)[\s\S]*\} catch \(e\) \{[\s\S]*console\.error\(\'\[TitleBar\] Toggle maximize failed:\', e\)[\s\S]*\}/)
  assert.match(titleBarSource, /useEffect\(\(\) => \{[\s\S]*appWindow\.isMaximized\(\)\.then\(setIsMaximized\)\.catch\(\(e\) => console\.error\(\'\[TitleBar\] isMaximized failed:\', e\)\)/)
})

test('TitleBar handles close button properly (minimize to tray)', () => {
  // 验证关闭按钮的处理逻辑
  assert.match(titleBarSource, /const handleClose = async \(\) => \{[\s\S]*try \{[\s\S]*const \{ invoke \} = await import\('@tauri-apps\/api\/core'\)[\s\S]*await invoke\('minimize_to_tray'\)[\s\S]*\} catch \{[\s\S]*await appWindow\.hide\(\)[\s\S]*\}/)
})

test('App lazily loads non-splash pages to reduce startup bundle pressure', () => {
  const appSource = readFileSync(resolve(projectRoot, 'src/App.tsx'), 'utf8')

  assert.match(appSource, /const OverviewPage = lazy\(\(\) => import\('\.\/components\/OverviewPage'\)\)/)
  assert.match(appSource, /const ScanPage = lazy\(\(\) => import\('\.\/components\/ScanPage'\)\)/)
  assert.match(appSource, /const QuarantinePage = lazy\(\(\) => import\('\.\/components\/QuarantinePage'\)\)/)
  assert.match(appSource, /const BehaviorPage = lazy\(\(\) => import\('\.\/components\/BehaviorPage'\)\)/)
  assert.match(appSource, /const SettingsPage = lazy\(\(\) => import\('\.\/components\/SettingsPage'\)\)/)
  assert.match(appSource, /const BehaviorLifecyclePage = lazy\(\(\) => import\('\.\/components\/BehaviorLifecyclePage'\)\)/)
  assert.doesNotMatch(appSource, /import OverviewPage from '\.\/components\/OverviewPage'/)
  assert.doesNotMatch(appSource, /import ScanPage from '\.\/components\/ScanPage'/)
  assert.doesNotMatch(appSource, /import QuarantinePage from '\.\/components\/QuarantinePage'/)
  assert.doesNotMatch(appSource, /import BehaviorPage from '\.\/components\/BehaviorPage'/)
  assert.doesNotMatch(appSource, /import SettingsPage from '\.\/components\/SettingsPage'/)
  assert.doesNotMatch(appSource, /import BehaviorLifecyclePage from '\.\/components\/BehaviorLifecyclePage'/)
  assert.match(appSource, /<Suspense fallback=\{<div className="page-container" \/>\}>/)
})

test('App keeps the page shell stable without page transition animation residue', () => {
  const appSource = readFileSync(resolve(projectRoot, 'src/App.tsx'), 'utf8')
  const globalCssSource = readFileSync(resolve(projectRoot, 'src/styles/global.css'), 'utf8')

  // 允许该标签带 data-low-power / data-remote 等其它真实属性，
  // 但仍要求 className 与 data-current-page 在同一个标签上。
  //  Tolerates other genuine attributes (data-low-power / data-remote) on the tag while still
  //  requiring className and data-current-page to sit on the same element.
  assert.match(appSource, /<div className="page-container"[^>]*\sdata-current-page=\{currentPage\}[^>]*>/)
  assert.doesNotMatch(appSource, /key=\{currentPage\}/)
  assert.doesNotMatch(appSource, /pageContainerClassName|page-container--animated|framer-motion|MotionConfig|AnimatePresence|motion\./)
  assert.doesNotMatch(globalCssSource, /pageFadeIn|page-container--animated/)
})

test('App keeps page shell stable and only animates when animations are enabled', () => {
  const appSource = readFileSync(resolve(projectRoot, 'src/App.tsx'), 'utf8')
  const globalCssSource = readFileSync(resolve(projectRoot, 'src/styles/global.css'), 'utf8')

  assert.doesNotMatch(globalCssSource, /@media \(prefers-reduced-motion: no-preference\) \{[\s\S]*\.page-container/)
})

test('Tray exit destroys webview windows after backend cleanup', () => {
  // 托盘退出不能在 invoke 响应返回前关闭窗口；后台清理完成后应使用 destroy() 做最终窗口收口。
  assert.match(trayCommandSource, /tokio::time::sleep\(Duration::from_millis\(75\)\)\.await;[\s\S]*execute_exit_after_invoke_response/)
  assert.match(trayCommandSource, /process_scanner\.stop\(\);[\s\S]*process_monitor\.stop\(\)[\s\S]*file_monitor\.stop\(\);[\s\S]*hook\.stop\(\)[\s\S]*etw\.pause\(\)[\s\S]*engine\.stop_engine\(\)\.await/)
  assert.match(trayCommandSource, /interception\.clear_all\(\);[\s\S]*destroy_webview_windows_for_exit\(&app_handle\);[\s\S]*app_handle\.exit\(0\);/)
  assert.match(trayCommandSource, /fn destroy_webview_windows_for_exit<[\s\S]*app_handle\.webview_windows\(\)/)
  assert.match(trayCommandSource, /"interception" => 0,[\s\S]*"main" => 2/)
  assert.match(trayCommandSource, /window\.destroy\(\)/)
  assert.doesNotMatch(trayCommandSource, /window\.close\(\)/)
})

test('SettingsPage uses Fluent Switch controls for monitoring toggles', () => {
  assert.match(settingsPageSource, /<Switch[\s\S]*checked=\{config\?\.behaviorMonitoring\?\.enabled \|\| false\}[\s\S]*handleMonitoringToggle\('behavior', data\.checked\)[\s\S]*disabled=\{monitoringControlPending !== null\}/)
  assert.match(settingsPageSource, /<Switch[\s\S]*checked=\{config\?\.processMonitoring\?\.enabled \|\| false\}[\s\S]*handleMonitoringToggle\('process', data\.checked\)[\s\S]*disabled=\{monitoringControlPending !== null\}/)
  assert.match(settingsPageSource, /<Switch[\s\S]*checked=\{config\?\.fileMonitoring\?\.enabled \|\| false\}[\s\S]*handleMonitoringToggle\('file', data\.checked\)[\s\S]*disabled=\{monitoringControlPending !== null\}/)
  assert.match(settingsPageSource, /<Switch checked=\{!animationsEnabled\} onChange=\{toggleAnimations\} \/>/)
})

test('SettingsPage has consistent Switch implementation for all monitoring switches', () => {
  const behaviorTogglePattern = /settings_behavior_monitoring[\s\S]*<Switch[\s\S]*handleMonitoringToggle\('behavior', data\.checked\)/
  const processTogglePattern = /settings_process_monitoring[\s\S]*<Switch[\s\S]*handleMonitoringToggle\('process', data\.checked\)/
  const fileTogglePattern = /settings_file_hook[\s\S]*<Switch[\s\S]*handleMonitoringToggle\('file', data\.checked\)/
  const animationsTogglePattern = /settings_disable_animations[\s\S]*<Switch checked=\{!animationsEnabled\} onChange=\{toggleAnimations\} \/>/

  assert.match(settingsPageSource, behaviorTogglePattern)
  assert.match(settingsPageSource, processTogglePattern)
  assert.match(settingsPageSource, fileTogglePattern)
  assert.match(settingsPageSource, animationsTogglePattern)
})

test('configStore uses runtime control pattern for monitoring settings', () => {
  // 验证三个监控开关都等待运行态控制命令，并在失败时回滚配置
  assert.match(configStoreSource, /setBehaviorMonitoring: \(enabled: boolean\) => Promise<void>/)
  assert.match(configStoreSource, /setBehaviorMonitoring: async \(enabled: boolean\) => \{[\s\S]*await setBehaviorMonitoringEnabled\(enabled\)[\s\S]*await get\(\)\.refreshMonitoringRuntimeStatus\(\)[\s\S]*set\(\{ config: previousConfig, monitoringControlError: message \}\)/)
  assert.match(configStoreSource, /setProcessMonitoring: async \(enabled: boolean\) => \{[\s\S]*await setProcessMonitoringEnabled\(enabled\)[\s\S]*await get\(\)\.refreshMonitoringRuntimeStatus\(\)[\s\S]*set\(\{ config: previousConfig, monitoringControlError: message \}\)/)
  assert.match(configStoreSource, /setFileMonitoring: async \(enabled: boolean\) => \{[\s\S]*await setFileMonitoringEnabled\(enabled\)[\s\S]*await get\(\)\.refreshMonitoringRuntimeStatus\(\)[\s\S]*set\(\{ config: previousConfig, monitoringControlError: message \}\)/)
  assert.doesNotMatch(configStoreSource, /await resumeEtw\(\)|await pauseEtw\(\)|await startProcessWatcher\(|await stopProcessWatcher\(\)|await startHookService\(|await stopHookService\(\)/)
})

test('configStore provides default config when config is null', () => {
  // 验证当 state.config 为 null 时，会提供默认配置
  assert.match(configStoreSource, /const fallbackConfig = \([\s\S]*\): AppConfig => \(\{[\s\S]*brand: '',[\s\S]*defaultPage: '',[\s\S]*minimizeToTray: false,[\s\S]*behaviorMonitoring: \{ enabled: behaviorEnabled \},[\s\S]*processMonitoring: \{ enabled: processEnabled \},[\s\S]*fileMonitoring: \{ enabled: fileEnabled \},[\s\S]*ui: \{ themeMode: 'system', animations: true \}[\s\S]*\}\)/)
})

test('ScanPage has error handling on file/directory selection', () => {
  // 验证扫描页文件选择有 try/catch
  assert.match(scanPageSource, /const handleSelectDirectory = async \(\) => \{[\s\S]*try \{[\s\S]*const selected = await open\([\s\S]*\} catch \(e\) \{[\s\S]*console\.error\(\'\[ScanPage\] Select directory failed:\', e\)[\s\S]*\}/)
  assert.match(scanPageSource, /const handleSelectFiles = async \(\) => \{[\s\S]*try \{[\s\S]*const selected = await open\([\s\S]*\} catch \(e\) \{[\s\S]*console\.error\(\'\[ScanPage\] Select files failed:\', e\)[\s\S]*\}/)
})

test('Tauri capabilities file exists with proper permissions', () => {
  // 验证 Tauri 权限配置文件存在
  const capabilitiesPath = resolve(projectRoot, 'src-tauri/capabilities/default.json')
  const interceptionCapabilitiesPath = resolve(projectRoot, 'src-tauri/capabilities/interception.json')
  const capabilitiesSource = readFileSync(capabilitiesPath, 'utf8')
  const interceptionCapabilitiesSource = readFileSync(interceptionCapabilitiesPath, 'utf8')
  const capabilities = JSON.parse(capabilitiesSource)
  const interceptionCapabilities = JSON.parse(interceptionCapabilitiesSource)
  assert.strictEqual(capabilities.identifier, 'default')
  assert.ok(Array.isArray(capabilities.permissions))
  assert.deepStrictEqual(capabilities.windows, ['main'])
  // 验证关键权限存在
  assert.ok(capabilities.permissions.includes('core:default'))
  assert.ok(capabilities.permissions.includes('core:window:default'))
  assert.ok(capabilities.permissions.includes('core:window:allow-minimize'))
  assert.ok(capabilities.permissions.includes('core:window:allow-toggle-maximize'))
  assert.ok(capabilities.permissions.includes('dialog:default'))
  assert.strictEqual(interceptionCapabilities.identifier, 'interception')
  assert.deepStrictEqual(interceptionCapabilities.windows, ['interception'])
  assert.ok(interceptionCapabilities.permissions.includes('core:default'))
  assert.ok(interceptionCapabilities.permissions.includes('core:event:allow-listen'))
  assert.ok(interceptionCapabilities.permissions.includes('core:window:allow-show'))
  assert.ok(interceptionCapabilities.permissions.includes('core:window:allow-hide'))
  assert.ok(interceptionCapabilities.permissions.includes('core:window:allow-unminimize'))
  assert.ok(interceptionCapabilities.permissions.includes('core:window:allow-set-always-on-top'))
  assert.ok(interceptionCapabilities.permissions.includes('core:window:allow-request-user-attention'))
  assert.ok(interceptionCapabilities.permissions.includes('core:window:allow-set-focus'))
  assert.ok(!interceptionCapabilities.permissions.includes('shell:default'))
  assert.ok(!interceptionCapabilities.permissions.includes('fs:default'))
})
