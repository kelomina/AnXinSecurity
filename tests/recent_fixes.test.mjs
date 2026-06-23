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

test('SettingsPage toggle switches use div-based implementation with keyboard support', () => {
  // 验证开关组件不再使用 <input> 标签，而是使用 <div>
  assert.doesNotMatch(settingsPageSource, /<input type="checkbox"[^>]*className="toggle-input"/)
  
  // 验证使用 div.toggle 并带有 on 状态类
  assert.match(settingsPageSource, /<div[^>]*className={`toggle \$\{config\?\.behaviorMonitoring\?\.enabled \? 'on' : ''\}`}/)
  
  // 验证有 onClick 处理，并通过统一运行态控制入口触发
  assert.match(settingsPageSource, /onClick=\{\(\) => \{[\s\S]*handleMonitoringToggle\('behavior', !\(config\?\.behaviorMonitoring\?\.enabled \|\| false\)\)[\s\S]*\}\}/)
  
  // 验证有 ARIA 标签
  assert.match(settingsPageSource, /role="switch"/)
  assert.match(settingsPageSource, /aria-checked=\{config\?\.behaviorMonitoring\?\.enabled \|\| false\}/)
  
  // 验证有键盘支持（Enter 和 Space）
  assert.match(settingsPageSource, /onKeyDown=\{\(e\) => \{[\s\S]*if \(e\.key === 'Enter' \|\| e\.key === ' '\)[\s\S]*e\.preventDefault\(\)[\s\S]*handleMonitoringToggle\('behavior', !\(config\?\.behaviorMonitoring\?\.enabled \|\| false\)\)[\s\S]*\}\}/)
})

test('SettingsPage has consistent toggle implementation for all monitoring switches', () => {
  // 验证所有三个监控开关（行为、进程、文件）都有相同的实现模式
  const behaviorTogglePattern = /实时行为监控[\s\S]*className={`toggle \$\{config\?\.behaviorMonitoring\?\.enabled \? 'on' : ''\}`[\s\S]*onClick[\s\S]*handleMonitoringToggle\('behavior'/
  const processTogglePattern = /进程监控[\s\S]*className={`toggle \$\{config\?\.processMonitoring\?\.enabled \? 'on' : ''\}`[\s\S]*onClick[\s\S]*handleMonitoringToggle\('process'/
  const fileTogglePattern = /文件 Hook 监控[\s\S]*className={`toggle \$\{config\?\.fileMonitoring\?\.enabled \? 'on' : ''\}`[\s\S]*onClick[\s\S]*handleMonitoringToggle\('file'/
  const animationsTogglePattern = /关闭动效[\s\S]*className={`toggle \$\{!animationsEnabled \? 'on' : ''\}`[\s\S]*onClick[\s\S]*toggleAnimations/
  
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
  assert.match(configStoreSource, /const fallbackConfig = \([\s\S]*\): AppConfig => \(\{[\s\S]*brand: '',[\s\S]*themeColor: '',[\s\S]*defaultPage: '',[\s\S]*minimizeToTray: false,[\s\S]*behaviorMonitoring: \{ enabled: behaviorEnabled \},[\s\S]*processMonitoring: \{ enabled: processEnabled \},[\s\S]*fileMonitoring: \{ enabled: fileEnabled \},[\s\S]*ui: \{ themeMode: 'system', animations: true \}[\s\S]*\}\)/)
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
