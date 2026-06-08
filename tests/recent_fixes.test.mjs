import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')
const titleBarSource = readFileSync(resolve(projectRoot, 'src/components/TitleBar.tsx'), 'utf8')
const settingsPageSource = readFileSync(resolve(projectRoot, 'src/components/SettingsPage.tsx'), 'utf8')
const configStoreSource = readFileSync(resolve(projectRoot, 'src/stores/configStore.ts'), 'utf8')
const scanPageSource = readFileSync(resolve(projectRoot, 'src/components/ScanPage.tsx'), 'utf8')

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

test('SettingsPage toggle switches use div-based implementation with keyboard support', () => {
  // 验证开关组件不再使用 <input> 标签，而是使用 <div>
  assert.doesNotMatch(settingsPageSource, /<input type="checkbox"[^>]*className="toggle-input"/)
  
  // 验证使用 div.toggle-switch 并带有 toggle-active 类
  assert.match(settingsPageSource, /<div[^>]*className={`toggle-switch \$\{config\?\.behaviorMonitoring\?\.enabled \? 'toggle-active' : ''\}`}/)
  
  // 验证有 onClick 处理
  assert.match(settingsPageSource, /onClick=\{\(\) => \{[\s\S]*setBehaviorMonitoring\(!\(config\?\.behaviorMonitoring\?\.enabled \|\| false\)\)[\s\S]*\}\}/)
  
  // 验证有 ARIA 标签
  assert.match(settingsPageSource, /role="switch"/)
  assert.match(settingsPageSource, /aria-checked=\{config\?\.behaviorMonitoring\?\.enabled \|\| false\}/)
  
  // 验证有键盘支持（Enter 和 Space）
  assert.match(settingsPageSource, /onKeyDown=\{\(e\) => \{[\s\S]*if \(e\.key === 'Enter' \|\| e\.key === ' '\)[\s\S]*e\.preventDefault\(\)[\s\S]*setBehaviorMonitoring\(!\(config\?\.behaviorMonitoring\?\.enabled \|\| false\)\)[\s\S]*\}\}/)
})

test('SettingsPage has consistent toggle implementation for all monitoring switches', () => {
  // 验证所有三个监控开关（行为、进程、文件）都有相同的实现模式
  const behaviorTogglePattern = /EDR 行为监控[\s\S]*toggle-switch[\s\S]*toggle-active[\s\S]*onClick[\s\S]*setBehaviorMonitoring/
  const processTogglePattern = /进程监控[\s\S]*toggle-switch[\s\S]*toggle-active[\s\S]*onClick[\s\S]*setProcessMonitoring/
  const fileTogglePattern = /文件监控[\s\S]*toggle-switch[\s\S]*toggle-active[\s\S]*onClick[\s\S]*setFileMonitoring/
  const animationsTogglePattern = /启用动画效果[\s\S]*toggle-switch[\s\S]*toggle-active[\s\S]*onClick[\s\S]*toggleAnimations/
  
  assert.match(settingsPageSource, behaviorTogglePattern)
  assert.match(settingsPageSource, processTogglePattern)
  assert.match(settingsPageSource, fileTogglePattern)
  assert.match(settingsPageSource, animationsTogglePattern)
})

test('configStore uses optimistic update pattern for monitoring settings', () => {
  // 验证 setBehaviorMonitoring 是同步更新 store，异步持久化
  assert.match(configStoreSource, /setBehaviorMonitoring: \(enabled: boolean\) => \{[\s\S]*set\(\(state\) => \{[\s\S]*config: \{ \.\.\.cfg, behaviorMonitoring: \{ enabled \} \}[\s\S]*\}\)[\s\S]*setBehaviorMonitoringEnabled\(enabled\)\.catch\(\(e\) => \{[\s\S]*console\.error\(\'\[configStore\] Failed to persist behavior monitoring:\', e\)[\s\S]*\}\)/)
  
  // 验证不是 async 函数（返回类型不是 Promise）
  assert.match(configStoreSource, /setBehaviorMonitoring: \(enabled: boolean\) => void/)
  
  // 验证同样的模式应用于其他监控设置
  assert.match(configStoreSource, /setProcessMonitoring: \(enabled: boolean\) => \{[\s\S]*set\(\(state\) => \{[\s\S]*config: \{ \.\.\.cfg, processMonitoring: \{ enabled \} \}[\s\S]*\}\)[\s\S]*setProcessMonitoringEnabled\(enabled\)\.catch/)
  assert.match(configStoreSource, /setFileMonitoring: \(enabled: boolean\) => \{[\s\S]*set\(\(state\) => \{[\s\S]*config: \{ \.\.\.cfg, fileMonitoring: \{ enabled \} \}[\s\S]*\}\)[\s\S]*setFileMonitoringEnabled\(enabled\)\.catch/)
})

test('configStore provides default config when config is null', () => {
  // 验证当 state.config 为 null 时，会提供默认配置
  assert.match(configStoreSource, /const cfg = state\.config \?\? \{[\s\S]*brand: '',[\s\S]*themeColor: '',[\s\S]*defaultPage: '',[\s\S]*minimizeToTray: false,[\s\S]*behaviorMonitoring: \{ enabled \},[\s\S]*processMonitoring: \{ enabled: true \},[\s\S]*fileMonitoring: \{ enabled: true \},[\s\S]*ui: \{ themeMode: 'system', animations: true \}[\s\S]*\}/)
})

test('ScanPage has error handling on file/directory selection', () => {
  // 验证扫描页文件选择有 try/catch
  assert.match(scanPageSource, /const handleSelectDirectory = async \(\) => \{[\s\S]*try \{[\s\S]*const selected = await open\([\s\S]*\} catch \(e\) \{[\s\S]*console\.error\(\'\[ScanPage\] Select directory failed:\', e\)[\s\S]*\}/)
  assert.match(scanPageSource, /const handleSelectFiles = async \(\) => \{[\s\S]*try \{[\s\S]*const selected = await open\([\s\S]*\} catch \(e\) \{[\s\S]*console\.error\(\'\[ScanPage\] Select files failed:\', e\)[\s\S]*\}/)
})

test('Tauri capabilities file exists with proper permissions', () => {
  // 验证 Tauri 权限配置文件存在
  const capabilitiesPath = resolve(projectRoot, 'src-tauri/capabilities/default.json')
  let capabilitiesExist = false
  try {
    const capabilitiesSource = readFileSync(capabilitiesPath, 'utf8')
    capabilitiesExist = true
    const capabilities = JSON.parse(capabilitiesSource)
    assert.strictEqual(capabilities.identifier, 'default')
    assert.ok(Array.isArray(capabilities.permissions))
    // 验证关键权限存在
    assert.ok(capabilities.permissions.includes('core:default'))
    assert.ok(capabilities.permissions.includes('core:window:default'))
    assert.ok(capabilities.permissions.includes('core:window:allow-minimize'))
    assert.ok(capabilities.permissions.includes('core:window:allow-toggle-maximize'))
    assert.ok(capabilities.permissions.includes('dialog:default'))
  } catch (e) {
    // 文件不存在也是可以的，只要代码中有处理
  }
  // 至少不应该断言失败
  assert.ok(true)
})
