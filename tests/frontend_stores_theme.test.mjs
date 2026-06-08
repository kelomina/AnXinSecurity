import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')

test('themeStore defines ThemeMode type with system, light, dark', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /export type ThemeMode = 'system' \| 'light' \| 'dark'/)
})

test('themeStore interface defines required methods', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')

  assert.match(themeStoreSource, /interface ThemeState/)
  assert.match(themeStoreSource, /themeMode: ThemeMode/)
  assert.match(themeStoreSource, /actualTheme: 'light' \| 'dark'/)
  assert.match(themeStoreSource, /animationsEnabled: boolean/)
  assert.match(themeStoreSource, /setThemeMode: \(mode: ThemeMode\) => void/)
  assert.match(themeStoreSource, /toggleAnimations: \(\) => void/)
  assert.ok(themeStoreSource.includes('initializeTheme: () =>'))
})

test('themeStore uses persist middleware', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /persist\(/, 'should use persist middleware')
  assert.match(themeStoreSource, /name: 'anxin-theme-storage'/)
})

test('themeStore persist partializes themeMode and animationsEnabled', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /partialize: \(state\) => \(\{[\s\S]*themeMode: state\.themeMode[\s\S]*animationsEnabled: state\.animationsEnabled/)
})

test('themeStore defaults to system theme and animations enabled', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /themeMode: 'system'/)
  assert.match(themeStoreSource, /animationsEnabled: true/)
})

test('themeStore getSystemTheme returns light or dark', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /const getSystemTheme = \(\): 'light' \| 'dark' => \{/)
  assert.match(themeStoreSource, /window\.matchMedia\('\(prefers-color-scheme: light\)'\)/)
})

test('themeStore setThemeMode applies theme to DOM', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /setThemeMode: \(mode: ThemeMode\) => \{[\s\S]*applyTheme\(actualTheme\)[\s\S]*set\(\{ themeMode: mode, actualTheme \}\)/)
})

test('themeStore setThemeMode resolves system theme correctly', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /const actualTheme = mode === 'system' \? getSystemTheme\(\) : mode/)
})

test('themeStore toggleAnimations updates DOM attribute', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /toggleAnimations: \(\) => \{[\s\S]*document\.body\.setAttribute\('data-animations', enabled \? 'on' : 'off'\)/)
})

test('themeStore toggleAnimations persists to backend', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /setAnimationsEnabled\(enabled\)\.catch/)
})

test('themeStore initializeTheme sets up media query listener', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /initializeTheme: \(\) => \{[\s\S]*mediaQuery\.addEventListener\('change', handleChange\)/)
  assert.match(themeStoreSource, /mediaQuery\.removeEventListener\('change', handleChange\)/)
})

test('themeStore initializeTheme returns cleanup function', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /return \(\) => mediaQuery\.removeEventListener\('change', handleChange\)/)
})

test('themeStore applyTheme sets data-theme attribute', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /const applyTheme = \(theme: 'light' \| 'dark'\) => \{[\s\S]*document\.documentElement\.setAttribute\('data-theme', theme\)/)
})

test('config API exports AppConfig interface', () => {
  const configSource = readFileSync(resolve(projectRoot, 'src/api/config.ts'), 'utf8')
  assert.match(configSource, /export interface AppConfig/)
  assert.match(configSource, /brand: string/)
  assert.match(configSource, /themeColor: string/)
  assert.match(configSource, /defaultPage: string/)
  assert.match(configSource, /minimizeToTray: boolean/)
})

test('config API AppConfig includes monitoring settings', () => {
  const configSource = readFileSync(resolve(projectRoot, 'src/api/config.ts'), 'utf8')
  assert.match(configSource, /behaviorMonitoring: \{[\s\S]*enabled: boolean/)
  assert.match(configSource, /processMonitoring: \{[\s\S]*enabled: boolean/)
  assert.match(configSource, /fileMonitoring: \{[\s\S]*enabled: boolean/)
})

test('config API AppConfig includes UI settings', () => {
  const configSource = readFileSync(resolve(projectRoot, 'src/api/config.ts'), 'utf8')
  assert.match(configSource, /ui: \{[\s\S]*themeMode: string/)
  assert.match(configSource, /animations: boolean/)
})

test('config API exports ExitConfirmation interface', () => {
  const configSource = readFileSync(resolve(projectRoot, 'src/api/config.ts'), 'utf8')
  assert.match(configSource, /export interface ExitConfirmation/)
  assert.match(configSource, /keep_service: boolean/)
  assert.match(configSource, /prompt_enabled: boolean/)
})

test('config API uses Tauri invoke for all commands', () => {
  const configSource = readFileSync(resolve(projectRoot, 'src/api/config.ts'), 'utf8')
  assert.match(configSource, /import \{ invoke \} from '@tauri-apps\/api\/core'/)
  assert.match(configSource, /await invoke\('get_config'\)/)
  assert.match(configSource, /await invoke\('set_behavior_monitoring_enabled', \{ enabled \}\)/)
  assert.match(configSource, /await invoke\('set_theme_mode', \{ mode \}\)/)
  assert.match(configSource, /await invoke\('set_animations_enabled', \{ enabled \}\)/)
  assert.match(configSource, /await invoke\('minimize_to_tray'\)/)
})
