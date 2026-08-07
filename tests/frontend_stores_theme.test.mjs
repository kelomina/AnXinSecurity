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
  assert.match(themeStoreSource, /setAnimationsEnabled: \(enabled: boolean, options\?: \{ persist\?: boolean \}\) => void/)
  assert.match(themeStoreSource, /syncFromConfig: \(config: AppConfig \| null \| undefined\) => void/)
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
  assert.match(themeStoreSource, /persistThemeMode\(mode\)\.catch/)
})

test('themeStore setThemeMode resolves system theme correctly', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /const actualTheme = mode === 'system' \? getSystemTheme\(\) : mode/)
})

test('themeStore applies animation preference to DOM attributes', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /const applyAnimationPreference = \(enabled: boolean\) => \{[\s\S]*document\.body\.setAttribute\('data-animations', enabled \? 'on' : 'off'\)/)
  assert.match(themeStoreSource, /document\.documentElement\.classList\.toggle\('reduce-motion', !enabled\)/)
})

test('themeStore toggleAnimations persists to backend', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /setAnimationsEnabled: \(enabled: boolean, options = \{ persist: true \}\) => \{[\s\S]*persistAnimationsEnabled\(enabled\)\.catch/)
  assert.match(themeStoreSource, /toggleAnimations: \(\) => \{[\s\S]*get\(\)\.setAnimationsEnabled\(enabled\)/)
})

test('themeStore syncs persisted appearance config without writing it back', () => {
  const themeStoreSource = readFileSync(resolve(projectRoot, 'src/stores/themeStore.ts'), 'utf8')
  assert.match(themeStoreSource, /import type \{ AppConfig \} from '\.\.\/api\/config'/)
  assert.match(themeStoreSource, /const isThemeMode = \(mode: string \| undefined\): mode is ThemeMode/)
  assert.match(themeStoreSource, /syncFromConfig: \(config: AppConfig \| null \| undefined\) => \{[\s\S]*config\?\.ui\?\.themeMode[\s\S]*config\?\.ui\?\.animations/)
  assert.match(themeStoreSource, /applyAnimationPreference\(animationsEnabled\)[\s\S]*set\(\{ themeMode: mode, actualTheme, animationsEnabled \}\)/)
  assert.doesNotMatch(themeStoreSource, /syncFromConfig: \(config: AppConfig \| null \| undefined\) => \{[\s\S]*persistAnimationsEnabled/)
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

test('App syncs persisted appearance config and keeps a non-animated page shell', () => {
  const appSource = readFileSync(resolve(projectRoot, 'src/App.tsx'), 'utf8')

  assert.match(appSource, /const initializeTheme = useThemeStore\(\(state\) => state\.initializeTheme\)/)
  assert.match(appSource, /const syncFromConfig = useThemeStore\(\(state\) => state\.syncFromConfig\)/)
  assert.match(appSource, /const configPromise = loadConfig\(\)/)
  assert.match(appSource, /const translationsPromise = loadTranslations\(\)/)
  assert.match(appSource, /setPhaseStatus\('config', 'active'\)[\s\S]*const configPromise = loadConfig\(\)/)
  assert.match(appSource, /setPhaseStatus\('theme', 'active'\)[\s\S]*const cleanupTheme = initializeTheme\(\)/)
  assert.match(appSource, /setPhaseStatus\('i18n', 'active'\)[\s\S]*const translationsPromise = loadTranslations\(\)/)
  assert.match(appSource, /setPhaseStatus\('listeners', 'active'\)[\s\S]*setPhaseStatus\('listeners', 'complete'\)/)
  assert.match(appSource, /await configPromise[\s\S]*syncFromConfig\(useConfigStore\.getState\(\)\.config\)/)
  assert.match(appSource, /await translationsPromise/)
  assert.match(appSource, /const cleanupTheme = initializeTheme\(\)/)
  // 锁住「className 与 data-current-page 在同一个标签上」这一实质要求，
  // 但允许该标签带其它属性（data-low-power / data-remote 是内存节省模式与远程会话的真实功能，
  // 不应为了迁就正则被删）。
  //  Locks the real requirement - className and data-current-page on the same tag - while
  //  tolerating additional attributes: data-low-power / data-remote are genuine features
  //  (memory-saving mode, remote session) and must not be dropped to satisfy a regex.
  assert.match(appSource, /<div className="page-container"[^>]*\sdata-current-page=\{currentPage\}[^>]*>/)
  assert.doesNotMatch(appSource, /key=\{currentPage\}/)
  assert.doesNotMatch(appSource, /pageContainerClassName|page-container--animated|framer-motion|MotionConfig|AnimatePresence|motion\./)
})

test('App defers heavy pages with React lazy and Suspense', () => {
  const appSource = readFileSync(resolve(projectRoot, 'src/App.tsx'), 'utf8')

  assert.match(appSource, /import React, \{ useEffect, useState, useCallback, lazy, Suspense \} from 'react'/)
  assert.match(appSource, /const OverviewPage = lazy\(\(\) => import\('\.\/components\/OverviewPage'\)\)/)
  assert.match(appSource, /const ScanPage = lazy\(\(\) => import\('\.\/components\/ScanPage'\)\)/)
  assert.match(appSource, /const QuarantinePage = lazy\(\(\) => import\('\.\/components\/QuarantinePage'\)\)/)
  assert.match(appSource, /const BehaviorPage = lazy\(\(\) => import\('\.\/components\/BehaviorPage'\)\)/)
  assert.match(appSource, /const SettingsPage = lazy\(\(\) => import\('\.\/components\/SettingsPage'\)\)/)
  assert.match(appSource, /const BehaviorLifecyclePage = lazy\(\(\) => import\('\.\/components\/BehaviorLifecyclePage'\)\)/)
  assert.match(appSource, /<Suspense fallback=\{<div className="page-container" \/>\}>/)
  // 锁住「className 与 data-current-page 在同一个标签上」这一实质要求，
  // 但允许该标签带其它属性（data-low-power / data-remote 是内存节省模式与远程会话的真实功能，
  // 不应为了迁就正则被删）。
  //  Locks the real requirement - className and data-current-page on the same tag - while
  //  tolerating additional attributes: data-low-power / data-remote are genuine features
  //  (memory-saving mode, remote session) and must not be dropped to satisfy a regex.
  assert.match(appSource, /<div className="page-container"[^>]*\sdata-current-page=\{currentPage\}[^>]*>/)
  assert.doesNotMatch(appSource, /key=\{currentPage\}/)
})

test('SplashScreen respects animation setting through Fluent style classes', () => {
  const source = readFileSync(resolve(projectRoot, 'src/components/SplashScreen.tsx'), 'utf8')

  assert.match(source, /import \{ useThemeStore \} from '\.\.\/stores\/themeStore'/)
  assert.match(source, /const animationsEnabled = useThemeStore\(\(state\) => state\.animationsEnabled\)/)
  assert.match(source, /overlayAnimated: \{[\s\S]*animationName: 'splashFadeIn'/)
  assert.match(source, /surfaceAnimated: \{[\s\S]*animationName: 'splashSlideIn'/)
  assert.match(source, /animationsEnabled \? styles\.overlayAnimated : ''/)
  assert.match(source, /animationsEnabled \? styles\.surfaceAnimated : ''/)
  assert.doesNotMatch(source, /style=/)
  assert.doesNotMatch(source, /framer-motion|AnimatePresence|motion\./)
})

test('global feedback surfaces use Fluent components without Framer Motion wrappers', () => {
  const toastSource = readFileSync(resolve(projectRoot, 'src/components/Toast.tsx'), 'utf8')
  const interceptionSource = readFileSync(resolve(projectRoot, 'src/components/InterceptionModal.tsx'), 'utf8')
  const traySource = readFileSync(resolve(projectRoot, 'src/components/TrayExitPrompt.tsx'), 'utf8')

  assert.match(toastSource, /Toaster/)
  assert.match(toastSource, /useToastController/)
  assert.match(toastSource, /ToastTrigger/)
  assert.match(interceptionSource, /DialogSurface/)
  assert.match(interceptionSource, /ProgressBar/)
  assert.match(traySource, /DialogSurface/)
  assert.match(traySource, /Checkbox/)
  assert.doesNotMatch(`${toastSource}\n${interceptionSource}\n${traySource}`, /framer-motion|AnimatePresence|motion\./)
})

test('config API exports AppConfig interface', () => {
  const configSource = readFileSync(resolve(projectRoot, 'src/api/config.ts'), 'utf8')
  assert.match(configSource, /export interface AppConfig/)
  assert.match(configSource, /brand: string/)
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
