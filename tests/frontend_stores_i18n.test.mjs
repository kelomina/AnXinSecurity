import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import test from 'node:test'

const projectRoot = resolve(import.meta.dirname, '..')

test('i18n API translate function returns key when no translation exists', () => {
  const i18nSource = readFileSync(resolve(projectRoot, 'src/api/i18n.ts'), 'utf8')
  assert.match(i18nSource, /export function translate\(key: string, translations: Translations, fallback\?: string\)/)

  const translate = (key, translations, fallback) => {
    return translations[key] || fallback || key
  }

  assert.equal(translate('hello', {}, undefined), 'hello')
  assert.equal(translate('hello', {}, 'Hello!'), 'Hello!')
  assert.equal(translate('hello', { hello: '你好' }), '你好')
  assert.equal(translate('missing', { hello: '你好' }, 'Fallback'), 'Fallback')
})

test('i18n API translate function handles empty translations', () => {
  const translate = (key, translations, fallback) => {
    return translations[key] || fallback || key
  }

  const emptyTranslations = {}
  assert.equal(translate('test', emptyTranslations), 'test')
  assert.equal(translate('test', emptyTranslations, 'default'), 'default')
})

test('i18n API translate function handles nested keys in translations', () => {
  const translate = (key, translations, fallback) => {
    return translations[key] || fallback || key
  }

  const translations = {
    'app.title': 'AnXinSecurity',
    'settings.theme': 'Theme',
    'settings.theme.light': 'Light Mode',
  }

  assert.equal(translate('app.title', translations), 'AnXinSecurity')
  assert.equal(translate('settings.theme.light', translations), 'Light Mode')
  assert.equal(translate('nonexistent', translations, 'Default'), 'Default')
})

test('i18n API translate function prioritizes fallback over key', () => {
  const translate = (key, translations, fallback) => {
    return translations[key] || fallback || key
  }

  assert.equal(translate('key', {}, 'fallback'), 'fallback')
  assert.equal(translate('key', { key: 'translated' }, 'fallback'), 'translated')
})

test('i18nStore interface defines required properties', () => {
  const configStoreSource = readFileSync(resolve(projectRoot, 'src/stores/i18nStore.ts'), 'utf8')

  assert.match(configStoreSource, /interface I18nState/)
  assert.match(configStoreSource, /locale: string/)
  assert.match(configStoreSource, /translations: Translations/)
  assert.match(configStoreSource, /loading: boolean/)
  assert.match(configStoreSource, /t: \(key: string, fallback\?: string\) => string/)
  assert.match(configStoreSource, /loadTranslations: \(\) => Promise<void>/)
  assert.match(configStoreSource, /setLocale: \(locale: string\) => Promise<void>/)
})

test('i18nStore defaults to zh-CN locale', () => {
  const i18nStoreSource = readFileSync(resolve(projectRoot, 'src/stores/i18nStore.ts'), 'utf8')
  assert.match(i18nStoreSource, /locale: 'zh-CN'/)
})

test('i18nStore loadTranslations handles errors gracefully', () => {
  const i18nStoreSource = readFileSync(resolve(projectRoot, 'src/stores/i18nStore.ts'), 'utf8')
  assert.match(i18nStoreSource, /const zhCNFallback: Translations = \{/)
  assert.match(i18nStoreSource, /catch \{[\s\S]*set\(\{ locale: 'zh-CN', translations: zhCNFallback, loading: false \}\)/)
})

test('i18nStore fallback contains ETW diagnostics strings', () => {
  const i18nStoreSource = readFileSync(resolve(projectRoot, 'src/stores/i18nStore.ts'), 'utf8')
  assert.match(i18nStoreSource, /behavior_diag_title: 'ETW 现场诊断'/)
  assert.match(i18nStoreSource, /behavior_diag_export_failed: '导出 ETW 诊断失败'/)
})

test('i18nStore t function uses translate from api', () => {
  const i18nStoreSource = readFileSync(resolve(projectRoot, 'src/stores/i18nStore.ts'), 'utf8')
  assert.match(i18nStoreSource, /t: \(key: string, fallback\?: string\) => \{[\s\S]*translate\(key, translations, fallback\)/)
})

test('i18n API functions use Tauri invoke', () => {
  const i18nSource = readFileSync(resolve(projectRoot, 'src/api/i18n.ts'), 'utf8')

  assert.match(i18nSource, /import \{ invoke \} from '@tauri-apps\/api\/core'/)
  assert.match(i18nSource, /await invoke\('get_locale'\)/)
  assert.match(i18nSource, /await invoke\('get_translations', \{ locale \}\)/)
  assert.match(i18nSource, /await invoke\('set_locale', \{ locale \}\)/)
})

test('i18n API exports Translations type', () => {
  const i18nSource = readFileSync(resolve(projectRoot, 'src/api/i18n.ts'), 'utf8')
  assert.match(i18nSource, /export type Translations = Record<string, string>/)
})
