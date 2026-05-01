/**
 * 国际化 API 封装
 * i18n API wrapper
 *
 * 封装语言获取、翻译加载和语言切换。
 * Wraps locale retrieval, translation loading, and language switching.
 */
import { invoke } from '@tauri-apps/api/core'

/** 翻译字典类型 / Translation dictionary type */
export type Translations = Record<string, string>

/**
 * 函数名称：getLocale
 * 函数作用：获取当前应用语言环境。
 * Purpose: Gets the current application locale.
 * 调用方：i18nStore 初始化
 * Called by: i18nStore initialization
 * 中文关键词：获取语言，语言环境，locale
 * English keywords: get locale, language environment
 */
export async function getLocale(): Promise<string> {
  return await invoke('get_locale')
}

/**
 * 函数名称：getTranslations
 * 函数作用：加载指定语言的翻译文件。
 * Purpose: Loads translation file for the specified locale.
 * 参数 locale: 语言代码 (zh-CN / en-US)
 * Called by: i18nStore 初始化
 * 中文关键词：加载翻译，语言包，翻译文件
 * English keywords: load translations, language pack, translation file
 */
export async function getTranslations(locale: string): Promise<Translations> {
  return await invoke('get_translations', { locale })
}

/**
 * 函数名称：setLocale
 * 函数作用：设置当前应用语言环境并持久化。
 * Purpose: Sets the current locale and persists it.
 * 参数 locale: 语言代码
 * 副作用：写入 config/app.json
 * Called by: SettingsPage 语言选择器
 * 中文关键词：设置语言，切换语言
 * English keywords: set locale, switch language
 */
export async function setLocale(locale: string): Promise<boolean> {
  return await invoke('set_locale', { locale })
}

/**
 * 简易翻译函数 — 从翻译字典查找文本
 * Simple translation function — looks up text from translation dictionary
 */
export function translate(key: string, translations: Translations, fallback?: string): string {
  return translations[key] || fallback || key
}
