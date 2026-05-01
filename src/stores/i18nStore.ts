/**
 * 国际化状态管理
 * i18n state management
 *
 * 管理当前语言环境和翻译数据。
 * Manages current locale and translation data.
 */
import { create } from 'zustand'
import { getLocale, getTranslations, setLocale as setApiLocale, translate, type Translations } from '../api/i18n'

/** i18n Store 接口 */
interface I18nState {
  locale: string
  translations: Translations
  loading: boolean
  t: (key: string, fallback?: string) => string
  loadTranslations: () => Promise<void>
  setLocale: (locale: string) => Promise<void>
}

export const useI18nStore = create<I18nState>((set, get) => ({
  locale: 'zh-CN',
  translations: {},
  loading: true,

  t: (key: string, fallback?: string) => {
    const { translations } = get()
    return translate(key, translations, fallback)
  },

  loadTranslations: async () => {
    try {
      const locale = await getLocale()
      const translations = await getTranslations(locale)
      set({ locale, translations, loading: false })
    } catch {
      // 默认使用中文
      set({ locale: 'zh-CN', translations: {}, loading: false })
    }
  },

  setLocale: async (locale: string) => {
    try {
      await setApiLocale(locale)
      const translations = await getTranslations(locale)
      set({ locale, translations })
    } catch (e) {
      console.error('Failed to set locale:', e)
    }
  },
}))
