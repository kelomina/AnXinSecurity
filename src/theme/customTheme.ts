import { createLightTheme, createDarkTheme, BrandVariants } from '@fluentui/react-components'

// 自定义品牌色 - 使用低饱和蓝灰作为主色调
const anxinBrand: BrandVariants = {
  10: '#020305',
  20: '#11161B',
  30: '#19232C',
  40: '#22303A',
  50: '#2B3D49',
  60: '#344B5A',
  70: '#3D5A6B',
  80: '#46697D',
  90: '#50798F',
  100: '#5A89A2',
  110: '#6498B4',
  120: '#72A8C5',
  130: '#86B7D2',
  140: '#9AC6DE',
  150: '#B0D4E8',
  160: '#C7E2F1',
}

// 创建自定义浅色主题
export const customLightTheme = createLightTheme(anxinBrand)

// 为浅色主题添加自定义覆盖
Object.assign(customLightTheme, {
  // 背景色层级 - 使用更清爽的浅灰
  colorNeutralBackground1: '#FFFFFF',
  colorNeutralBackground2: '#F8F9FA',
  colorNeutralBackground3: '#F0F2F5',
  colorNeutralBackground4: '#E8EBED',

  // 文本颜色 - 增强对比度
  colorNeutralForeground1: '#1C1C1C',
  colorNeutralForeground2: '#424242',
  colorNeutralForeground3: '#616161',
  colorNeutralForeground4: '#9E9E9E',

  // 边框颜色 - 更柔和
  colorNeutralStroke1: '#D1D5DB',
  colorNeutralStroke2: '#E5E7EB',

  // 品牌色 - 降低饱和度，减少页面刺眼感
  colorBrandBackground: '#5E95C6',
  colorBrandBackgroundHover: '#4F86B7',
  colorBrandBackgroundPressed: '#426F98',
  colorBrandForeground1: '#5E95C6',
  colorBrandForeground2: '#426F98',

  // 语义化颜色 - 保留安全含义，降低饱和度
  colorPaletteRedBackground2: '#F4E3E4',
  colorPaletteRedBackground3: '#B85A5D',
  colorPaletteRedForeground2: '#B85A5D',
  colorPaletteRedBorder1: '#E5C8C9',
  colorPaletteRedBorder2: '#D6A4A6',
  colorPaletteRedBorderActive: '#B85A5D',

  colorPaletteGreenBackground2: '#E3F0E5',
  colorPaletteGreenBackground3: '#5F9469',
  colorPaletteGreenForeground2: '#4F8A5B',
  colorPaletteGreenBorder2: '#A9C9AE',
  colorPaletteGreenBorderActive: '#5F9469',

  colorPaletteYellowBackground2: '#F5EAD8',
  colorPaletteYellowBackground3: '#B98645',
  colorPaletteYellowForeground2: '#A8793E',
  colorPaletteYellowBorder2: '#D5B37A',
  colorPaletteYellowBorderActive: '#A8793E',

  colorPaletteBlueBackground2: '#E3EDF5',
  colorPaletteBlueForeground2: '#4F7FAE',
  colorPaletteBlueBorder2: '#A8C2DA',
  colorPaletteBlueBorderActive: '#D7E5EF',

  // 卡片阴影 - 更柔和的阴影
  shadow4: '0 2px 4px rgba(0, 0, 0, 0.05)',
  shadow8: '0 4px 8px rgba(0, 0, 0, 0.08)',
  shadow16: '0 8px 16px rgba(0, 0, 0, 0.10)',
  shadow28: '0 14px 28px rgba(0, 0, 0, 0.12)',
  shadow64: '0 32px 64px rgba(0, 0, 0, 0.15)',
})

// 创建自定义深色主题
export const customDarkTheme = createDarkTheme(anxinBrand)

// 为深色主题添加自定义覆盖
Object.assign(customDarkTheme, {
  // 背景色层级 - 使用更深邃的深色，层次更分明
  colorNeutralBackground1: '#0F1419',
  colorNeutralBackground2: '#16222D',
  colorNeutralBackground3: '#1B2F3F',
  colorNeutralBackground4: '#234863',

  // 文本颜色 - 更清晰
  colorNeutralForeground1: '#F5F5F5',
  colorNeutralForeground2: '#E0E0E0',
  colorNeutralForeground3: '#B0B0B0',
  colorNeutralForeground4: '#808080',

  // 边框颜色 - 更明显
  colorNeutralStroke1: '#3A4A5C',
  colorNeutralStroke2: '#2D3A48',

  // 品牌色 - 深色背景上保持清晰但不过亮
  colorBrandBackground: '#72A8C5',
  colorBrandBackgroundHover: '#86B7D2',
  colorBrandBackgroundPressed: '#5E95C6',
  colorBrandForeground1: '#9AC6DE',
  colorBrandForeground2: '#86B7D2',

  // 语义化颜色 - 深色主题优化并降低饱和度
  colorPaletteRedBackground2: '#332222',
  colorPaletteRedBackground3: '#7E4A4C',
  colorPaletteRedForeground2: '#D9A0A2',
  colorPaletteRedBorder1: '#573435',
  colorPaletteRedBorder2: '#704547',
  colorPaletteRedBorderActive: '#B8787A',

  colorPaletteGreenBackground2: '#223428',
  colorPaletteGreenBackground3: '#4A7852',
  colorPaletteGreenForeground2: '#A1C8A8',
  colorPaletteGreenBorder2: '#3F704A',
  colorPaletteGreenBorderActive: '#6F9B75',

  colorPaletteYellowBackground2: '#342E21',
  colorPaletteYellowBackground3: '#7D6339',
  colorPaletteYellowForeground2: '#D7B978',
  colorPaletteYellowBorder2: '#735A2D',
  colorPaletteYellowBorderActive: '#A48654',

  colorPaletteBlueBackground2: '#202D38',
  colorPaletteBlueForeground2: '#A6C5DD',
  colorPaletteBlueBorder2: '#3E668A',
  colorPaletteBlueBorderActive: '#334A5D',

  // 卡片阴影 - 深色主题的阴影
  shadow4: '0 2px 4px rgba(0, 0, 0, 0.3)',
  shadow8: '0 4px 8px rgba(0, 0, 0, 0.4)',
  shadow16: '0 8px 16px rgba(0, 0, 0, 0.5)',
  shadow28: '0 14px 28px rgba(0, 0, 0, 0.6)',
  shadow64: '0 32px 64px rgba(0, 0, 0, 0.7)',
})
