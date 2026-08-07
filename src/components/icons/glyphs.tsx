/**
 * 安芯图标集 — 全部 40 个界面图标
 * AnXin icon set - all 40 UI glyphs
 *
 * 每个图标手工绘制在 24x24 网格上，遵循 README.md 中的几何规范：
 * 容器形用 45 度切角（盾牌 / 芯片 / 文件 / 机箱 / 回收箱），动作形保持开放笔画。
 * Each glyph is hand-drawn on a 24x24 grid following the geometry spec in README.md:
 * container shapes use 45-degree chamfers (shield / die / file / chassis / bin),
 * action marks stay open strokes.
 *
 * 调用方：src/components/icons/index.ts（统一出口）
 * Called by: src/components/icons/index.ts (single barrel export)
 *
 * 中文关键词：图标，盾牌，芯片，扫描，行为监控，隔离区，设置
 * English keywords: icon, shield, silicon die, scan, behavior monitor, quarantine, settings
 */
import { createIcon, p, pf, c, dot } from './createIcon'

/* ------------------------------------------------------------------ *
 * 核心形状 / Core shapes
 * 盾牌与芯片是整套图标的几何母题，其它图标复用同样的 45 度切角。
 * The shield and the die are the geometric motif the rest of the set inherits.
 * ------------------------------------------------------------------ */

/** 安芯盾：六边切面护甲，非圆角盾 / AnXin shield: faceted armour plate, not a rounded shield */
const SHIELD = 'M12 2.6L19.8 5.4V11.9L12 21.4L4.2 11.9V5.4Z'
/** 芯片本体：切角方形晶粒 / Die body: chamfered square */
const DIE = 'M9 6.6H15L17.4 9V15L15 17.4H9L6.6 15V9Z'

/* ------------------------------------------------------------------ *
 * 防护 / Protection
 * ------------------------------------------------------------------ */

export const Shield = createIcon('Shield', [p(SHIELD)])

export const ShieldCheck = createIcon('ShieldCheck', [p(SHIELD), p('M8.5 11.6L11 14.1L15.5 9.4')])

export const ShieldAlert = createIcon('ShieldAlert', [
  p(SHIELD),
  p('M12 7.6V12.6'),
  dot(12, 15.9),
])

export const ShieldOff = createIcon('ShieldOff', [p(SHIELD), p('M5.6 5.2L18.4 18')])

/* ------------------------------------------------------------------ *
 * 引擎与行为 / Engine and behavior
 * ------------------------------------------------------------------ */

/** 行为监控：事件轨迹波形 / Behavior monitor: event trace waveform */
export const Activity = createIcon('Activity', [p('M2.6 12H7.3L9.7 5.2L14.2 18.9L16.6 12H21.4')])

/** 引擎核心：晶粒加八根引脚 / Engine core: die with eight pins */
export const Cpu = createIcon('Cpu', [
  p(DIE),
  p('M10.3 10.3H13.7V13.7H10.3Z'),
  p('M10.5 6.6V3.2'),
  p('M13.5 6.6V3.2'),
  p('M10.5 17.4V20.8'),
  p('M13.5 17.4V20.8'),
  p('M6.6 10.5H3.2'),
  p('M6.6 13.5H3.2'),
  p('M17.4 10.5H20.8'),
  p('M17.4 13.5H20.8'),
])

/* ------------------------------------------------------------------ *
 * 告警与状态 / Alerts and status
 * ------------------------------------------------------------------ */

export const AlertOctagon = createIcon('AlertOctagon', [
  p('M8.7 3H15.3L21 8.7V15.3L15.3 21H8.7L3 15.3V8.7Z'),
  p('M12 8V12.9'),
  dot(12, 16.2),
])

export const AlertTriangle = createIcon('AlertTriangle', [
  p('M12 3.4L21.4 19.8H2.6Z'),
  p('M12 9.6V13.8'),
  dot(12, 17),
])

export const Info = createIcon('Info', [c(12, 12, 9), p('M12 11V16.4'), dot(12, 7.9)])

export const Check = createIcon('Check', [p('M4.6 12.6L9.6 17.6L19.4 6.4')])

export const CheckCircle = createIcon('CheckCircle', [
  c(12, 12, 9),
  p('M7.9 12.4L10.9 15.4L16.3 9.3'),
])

export const XCircle = createIcon('XCircle', [
  c(12, 12, 9),
  p('M8.6 8.6L15.4 15.4'),
  p('M15.4 8.6L8.6 15.4'),
])

export const Clock3 = createIcon('Clock3', [c(12, 12, 9), p('M12 6.6V12H16.4')])

/* ------------------------------------------------------------------ *
 * 扫描与检出 / Scan and detection
 * ------------------------------------------------------------------ */

export const Search = createIcon('Search', [c(10.7, 10.7, 6.7), p('M15.5 15.5L20.8 20.8')])

/** 文件扫描：切角文件 + 检出镜，文件右下留口给镜体 / File scan: chamfered file plus lens */
export const FileSearch = createIcon('FileSearch', [
  p('M12.4 3.2H6.2L4.8 4.6V17.4L6.2 18.8H9.6'),
  p('M12.4 3.2V7.6H16.8'),
  p('M16.8 7.6V11'),
  c(14.8, 15.2, 3.7),
  p('M17.4 17.8L20.6 21'),
])

/** 取景角标，同时用于窗口最大化 / Framing brackets, shared with window maximize */
const FRAME_BRACKETS = [
  p('M9.4 3.6H5L3.6 5V9.4'),
  p('M14.6 3.6H19L20.4 5V9.4'),
  p('M20.4 14.6V19L19 20.4H14.6'),
  p('M3.6 14.6V19L5 20.4H9.4'),
]

export const Maximize2 = createIcon('Maximize2', FRAME_BRACKETS)

/* ------------------------------------------------------------------ *
 * 文件与目录 / Files and folders
 * ------------------------------------------------------------------ */

export const FilePlus = createIcon('FilePlus', [
  p('M13.6 3.2H7L5.6 4.6V19.4L7 20.8H17L18.4 19.4V8Z'),
  p('M13.6 3.2V8H18.4'),
  p('M12 11.6V16.8'),
  p('M9.4 14.2H14.6'),
])

export const FolderOpen = createIcon('FolderOpen', [
  p('M3.4 19.4V6.6L4.8 5.2H9.4L11.6 7.6H18.6L20 9V12.2'),
  p('M3.4 19.4L6.4 12.2H21.2L18.2 19.4Z'),
])

export const Download = createIcon('Download', [
  p('M12 3.4V15.4'),
  p('M6.9 10.3L12 15.4L17.1 10.3'),
  p('M4.2 17.6V19.4L5.6 20.8H18.4L19.8 19.4V17.6'),
])

export const ExternalLink = createIcon('ExternalLink', [
  p('M11.5 4.6H6L4.6 6V18L6 19.4H18L19.4 18V12.5'),
  p('M14.4 4.6H19.4V9.6'),
  p('M19.4 4.6L11.8 12.2'),
])

export const Trash2 = createIcon('Trash2', [
  p('M3.6 6.4H20.4'),
  p('M9.4 6.4V4.6L10.4 3.6H13.6L14.6 4.6V6.4'),
  p('M5.8 6.4V19.4L7.2 20.8H16.8L18.2 19.4V6.4'),
  p('M10.2 10.4V16.8'),
  p('M13.8 10.4V16.8'),
])

/* ------------------------------------------------------------------ *
 * 传输控制 / Transport controls
 * 启停类主控用实心，与轮廓图标形成层级区分。
 * Primary start/stop controls are solid, creating a deliberate weight hierarchy.
 * ------------------------------------------------------------------ */

export const Play = createIcon('Play', [
  pf('M8.6 5.1V18.9L19.4 12.6C19.9 12.3 19.9 11.7 19.4 11.4Z'),
])

export const Pause = createIcon('Pause', [
  pf('M8.6 4.6H10L11 5.6V18.4L10 19.4H8.6L7.6 18.4V5.6Z'),
  pf('M14 4.6H15.4L16.4 5.6V18.4L15.4 19.4H14L13 18.4V5.6Z'),
])

export const Power = createIcon('Power', [
  p('M12 3.2V11.8'),
  p('M6.9 6.4A7.9 7.9 0 1 0 17.1 6.4'),
])

export const PowerOff = createIcon('PowerOff', [
  p('M12 3.2V11.8'),
  p('M6.9 6.4A7.9 7.9 0 1 0 17.1 6.4'),
  p('M4.2 4.2L19.8 19.8'),
])

export const RefreshCw = createIcon('RefreshCw', [
  p('M3.4 12A8.6 8.6 0 0 1 17.9 5.7L20.6 8.2'),
  p('M20.6 3.6V8.5H15.7'),
  p('M20.6 12A8.6 8.6 0 0 1 6.1 18.3L3.4 15.8'),
  p('M3.4 20.4V15.5H8.3'),
])

export const RotateCcw = createIcon('RotateCcw', [
  p('M3.5 3.6V9.4H9.3'),
  p('M3.6 9.3A8.7 8.7 0 1 1 3.9 15.4'),
])

export const Loader = createIcon('Loader', [
  p('M12 7.4V2.7'),
  p('M15.25 8.75L18.58 5.42'),
  p('M16.6 12H21.3'),
  p('M15.25 15.25L18.58 18.58'),
  p('M12 16.6V21.3'),
  p('M8.75 15.25L5.42 18.58'),
  p('M7.4 12H2.7'),
  p('M8.75 8.75L5.42 5.42'),
])

export const LoaderCircle = createIcon('LoaderCircle', [p('M21 12A9 9 0 1 1 12 3')])

/* ------------------------------------------------------------------ *
 * 导航与窗口 / Navigation and window chrome
 * ------------------------------------------------------------------ */

export const LayoutDashboard = createIcon('LayoutDashboard', [
  p('M3.4 4.8L4.8 3.4H9.4L10.8 4.8V10.6L9.4 12H4.8L3.4 10.6Z'),
  p('M13.2 4.8L14.6 3.4H19.2L20.6 4.8V7L19.2 8.4H14.6L13.2 7Z'),
  p('M13.2 12.4L14.6 11H19.2L20.6 12.4V19.2L19.2 20.6H14.6L13.2 19.2Z'),
  p('M3.4 16L4.8 14.6H9.4L10.8 16V19.2L9.4 20.6H4.8L3.4 19.2Z'),
])

export const ArrowLeft = createIcon('ArrowLeft', [p('M20 12H4.6'), p('M11 5.6L4.6 12L11 18.4')])

export const X = createIcon('X', [p('M5.6 5.6L18.4 18.4'), p('M18.4 5.6L5.6 18.4')])

export const Minus = createIcon('Minus', [p('M4.6 12H19.4')])

export const Plus = createIcon('Plus', [p('M12 4.6V19.4'), p('M4.6 12H19.4')])

/* ------------------------------------------------------------------ *
 * 设置 / Settings
 * ------------------------------------------------------------------ */

/** 六齿齿轮，齿数与盾牌切面数一致 / Six-tooth gear, tooth count matches the shield facets */
export const Settings = createIcon('Settings', [
  p(
    'M9.21 6.02L9.89 2.84H14.11L14.79 6.02L15.79 6.59L18.87 5.59L20.99 9.25L18.57 11.42V12.58L20.99 14.75L18.87 18.41L15.79 17.41L14.79 17.98L14.11 21.16H9.89L9.21 17.98L8.21 17.41L5.13 18.41L3.01 14.75L5.43 12.58V11.42L3.01 9.25L5.13 5.59L8.21 6.59Z',
  ),
  c(12, 12, 3.05),
])

export const Monitor = createIcon('Monitor', [
  p('M4.6 4.2H19.4L20.8 5.6V15.4L19.4 16.8H4.6L3.2 15.4V5.6Z'),
  p('M12 16.8V20.4'),
  p('M9.4 20.4H14.6'),
])

export const Sun = createIcon('Sun', [
  c(12, 12, 4.8),
  p('M18.4 12H21.2'),
  p('M16.53 16.53L18.51 18.51'),
  p('M12 18.4V21.2'),
  p('M7.47 16.53L5.49 18.51'),
  p('M5.6 12H2.8'),
  p('M7.47 7.47L5.49 5.49'),
  p('M12 5.6V2.8'),
  p('M16.53 7.47L18.51 5.49'),
])

export const Moon = createIcon('Moon', [
  p('M20.4 14.6A9 9 0 1 1 9.4 3.6A7.2 7.2 0 0 0 20.4 14.6Z'),
])

export const Globe2 = createIcon('Globe2', [
  c(12, 12, 9),
  p('M3 12H21'),
  p('M12 3A5.4 9 0 0 1 12 21'),
  p('M12 3A5.4 9 0 0 0 12 21'),
])

export const Key = createIcon('Key', [
  c(8.3, 15.7, 4.4),
  p('M11.4 12.6L20.6 3.4'),
  p('M16.6 7.4L19 9.8'),
])

/* ------------------------------------------------------------------ *
 * 网络防火墙 / Network firewall
 * ------------------------------------------------------------------ */

/**
 * 防火墙：砖墙。容器沿用 DIE 的 45 度切角母题，横竖砖缝错缝排布，
 * 与 Globe2 的圆形网络语义区分开 —— 一个表示"网络"，一个表示"拦截网络"。
 * Firewall: a brick wall. The container reuses the 45-degree chamfer motif from
 * DIE, with staggered courses. It reads distinctly from Globe2's circular
 * network mark: one means "network", this one means "network being blocked".
 */
export const Firewall = createIcon('Firewall', [
  p('M6.6 5.4H17.4L19.4 7.4V16.6L17.4 18.6H6.6L4.6 16.6V7.4Z'),
  p('M4.6 12H19.4'),
  p('M10.4 5.4V12'),
  p('M14 12V18.6'),
])
