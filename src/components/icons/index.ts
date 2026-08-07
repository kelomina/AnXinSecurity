/**
 * 安芯图标集统一出口
 * AnXin icon set barrel export
 *
 * 调用方：src/components/*.tsx（各页面与全局组件）
 * Called by: src/components/*.tsx (pages and global components)
 *
 * 图标名与原 lucide-react 保持一致，调用点只需改导入来源。
 * Glyph names match the previous lucide-react names, so call sites only change the import source.
 *
 * 中文关键词：图标出口，图标索引，导入来源
 * English keywords: icon barrel, icon index, import source
 */
export { createIcon, ICON_GRID, ICON_STROKE } from './createIcon'
export type { IconProps, GlyphNode } from './createIcon'

export {
  // 防护 / Protection
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  // 引擎与行为 / Engine and behavior
  Activity,
  Cpu,
  // 告警与状态 / Alerts and status
  AlertOctagon,
  AlertTriangle,
  Info,
  Check,
  CheckCircle,
  XCircle,
  Clock3,
  // 扫描与检出 / Scan and detection
  Search,
  FileSearch,
  Maximize2,
  // 文件与目录 / Files and folders
  FilePlus,
  FolderOpen,
  Download,
  ExternalLink,
  Trash2,
  // 传输控制 / Transport controls
  Play,
  Pause,
  Power,
  PowerOff,
  RefreshCw,
  RotateCcw,
  Loader,
  LoaderCircle,
  // 导航与窗口 / Navigation and window chrome
  LayoutDashboard,
  ArrowLeft,
  X,
  Minus,
  Plus,
  // 设置 / Settings
  Settings,
  Monitor,
  Sun,
  Moon,
  Globe2,
  Key,
  // 网络防火墙 / Network firewall
  Firewall,
} from './glyphs'
