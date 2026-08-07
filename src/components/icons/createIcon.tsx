/**
 * 安芯图标工厂
 * AnXin icon factory
 *
 * 生成与 lucide-react 接口兼容的 SVG 图标组件，替换第三方通用图标集，
 * 使全部图标遵循同一套「安芯」几何语言。
 * Creates SVG icon components that are API-compatible with lucide-react so the
 * whole set can share one "AnXin" geometric language instead of a generic third-party set.
 *
 * 调用方：src/components/icons/glyphs.tsx（唯一调用方，逐个声明图标）
 * Called by: src/components/icons/glyphs.tsx (sole caller, declares each glyph)
 *
 * 设计规范见同目录 README.md。核心约定：
 * Design spec lives in README.md next to this file. Core contract:
 *   - 画布 24x24，安全区 20x20 / canvas 24x24, live area 20x20
 *   - 描边 1.75，颜色继承 currentColor / stroke 1.75, color inherited via currentColor
 *   - 容器形（盾、芯片、文件、机箱）用 45 度切角，不用圆角
 *     container shapes (shield, die, file, chassis) use 45-degree chamfers, never rounded corners
 *   - 动作形（勾、叉、箭头）保持开放笔画，圆头收尾
 *     action marks (check, cross, arrow) stay open strokes with round caps
 *
 * 中文关键词：图标，SVG，图标工厂，切角，描边，主题色继承
 * English keywords: icon, SVG, icon factory, chamfer, stroke, currentColor inheritance
 */
import React from 'react'

/** 单个图形元素：路径或圆 / A single drawable: path or circle */
export type GlyphNode =
  | { kind: 'path'; d: string; fill?: boolean }
  | { kind: 'circle'; cx: number; cy: number; r: number; fill?: boolean }

/**
 * 图标组件 props。
 * 与 lucide-react 保持一致，现有调用点（size / color / className）无需改动。
 * Matches lucide-react so existing call sites (size / color / className) keep working unchanged.
 */
export interface IconProps extends Omit<React.SVGProps<SVGSVGElement>, 'color'> {
  /** 边长，单位 px，默认 24 / Edge length in px, default 24 */
  size?: number | string
  /** 描边颜色，默认继承父级文字颜色 / Stroke color, defaults to inherited text color */
  color?: string
  /** 描边宽度，24 网格单位，默认 1.75 / Stroke width in 24-grid units, default 1.75 */
  strokeWidth?: number | string
}

/** 设计规范常量 / Design spec constants */
export const ICON_GRID = 24
export const ICON_STROKE = 1.75

/**
 * 由图形节点声明生成图标组件。
 * Builds an icon component from a declarative list of glyph nodes.
 */
export function createIcon(displayName: string, nodes: GlyphNode[]): React.FC<IconProps> {
  const Icon: React.FC<IconProps> = ({
    size = ICON_GRID,
    color = 'currentColor',
    strokeWidth = ICON_STROKE,
    ...rest
  }) => (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox={`0 0 ${ICON_GRID} ${ICON_GRID}`}
      fill="none"
      stroke={color}
      strokeWidth={strokeWidth}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {nodes.map((node, index) =>
        node.kind === 'path' ? (
          <path
            key={index}
            d={node.d}
            {...(node.fill ? { fill: color, stroke: 'none' } : null)}
          />
        ) : (
          <circle
            key={index}
            cx={node.cx}
            cy={node.cy}
            r={node.r}
            {...(node.fill ? { fill: color, stroke: 'none' } : null)}
          />
        ),
      )}
    </svg>
  )

  Icon.displayName = displayName
  return Icon
}

/** 声明一条描边路径 / Declare a stroked path */
export const p = (d: string): GlyphNode => ({ kind: 'path', d })
/** 声明一条填充路径 / Declare a filled path */
export const pf = (d: string): GlyphNode => ({ kind: 'path', d, fill: true })
/** 声明一个描边圆 / Declare a stroked circle */
export const c = (cx: number, cy: number, r: number): GlyphNode => ({ kind: 'circle', cx, cy, r })
/** 声明一个实心圆点，用于感叹号下点等 / Declare a solid dot, e.g. the dot under an exclamation mark */
export const dot = (cx: number, cy: number, r = 0.95): GlyphNode => ({
  kind: 'circle',
  cx,
  cy,
  r,
  fill: true,
})
