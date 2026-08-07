# 安芯图标系统 / AnXin Icon System

自绘图标集，替换原先的 `lucide-react` 通用图标，使界面图标与产品主题（Windows 端点安全防护）一致。

Hand-drawn icon set replacing the generic `lucide-react` icons so UI glyphs match the product theme
(Windows endpoint security).

## 为什么自绘 / Why redraw

`lucide-react` 是通用图标集，圆角、圆头、统一 2px 描边，放在任何 SaaS 界面里都成立，因此也不属于任何产品。
安芯的主题是「安全的芯」——硅片、事件轨迹、护甲。这套图标把这个主题变成可复用的几何规则。

`lucide-react` is a general-purpose set: rounded corners everywhere, uniform 2px strokes, equally at home
in any SaaS UI and therefore belonging to none. AnXin's theme is "the secure core" — silicon, event traces,
armour. This set turns that theme into reusable geometric rules.

## 几何规范 / Geometry spec

| 项 / Item | 值 / Value |
| --- | --- |
| 画布 / Canvas | `24 x 24`（`viewBox="0 0 24 24"`） |
| 安全区 / Live area | `20 x 20`，四周留 2 单位 |
| 描边 / Stroke | `1.75`（`ICON_STROKE`），比 lucide 的 `2` 细，在 14-20px 常用尺寸下更锐利 |
| 端点 / Caps | `round` |
| 拐角 / Joins | `round`（切角由路径几何实现，不靠 join 圆滑） |
| 颜色 / Color | `currentColor`，随 Fluent 2 token 与明暗主题自动变化 |

## 三条造型规则 / Three shape rules

1. **容器形用 45 度切角，不用圆角。**
   盾牌、芯片、文件、机箱、回收箱、文件夹、面板——凡是「装东西」的形状，四角切 45 度斜边。
   切角尺寸约为该形宽度的 9%，最小 1.2 单位。这是整套图标最容易辨认的特征，也是与 Fluent 2 / lucide
   全圆角语言的分界线。
   **Container shapes use 45-degree chamfers, never rounded corners.** Shield, die, file, chassis, bin,
   folder, panel — anything that *contains* something gets its corners cut at 45 degrees, sized at roughly
   9% of the shape's width with a 1.2-unit floor.

2. **动作形保持开放笔画。**
   勾、叉、加号、减号、箭头、波形——表示「做一件事」的图标不封闭成形状，用圆头收尾。
   容器是硬件，动作是操作，两者在视觉上就该分开。
   **Action marks stay open strokes.** Check, cross, plus, minus, arrow, waveform — glyphs that mean
   *do a thing* are never closed into a container. Containers are hardware; actions are operations.

3. **启停主控用实心。**
   `Play` / `Pause` 是引擎与扫描的主控开关，用实心形与周围轮廓图标拉开层级；其余全部为轮廓。
   **Start/stop primaries are solid.** `Play` / `Pause` drive the engine and the scanner, so they carry
   solid weight against the outline set. Everything else is outline.

## 母题 / Motifs

- `SHIELD` — 六边切面护甲。`Shield` / `ShieldCheck` / `ShieldAlert` / `ShieldOff` 共用同一条外轮廓，
  只换内部标记，保证四个状态在同一位置读出差异。
  One shield outline shared by all four states; only the inner mark changes.
- `DIE` — 切角方形晶粒，对应产品名里的「芯」，用于 `Cpu`。
  The chamfered die behind the product name, used in `Cpu`.
- 取景角标 / framing brackets — 四个 L 形角标，同时用于 `Maximize2`，把「检出取景」的语义带进窗口控制。

## 新增图标 / Adding a glyph

1. 在 `glyphs.tsx` 对应分区里用 `createIcon(name, nodes)` 声明，节点用 `p` / `pf` / `c` / `dot` 四个助手。
2. 坐标写到小数点后一位，遵守上面三条规则；斜线只用 45 度。
3. 在 `index.ts` 的分区里补上导出。
4. 用 `node scripts/check-icons.mjs` 校验几何（超出安全区、非法路径、缺失导出会报错）。

## 文件 / Files

| 文件 / File | 职责 / Responsibility |
| --- | --- |
| `createIcon.tsx` | 图标工厂、`IconProps`、规范常量 / factory, props, spec constants |
| `glyphs.tsx` | 40 个图标的路径声明 / path declarations for all 40 glyphs |
| `index.ts` | 统一导出 / barrel export |

## 接口兼容 / API compatibility

props 与 `lucide-react` 一致（`size` / `color` / `className` / `strokeWidth` 以及任意 SVG 属性），
迁移时调用点只改导入来源：

Props match `lucide-react` (`size` / `color` / `className` / `strokeWidth` plus any SVG attribute), so
migration only changes the import source:

```diff
-import { Shield, ShieldCheck } from 'lucide-react'
+import { Shield, ShieldCheck } from './icons'
```
