/**
 * 安芯图标几何校验
 * AnXin icon geometry check
 *
 * 校验 src/components/icons/glyphs.tsx 里每个图标的路径几何是否符合 README.md 的规范：
 * 坐标落在画布内、路径命令合法、导出与 index.ts 一致、调用点没有残留第三方图标导入。
 * Validates that every glyph in src/components/icons/glyphs.tsx follows the spec in README.md:
 * coordinates stay inside the canvas, path commands are well-formed, exports match index.ts,
 * and no call site still imports the third-party icon set.
 *
 * 用法 / Usage: node scripts/check-icons.mjs
 * 退出码 / Exit code: 0 通过 / pass, 1 存在问题 / issues found
 */
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const ICONS_DIR = join(ROOT, 'src', 'components', 'icons')
const GRID = 24
const STROKE = 1.75
/** 画布外允许的溢出量，等于半个描边宽度 / Allowed bleed, equal to half the stroke width */
const BLEED = STROKE / 2

const problems = []
const fail = (msg) => problems.push(msg)

/* ---------- 1. 解析 glyphs.tsx / Parse glyphs.tsx ---------- */

const glyphsSource = readFileSync(join(ICONS_DIR, 'glyphs.tsx'), 'utf8')

/** 展开 SHIELD / DIE 等共享常量 / Expand shared constants such as SHIELD and DIE */
const constants = new Map()
for (const m of glyphsSource.matchAll(/^const ([A-Z_]+) = '([^']+)'$/gm)) {
  constants.set(m[1], m[2])
}

const icons = new Map()

// 行内声明：createIcon('Name', [ ...nodes ])
// Inline declaration: createIcon('Name', [ ...nodes ])
for (const m of glyphsSource.matchAll(
  /export const (\w+) = createIcon\(\s*'(\w+)',\s*\[([\s\S]*?)\]\s*,?\s*\)/g,
)) {
  const [, exportName, displayName, body] = m
  if (exportName !== displayName) {
    fail(`${exportName}: displayName 为 '${displayName}'，与导出名不一致`)
  }
  icons.set(exportName, body)
}

// 复用共享数组声明：createIcon('Name', SHARED_ARRAY)
// Shared-array declaration: createIcon('Name', SHARED_ARRAY)
for (const m of glyphsSource.matchAll(
  /export const (\w+) = createIcon\(\s*'(\w+)',\s*([A-Z_]+)\s*\)/g,
)) {
  const [, exportName, displayName, arrayName] = m
  if (exportName !== displayName) {
    fail(`${exportName}: displayName 为 '${displayName}'，与导出名不一致`)
  }
  const arr = glyphsSource.match(new RegExp(`const ${arrayName} = \\[([\\s\\S]*?)\\n\\]`))
  if (!arr) {
    fail(`${exportName}: 找不到共享节点数组 ${arrayName}`)
    continue
  }
  icons.set(exportName, arr[1])
}

if (icons.size === 0) fail('未从 glyphs.tsx 解析出任何图标')

/* ---------- 2. 校验路径几何 / Validate path geometry ---------- */

/** SVG 路径允许的命令 / Path commands the set is allowed to use */
const ALLOWED_COMMANDS = /^[MLHVACZmlhvacz\s\-.,0-9]+$/

/**
 * 抽取路径中的坐标点。
 * 只取 M/L/C/A 的绝对坐标对以及 H/V 的单值，用于判断是否越界。
 * Extracts coordinates from a path, enough to bound-check the glyph.
 */
function extractPoints(d) {
  const points = []
  const tokens = d.match(/[MLHVACZmlhvacz]|-?\d*\.?\d+/g) || []
  let cmd = null
  let cursor = { x: 0, y: 0 }
  let i = 0
  const nextNum = () => Number(tokens[i++])
  while (i < tokens.length) {
    const token = tokens[i]
    if (/[MLHVACZmlhvacz]/.test(token)) {
      cmd = token
      i++
      if (cmd === 'Z' || cmd === 'z') continue
      continue
    }
    switch (cmd) {
      case 'M':
      case 'L': {
        cursor = { x: nextNum(), y: nextNum() }
        points.push(cursor)
        break
      }
      case 'H': {
        cursor = { x: nextNum(), y: cursor.y }
        points.push(cursor)
        break
      }
      case 'V': {
        cursor = { x: cursor.x, y: nextNum() }
        points.push(cursor)
        break
      }
      case 'C': {
        nextNum(); nextNum(); nextNum(); nextNum()
        cursor = { x: nextNum(), y: nextNum() }
        points.push(cursor)
        break
      }
      case 'A': {
        nextNum(); nextNum(); nextNum(); nextNum(); nextNum()
        cursor = { x: nextNum(), y: nextNum() }
        points.push(cursor)
        break
      }
      default:
        i++
    }
  }
  return points
}

for (const [name, body] of icons) {
  const paths = [...body.matchAll(/\bpf?\(\s*'([^']+)'/g)].map((m) => m[1])
  const consts = [...body.matchAll(/\bpf?\(\s*([A-Z_]+)\s*\)/g)].map((m) => constants.get(m[1]))
  // dot() 的半径可省略，默认与 createIcon.tsx 中的默认值一致
  // dot() may omit its radius; fall back to the same default as createIcon.tsx
  const DOT_DEFAULT_RADIUS = 0.95
  const circles = [...body.matchAll(/\b(c|dot)\(([^)]*)\)/g)].map((m) => {
    const args = m[2].split(',').map((n) => Number(n.trim()))
    if (m[1] === 'dot' && args.length === 2) args.push(DOT_DEFAULT_RADIUS)
    return args
  })

  const allPaths = [...paths, ...consts].filter(Boolean)
  if (allPaths.length === 0 && circles.length === 0) {
    fail(`${name}: 未解析出任何图形节点`)
    continue
  }

  for (const d of allPaths) {
    if (!ALLOWED_COMMANDS.test(d)) {
      fail(`${name}: 路径含非法字符 -> ${d.slice(0, 40)}`)
      continue
    }
    for (const pt of extractPoints(d)) {
      if (!Number.isFinite(pt.x) || !Number.isFinite(pt.y)) {
        fail(`${name}: 路径存在无效坐标 -> ${d.slice(0, 40)}`)
        break
      }
      if (
        pt.x < -BLEED ||
        pt.y < -BLEED ||
        pt.x > GRID + BLEED ||
        pt.y > GRID + BLEED
      ) {
        fail(`${name}: 坐标 (${pt.x}, ${pt.y}) 超出 24x24 画布`)
      }
    }
  }

  for (const [cx, cy, r] of circles) {
    if (![cx, cy, r].every(Number.isFinite)) {
      fail(`${name}: 圆参数无效 (${cx}, ${cy}, ${r})`)
      continue
    }
    if (cx - r < -BLEED || cy - r < -BLEED || cx + r > GRID + BLEED || cy + r > GRID + BLEED) {
      fail(`${name}: 圆 (${cx}, ${cy}, r=${r}) 超出 24x24 画布`)
    }
  }
}

/* ---------- 3. 校验导出一致性 / Validate barrel exports ---------- */

const indexSource = readFileSync(join(ICONS_DIR, 'index.ts'), 'utf8')
const exportBlock = indexSource.match(/export \{([\s\S]*?)\} from '\.\/glyphs'/)
if (!exportBlock) {
  fail("index.ts 缺少 from './glyphs' 的导出块")
} else {
  const exported = new Set(
    exportBlock[1]
      .split('\n')
      .map((line) => line.replace(/\/\/.*$/, '').trim().replace(/,$/, ''))
      .filter((line) => /^\w+$/.test(line)),
  )
  for (const name of icons.keys()) {
    if (!exported.has(name)) fail(`index.ts 未导出图标 ${name}`)
  }
  for (const name of exported) {
    if (!icons.has(name)) fail(`index.ts 导出了不存在的图标 ${name}`)
  }
}

/* ---------- 4. 校验调用点无第三方图标残留 / No leftover third-party imports ---------- */

function walk(dir) {
  const out = []
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry)
    if (statSync(full).isDirectory()) out.push(...walk(full))
    else if (/\.tsx?$/.test(entry)) out.push(full)
  }
  return out
}

for (const file of walk(join(ROOT, 'src'))) {
  const source = readFileSync(file, 'utf8')
  if (source.includes("from 'lucide-react'")) {
    fail(`${file.slice(ROOT.length + 1)}: 仍在从 lucide-react 导入图标`)
  }
}

/* ---------- 输出 / Report ---------- */

if (problems.length > 0) {
  console.error(`图标校验失败，共 ${problems.length} 处问题:`)
  for (const problem of problems) console.error(`  - ${problem}`)
  process.exit(1)
}

console.log(`图标校验通过：${icons.size} 个图标，几何、导出与调用点均符合规范。`)
