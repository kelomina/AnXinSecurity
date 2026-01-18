# ETW 匹配规则编写指南

本文档说明如何编写 `config/etw_match_rules.json` 中的规则，以自定义 AnXin Security 的拦截与审计行为。

## 规则文件结构

规则文件是一个 JSON 数组，每个元素代表一条检测规则。

```json
[
  {
    "ruleId": "Process-Block-Cmd",
    "threatType": "SuspiciousExecution",
    "severity": 4,
    "recommendAction": "block",
    "provider": "Process",
    "op": "ProcessStart",
    "targetContains": ["cmd.exe", "powershell.exe"],
    "targetPatterns": ["*\\Temp\\*.exe"]
  }
]
```

## 字段详解

### 基础元数据

| 字段名 | 类型 | 必填 | 说明 |
| :--- | :--- | :--- | :--- |
| `ruleId` | string | 是 | 规则唯一标识符（如 `R-001`）。 |
| `threatType` | string | 否 | 威胁类型分类（如 `Ransomware`, `Spyware`）。默认同 `ruleId`。 |
| `severity` | number | 否 | 严重等级（1-5），5 为最高危。默认为 3。 |
| `recommendAction` | string | 否 | 命中后的建议动作：`block` (拦截), `monitor` (仅记录)。默认为 `block`。 |

### 匹配条件

以下条件均为“逻辑或”关系（只要满足任意一个条件即视为命中），但同一字段内的数组元素也是“逻辑或”。

| 字段名 | 类型 | 说明 | 示例 |
| :--- | :--- | :--- | :--- |
| `provider` | string | **必填** | 事件来源：`Process`, `File`, `Registry`, `Network`。 |
| `op` | string | **必填** | 操作类型：`ProcessStart`, `FileCreate`, `RegSetValue` 等。 |
| `targetContains` | array | 目标路径包含指定子串（不区分大小写）。 | `["cmd.exe"]` |
| `targetPrefix` | array | 目标路径以指定字符串开头。 | `["C:\\Windows\\System32"]` |
| `targetPatterns` | array | **(新增)** 目标路径通配符匹配（支持 `*` 和 `?`）。 | `["*\\Temp\\*.exe", "*.vbs"]` |

### 高级时间窗口匹配

用于检测“在一定时间内发生了特定序列的操作”。

| 字段名 | 类型 | 说明 |
| :--- | :--- | :--- |
| `windowMs` | number | 时间窗口大小（毫秒）。若为 0 则不启用时间窗口逻辑。 |
| `requiredOps` | array | 在当前事件发生前 `windowMs` 毫秒内，必须已发生的先决事件。 |

**requiredOps 结构：**

```json
"requiredOps": [
  { "provider": "File", "op": "FileCreate" }
]
```

## 匹配逻辑说明

1. **基本匹配**：引擎首先检查 `provider` 和 `op` 是否一致。
2. **路径匹配**：
   - 检查 `targetPrefix`：是否以某前缀开头。
   - 检查 `targetContains`：是否包含某子串。
   - 检查 `targetPatterns`：是否符合通配符模式（使用 Windows `PathMatchSpec` 标准）。
   - 若以上三个数组均为空，则视为“无路径过滤”（即匹配该 op 的所有事件）。
   - 若以上数组不为空，则只要命中其中**任意一条**即视为路径匹配成功。
3. **窗口匹配**：若定义了 `windowMs`，引擎会检查该 PID 在过去 `windowMs` 毫秒内是否触发过 `requiredOps` 中定义的事件。

## 示例

### 1. 拦截 Temp 目录下的所有 EXE 运行

```json
{
  "ruleId": "Block-Temp-Exe",
  "provider": "Process",
  "op": "ProcessStart",
  "targetPatterns": [
    "*\\AppData\\Local\\Temp\\*.exe",
    "C:\\Windows\\Temp\\*.exe"
  ],
  "recommendAction": "block"
}
```

### 2. 拦截特定扩展名的文件创建

```json
{
  "ruleId": "Anti-Ransomware-Extension",
  "provider": "File",
  "op": "FileCreate",
  "targetPatterns": ["*.encrypted", "*.locky"],
  "severity": 5
}
```
