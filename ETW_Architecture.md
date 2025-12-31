# ETW (Event Tracing for Windows) 架构设计文档

## 1. 概述
本项目集成了 ETW (Event Tracing for Windows) 技术，用于实时监控系统的底层行为，包括进程创建、文件操作、注册表修改以及网络活动。ETW 是 Windows 提供的轻量级、高性能的事件跟踪机制，非常适合用于安全监控和行为分析。

## 2. 程序启动与初始化全流程

程序的启动过程调整为：UI 预备 -> 数据扫描（阻塞）-> 处理积压弹窗 -> 安全组件启动 -> 销毁 Splash -> 显示主界面。以下是详细流程：

1.  **单实例检查**：通过 `app.requestSingleInstanceLock()` 确保系统内只有一个程序实例在运行。
2.  **环境与配置初始化**：
    *   加载 `config/app.json` 配置文件。
    *   初始化多语言字典 (`loadI18n`)。
    *   加载本地 `winapi` 扩展。
3.  **UI 预准备**：
    *   **创建 Splash 窗口**：显示启动画面和加载状态。
    *   **创建主窗口 (隐藏)**：在后台初始化主界面，但不立即显示。
    *   **创建系统托盘**：初始化托盘图标和菜单。
4.  **数据同步与扫描 (关键阻塞环节)**：
    *   **PID 快照**：获取当前系统所有进程快照，用于后续初始化信任过滤器的 Seed。
    *   **拦截快照扫描**：对当前运行的进程进行模块签名和完整性校验。
    *   **必须等待扫描完成并确保结果返回后**，方可进入下一步。
5.  **处理积压拦截弹窗**：扫描期间积压的所有拦截任务从此阶段开始处理。
6.  **安全组件启动**：
    *   **行为分析器**：启动 `behavior_analyzer`。
    *   **ETW 工作线程启动**：启动 `etw_worker.js` 并进入监控状态。
    *   **后台安全引擎启动与健康检查**：检查并按需启动后台安全引擎 (`Axon_ml.exe`)，并完成健康检查确认可用。
7.  **销毁 Splash 窗口**。
8.  **主界面呈现**：调用 `win.show()` 最终显示主界面。

## 3. 核心组件架构

### 3.1 ETW 工作线程 (etw_worker.js)
为了确保主进程的响应速度，所有的 ETW 事件捕获和初步处理逻辑都运行在一个独立的 Worker 线程中。
- **低级 API 调用**: 使用 `koffi` 库通过 FFI 直接调用 Windows 系统库。
- **会话管理**: 负责 ETW 会话的生命周期管理。
- **数据解析**: 
  - 将原始二进制事件记录 (`EVENT_RECORD`) 解析为 JavaScript 对象。
  - **路径启发式解析**: 由于内核事件中的路径格式多样（如 `\Device\HarddiskVolume3\...`），系统实现了启发式算法 `pickBestPathCandidate` 来识别和转换最可能的路径。
  - **网络数据解析**: `parseNetworkUserDataHeuristic` 能够从原始字节流中提取本地/远程 IP 和端口。

### 3.2 信任过滤机制 (etw_trusted_pid_filter.js)
为了减少噪音并提高性能，系统实现了一个复杂的信任过滤机制。
- **动态信任 PID 集合**: 实时维护一个 `trusted` Set。
- **数字签名验证**: 集成 `winapi.verifyTrust`，对新启动的进程进行数字签名校验。
- **路径匹配**: 支持精确路径匹配和目录前缀匹配（如信任整个安装目录）。

### 3.3 主进程集成 (main.js)
主进程负责管理 ETW 工作线程，并处理其发送的消息。
- **Pid Snapshot**: 在 ETW 启动时，主进程会获取当前系统所有进程的快照并发送给 Worker，用于初始化信任过滤器。

## 4. 技术细节
- **FFI 引擎**: 选用 `koffi` 而非 `ffi-napi`，主要是基于其更优的性能表现和对现代 Node.js 版本的良好支持。
- **异步处理**: `ProcessTrace` 在 Worker 线程中以异步模式运行，允许 Worker 响应来自主进程的控制消息（如更新配置或停止会话）。

## 5. 配置参数说明 (config/app.json)

ETW 相关的配置位于 `etw` 根键下，以下是详细参数说明：

### 5.1 基础配置 (etw.*)
| 参数名 | 类型 | 说明 | 默认值 |
| :--- | :--- | :--- | :--- |
| `enabled` | Boolean | 是否启用 ETW 监控 | `true` |
| `sessionName` | String | ETW 会话的唯一名称 | `AnXinSecuritySession` |
| `userDataMaxBytes` | Number | 解析事件用户数据时的最大字节数 | `65536` |
| `stopTimeoutMs` | Number | 停止会话时的超时时间 | `2500` |
| `startRetries` | Number | 启动失败后的重试次数 | `2` |
| `retryDelayMs` | Number | 重试间隔（毫秒） | `150` |
| `resolveProcessName` | Boolean | 是否在 Worker 中解析进程名称 | `true` |

### 5.2 过滤器配置 (etw.filters.*)
#### 5.2.1 信任 PID 过滤 (etw.filters.trustedPid)
| 参数名 | 类型 | 说明 |
| :--- | :--- | :--- |
| `enabled` | Boolean | 是否启用信任 PID 过滤 |
| `applyToSnapshot` | Boolean | 是否对启动时的存量进程应用过滤 |
| `applyToNewProcesses` | Boolean | 是否对新启动的进程应用过滤 |
| `userTrustedPaths` | Array | 用户定义的受信路径列表（文件或目录） |
| `baseTrustedPids` | Array | 静态信任的 PID 列表（通常包含 0 和 4） |
| `extraTrustedPids` | Array | 额外的静态信任 PID |

#### 5.2.2 操作过滤 (skipOps)
针对不同 Provider，可以配置跳过特定的操作类型以减少数据量：
- `Registry.skipOps`: 默认跳过 `OpenKey`, `CloseKey`, `QueryKey` 等高频操作。
- `Process.skipOps`, `File.skipOps`, `Network.skipOps`: 可按需配置。

### 5.3 网络特定配置 (etw.network)
| 参数名 | 类型 | 说明 |
| :--- | :--- | :--- |
| `filterPrivateIps` | Boolean | 是否过滤内网 IP 通讯 |
| `skipLoopback` | Boolean | 是否跳过回环地址 (127.0.0.1) |

### 5.4 拦截与校验 (etw.interception)
| 参数名 | 类型 | 说明 |
| :--- | :--- | :--- |
| `snapshotVerifyOnEtwStart` | Boolean | ETW 启动时是否对所有进程进行模块完整性校验 |
| `snapshotTrustThreshold` | Number | 信任阈值 |
| `skipSystemDll` | Boolean | 校验时是否跳过系统签名 DLL |

## 6. 监控范围 (Providers)
- **Process**: `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716`
- **File**: `EDD08927-9CC4-4E65-B970-C2560FB5C289`
- **Registry**: `70EB4F03-C1DE-4F73-A051-33D13D5413BD`
- **Network**: `7DD42A49-5329-4832-8DFD-43D979153A88`
