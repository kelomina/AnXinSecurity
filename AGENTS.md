# Project Constraints

## Scope

- `AnXinSecurity` 是一款基于 **Tauri 2.0** 的 **Windows 安全防护桌面应用**。
- 真实存在的技术栈：
  - **前端**：`React 18`、`TypeScript`、`Vite`、`Zustand`、`Fluent UI React v9`、`Tauri JS API`
  - **后端**：`Rust 2021`、`Tauri 2.0`、`Tokio`、`SQLx(SQLite)`、`Windows API`
  - **原生模块**：3 个内核驱动（`AnXinProcProtect` 进程保护、`AnXinFileProtect` 文件保护、`AnXinNetFilter` WFP 网络防火墙）+ 用户态 `file_hook` DLL（Detours）
  - **配置**：`config/app.json`、`config/scan_rules.json`、`config/etw_match_rules.json`、`config/firewall_rules.json`、`config/i18n/*.json`
- 真实存在的能力：
  - 文件扫描、ETW 行为监控、进程/文件监控
  - 隔离区、进程拦截、启动快照、信任验证（含证书吊销检查）
  - 网络防火墙（WFP 驱动 + 用户态规则编排）
  - 允许列表 / 排除项、日志、错误追踪、审计
  - IPC 服务进程通信、Windows 服务模式、权限提升通道
  - 主题切换与中英双语界面

## Forbidden Actions

- **不确定先搜/先问/先实验**，不得凭假设写代码。
- 不得新增平行实现，或绕过 `commands -> services -> models/utils` 分层。
- 不得沿用 **Tauri 1.0 allowlist**；所有权限声明必须在 `src-tauri/capabilities/`（或项目既定目录）维护。
- 新增 **Tauri 插件**、`invoke` 命令、事件监听或其他 API 调用时，必须同步更新 capability 配置。
- 不得硬编码端口、路径、规则、功能开关、密钥或其他环境值。
- 不得把运行时状态写回仓库配置，尤其是 allowlist、exclusions、缓存、数据库和隔离索引。
- 不得删除测试、放宽断言、吞异常、伪造结果，或在代码 / 测试 / 配置 / 日志中泄露敏感信息。
- **禁止自动分析转储文件（dump）**：不得自动调用 `kd` / `cdb` / `WinDbg` 分析内核转储。自动符号下载与分析会占满内存，导致宿主机卡死甚至崩溃（2026-08 实测复现）。需要分析 dump 时，只负责把转储文件导出到用户桌面并通知用户手动分析（见 `## Crash Dump Handling`）。
- 不得修改公共命令、配置键、数据库结构、事件名或外部接口，除非已确认兼容方案。
- 不得随意新增依赖、切换技术栈，或降低受保护进程、自身进程、隔离区和安全擦除边界。

## Crash Dump Handling

- 遇到内核蓝屏转储（`MEMORY.DMP` / `Minidump\*.dmp`）时，agent **禁止**自动运行调试器（kd/cdb/WinDbg）分析。
- 正确流程：
  1. 把转储文件从来宾 / 目标机导出到 `C:\Users\Saika\Desktop\`（保留原始文件名）。
  2. 通知用户手动分析；用户会在调试器里自行定位故障栈。
- 原因：kd/cdb 分析转储会触发大体积符号下载与高内存占用，2026-08 实测导致宿主机内存溢出、系统崩溃卡死。

## VM 自动化来宾重启

- 本项目 Hyper-V VM（`病毒测试`，VMId `7b66415c-52cb-468e-b9bd-368746f42863`）自动化流程中的**来宾重启一律视为已获批准**，不得逐次询问用户。
- 重启前在回复中说明"将重启 guest"及重启目的即可，随后直接执行 `shutdown /r` 或通过脚本触发。
- 适用范围：驱动部署后的加载重启、卸载收口验证（T10）的重启、自保测试相关的重启等所有 vm-automation 脚本触发的 guest 重启。
- 用户于 2026-08-13 明确授权：该 VM 的来宾重启默认允许，后续不再询问。

## VM 测试检查点纪律（2026-08-23 实测教训固化）

- **测试专用初始化检查点是一切的基础**：检查点本身必须是「配置好一切」的就绪状态——OS 正常、PS Direct 凭据（`test`）可用、网络/NAT 就绪、依赖组件齐备；进入该检查点后不遗留任何上轮测试的安装、驱动、样本或脏配置。
- **任何安装/运行实测开始前**：必须先确认该初始化检查点存在且可用，然后从它恢复出发；禁止在未知或脏状态上直接开测。若检查点缺失或损坏，先重建检查点再测试，不得跳过。
- **测试完成之后一定要还原到该检查点**：收尾时恢复检查点，保证下一轮测试从同样的干净基础出发；还原后应抽查关键项（服务/驱动/安装目录不存在、凭据可连）确认还原成功。
- **检查点操作红线**：
  - 严禁删除或移动检查点引用的差异盘（.avhdx）文件；清理磁盘前必须先确认快照树不再需要或已合并。
  - 一台 VM 的系统盘只能被一个 VM 配置引用；发现同名克隆/共享盘配置立即纠正。
  - 恢复检查点前 VM 必须完全关机（Saved 状态需先丢弃保存状态），避免半恢复导致的断链与错挂盘。
- 背景：2026-08-23 三进程实测中因快照链中间差异盘被删、双 VM 共盘错配，导致基线不可恢复、凭据失配，实测被迫中断重建环境。

## Mandatory Standards

- **始终使用中文回复。**
- **修改前先搜**入口、调用方、被调用方、测试、配置和文档。
- **先理解，再修改；先复用，再新增；先兼容，再扩展。**
- **分层职责固定**：
  - `commands` 只校验和透传
  - `services` 编排业务
  - `models` 只放数据
  - `utils` 只放纯工具
  - 前端 `api/stores/components` 分别只做 invoke 封装、状态 / 业务管理、渲染交互
- **统一错误处理**：后端用 `Result` 向上传递可恢复错误；命令层转成用户可读但不泄露敏感信息的消息；前端只负责展示和必要降级。
- **统一并发模式**：Tokio、ETW、进程监控和文件监控必须是可取消、可重复启动、幂等的长任务；共享状态优先用 `Arc`、`Mutex`、`tokio::sync`，停止时必须有明确停止信号和清理路径。
- **统一日志规范**：`info / warn / error / debug` 分级明确，日志应保持结构化或半结构化，至少带模块前缀、动作和对象标识；不得打印密钥、完整文件内容或原始用户隐私。
- **所有用户可见文本必须走 i18n**，不得在前端组件或 Rust 代码中硬编码中英文；新增文案必须同时提供 `zh-CN` 和 `en`，并保持键名一致。
- **SQLx + SQLite** 的表结构变更必须走迁移管理，先加迁移再改代码，不得靠运行时代码偷偷改库结构。
- **构建与发布分层**：开发用 `npm run dev` / `npm run dev:frontend`，生产用 `npm run build`；改打包、安装器、资源路径或 manifest 时，要同步确认 Tauri 构建链路与 Windows 发布行为。
- **开发服务器超时下限**：运行 `npm run dev` 时，命令超时时间必须设置为至少 120 秒，不得用低于 120 秒的超时结果判断开发服务器启动失败。
- 任何核心逻辑变更后，尽可能运行 `npm run lint`、`npm run typecheck`、`npm run test`、`cargo check`、`cargo test`。
- 静态配置优先放 `config/`；运行时用户状态放 APPDATA 或仓库外忽略目录；文档与代码冲突时，以代码和可验证产物为准。
- **持续运行文档必读必更**：涉及启动快照、扫描、监控、拦截、信任验证、配置、i18n 或测试收口前，先读 `docs/continuous-running.md`；相关变更后必须同步更新该文档。

## Architecture Rules

- **前端入口**：`src/main.tsx`、`src/App.tsx`
- **前端页面**：`OverviewPage`、`ScanPage`、`QuarantinePage`、`BehaviorPage`、`BehaviorLifecyclePage`、`FirewallPage`、`SettingsPage`
- **前端全局组件**：`TitleBar`、`Sidebar`、`Toast`、`SplashScreen`、`InterceptionModal`、`InterceptionWindowApp`、`TrayExitPrompt`、`ErrorBoundary`
- **前端状态仓库**：`configStore`、`scannerStore`、`quarantineStore`、`firewallStore`、`themeStore`、`i18nStore`、`toastStore`
- **前端 API**：扫描、扫描规则、行为、进程、隔离区、配置、允许列表、排除项、系统、日志、文件、错误追踪、风险分析、防火墙、权限、快照、开发设置、i18n
- **Rust 分层**（2026-08-23 三进程拆分后）：共享逻辑在 `src-tauri/crates/anxin-core/src/` 的 `commands/`（24 模块）、`services/`、`models/`、`utils/`；新增能力优先挂到已有模块。三个薄壳 bin：`AnXinSecurity.exe`（Main，仅主界面 UI + 安装期驱动 CLI，关闭即退出）、`AnXinTray.exe`（托盘 + 拦截弹窗 + 退出确认 + IPC bridge）、`AnXinService.exe`（完整后端，Windows Service / `--foreground`）。方案权威见 `docs/three-process-split.md`
- **进程拓扑**：SCM 启动 AnXinService → 跨会话拉起 AnXinTray → 首启拉起 AnXinSecurity Main；托盘「退出」经 IPC `shutdown_service` 停服并全 GUI 退出；UI 进程不内嵌任何防护组件（standalone 已废弃，提权无服务时引导 foreground service）
- **现有命令 / 服务**：配置、扫描、行为（v1+v2）、隔离、排除 / 允许、托盘、进程、引擎、信任、拦截、风险、快照、开发设置、系统、i18n、错误追踪、日志、文件系统、文件钩子、防火墙、权限、IPC 桥接
- **原生模块**：
  - `native/driver/`（AnXinProcProtect.sys）— 进程/线程/注册表保护，WDM + Ob/Ps/Cm 回调
  - `native/file_protect/`（AnXinFileProtect.sys）— 关键文件保护，文件系统微过滤器
  - `native/net_filter/`（AnXinNetFilter.sys）— WFP 网络防火墙 callout 驱动
  - `native/file_hook/`（用户态 DLL）— Detours 文件 API Hook 与注入检测链路
  - ETW、进程轮询、信任验证、风险评级已由 Rust 后端接管
- **配置职责**：`config/app.json` 管主配置，`scan_rules.json` 管快速扫描规则，`etw_match_rules.json` 管行为匹配规则，`firewall_rules.json` 管网络防火墙规则，`config/i18n/*.json` 管语言包
- **测试位置**：`tests/`（前端测试套件）和 `src-tauri/crates/anxin-core/tests/`（Rust 集成测试 18 文件 + common）；修改原生模块时补充对应 `native/*/tests`
- **通信边界**：前后端只通过 Tauri commands/events；功能开关关闭时，对应监控与采集逻辑必须真正停止，不能只关界面不关后台
- **服务模式**：由独立的 `AnXinService.exe --service` 以 Windows Service 运行（亦支持 `--foreground` 前台模式供调试/引导）；GUI 进程通过 IPC（命名管道）与服务进程通信

## Documentation Rules

- `docs/continuous-running.md` 是项目**进度文档**（值班交接本），记录当前安全链路状态、已验证命令、未完成风险和下一步优先级。
- **每轮任务开始时必须先读** `docs/continuous-running.md` 的「当前状态快照」与最新进度条目（文档头部置顶），确认已完成/进行中状态，避免重复劳动或踩已记录过的坑。
- 修改启动快照、进程 / 文件监控、扫描缓存、信任验证、证书吊销、拦截队列、运行时配置、i18n 或测试结论后，必须同步更新 `docs/continuous-running.md`。
- 文档必须区分“已验证状态”“计划 / 假设”“风险 / 待办”；没有实际运行的命令不得写成已通过。
- 文档与代码冲突时，以代码和可验证产物为准，同时更新文档消除冲突。
- `建议.md` 是临时性的剩余工作清单，其中列出的部分实现和未实现项应作为当前最高优先级的收口目标，尽快完成，不要长期挂起。
- 当 `建议.md` 中列出的内容全部完成，或已被正式废弃时，必须同步删除 `建议.md`，并移除本文件里这条关于 `建议.md` 的要求，避免保留过期约束。

## Security & Safety

- 任何文件、进程、网络、数据库、加密、命令执行和 **FFI** 逻辑都视为高风险，必须先做输入校验和边界检查。
- 路径、文件名、PID、规则内容、配置值都要防止路径穿越、命令注入、越权访问和误操作。
- 隔离区、密钥、运行时 allowlist / exclusions 等敏感状态必须使用既有加密和 APPDATA 策略；生产密钥优先用 **Windows DPAPI**。
- 跨 **FFI** 边界（Rust 调用 C++ DLL）传数据时，必须校验指针有效性、字符串编码（UTF-16 / UTF-8）和生命周期；不得交叉释放 Rust / C++ 各自分配的内存。
- 关键安全动作必须 **fail-closed**；受保护系统进程和自身进程必须禁止操作；安全擦除、拦截、挂起、终止、恢复等边界不得放宽。
- 日志和错误信息只能输出必要诊断内容，不能泄露敏感信息；新增依赖、规则或接口前，要先评估攻击面、误报率和维护成本。

## Vulnerability Tracking

- `buglist.md` 是项目安全漏洞追踪文件，记录已发现的所有安全漏洞，需持续更新。
- **发现新漏洞时必须**：
  1. 在 `buglist.md` 中新增条目，按编号递增（VUL-NNN）
  2. 填写严重等级（Critical / High / Medium / Low）、漏洞类型、影响模块、状态（Open / Fixed / Accepted）
  3. 提供详细的漏洞描述、代码位置和攻击向量
  4. 更新漏洞索引表
- **修复漏洞时必须**：
  1. 在 `buglist.md` 对应条目中将状态改为 Fixed
  2. 记录修复日期和修复方式
- **修改安全相关代码前必须**：先阅读 `buglist.md`，确认修改不会引入新漏洞或影响已有漏洞的修复状态
- **漏洞严重等级定义**：
  - **Critical**：可被远程利用或导致系统完全沦陷（如任意代码执行、提权）
  - **High**：可被本地利用或导致安全防护绕过（如签名验证绕过、路径遍历）
  - **Medium**：可能导致信息泄露或安全功能降级（如密钥泄露、审计缺失）
  - **Low**：影响有限或利用条件苛刻（如配置残留、日志信息泄露）
- **当前已知漏洞摘要**（2026-08-24 与 `buglist.md` 核对，以该文件为准）：
  - 共 106 条（VUL-001 ~ VUL-108，编号有跳号），Fixed 55 / Open 50 / Accepted 1
  - Open 集中在 VUL-004~014、VUL-041、VUL-053~090 及 VUL-106~108（隔离擦除、路径遍历、capability 过宽、file_hook 注入器系列等）
  - 三进程拆分安全复查新增 **VUL-106**（Medium, Open）：IPC 客户端身份校验仅按镜像文件名白名单、无安装目录/签名比对；拆分将白名单扩至 anxin-tray.exe 后伪装面增大
  - Rust 依赖审计新增 **VUL-107**（Low, Accepted, cargo-audit 2026-08-23）：sqlx 0.7.4 RUSTSEC-2024-0363 为唯一 Windows 可达条目且仅用 SQLite 嵌入式驱动；quick-xml/rsa 经产物符号抽查确认不在 Windows 构建内（tauri Linux/macOS 跨平台链）；sqlx 0.8 迁移单独立项
  - VM 安装实测新增 **VUL-108**（High, Open, 2026-08-24）：ProcProtect 进程创建路径对受保护服务跨会话令牌干预降权（0x80070542），驱动运行时服务无法拉起用户会话 GUI；需驱动侧为服务→Tray 合法路径加豁免；launch_ui_process 已附带登录就绪轮询修复
  - 驱动相关 P0-P1（VUL-045 ~ VUL-052）与驱动 BSOD/BYOVD 审计（VUL-091 ~ VUL-094）已于 2026-07-30 全部修复
  - 驱动自保专项测试（2026-08-13 来宾实测）新增 VUL-096 ~ VUL-103 已全部修复：webview 子进程保护传播（VUL-096）、安装目录运行期文件保护（VUL-097）、服务键注册表保护 4/4（VUL-098）、SET_DIAG 授权校验（VUL-099）、进程名伪装授权校验（VUL-100）、卸载 .sys 清理（VUL-101，改用一次性 SYSTEM 计划任务删服务键 + PFRO 重启删除，T10 "卸载 + 重启一次全清"验证通过）、FpmQueryPaths 紧凑回复 + 超时守卫（VUL-102）、线程上下文句柄剥离（VUL-103）；VUL-104（ProcMon 缺 /INTEGRITYCHECK）、VUL-105（IPC 单线程被扫描阻塞 broken-pipe）均已修复
  - 修改本摘要时必须与 `buglist.md` 实际内容核对，不得凭记忆更新
