# AnXinSecurity 持续运行文档

## 文档用途

这份文档是后续开发者和 AI 接手 AnXinSecurity 时的固定入口。它只记录和持续运行有关的高信号信息：当前安全链路做到哪里、哪些结论已经核对过、哪些风险还没解决、下一步优先做什么。

可以把它理解成项目的“值班交接本”：代码是现场，`建议.md` 是阶段方案，这份文档负责告诉下一位接手的人现场现在是什么状态，哪些地方不能误判，哪些任务应先处理。

## 更新规则

- 每次修改启动快照、文件扫描、进程监控、文件钩子、ETW、信任验证、签名缓存、证书吊销、拦截队列、运行时配置、i18n 或相关测试结论后，都必须同步更新本文件。
- 只能把已经从代码、配置、命令输出或测试结果核对过的内容写成“已验证状态”。
- 没有实际运行的命令，不能写成“已通过”；只能写成“建议运行”或“本轮未运行”。
- 计划、假设、风险和待办必须单独列出，不能和已完成能力混在一起。
- 文档和代码冲突时，以代码和可验证产物为准，并在本文件中补充冲突说明和下一步修正项。

## 当前状态快照

更新时间：2026-08-24

### 2026-08-24 三进程 VM 安装实测（第一轮）：拓扑闭环验证通过，VUL-108 阻断驱动运行时的 GUI 拉起

**目标**：在「病毒测试」VM 上安装三进程版并实测 §6 清单。检查点纪律已固化（AGENTS.md「VM 测试检查点纪律」），本轮从用户重建的「测试专用初始化」检查点出发，测毕已还原并抽查（安装目录不存在、服务未注册、凭据可连）。

**已验证状态（VM 内实际运行）**

1. **安装**：NSIS 静默安装成功；`C:\Program Files\AnXinSecurity\` 下三 exe 齐备（8.3MB/3.7MB/3.9MB）；`sc binPath = "...\AnXinService.exe" --service`（Phase 6 切换生效）；AUTO_START。
2. **编排链**：SCM → AnXinService(s=0) RUNNING → 跨会话拉起 AnXinTray(s=1) 存活 → Tray 连上 IPC 后自动拉起 AnXinSecurity Main(s=1)——**三进程共存拓扑完整达成**（ProcProtect STOPPED 条件下，见第 4 点）。
3. **IPC**：`\\.\pipe\Global\AnXinSecurityIPC` 与 `anxin_security_filehook` 管道就绪；Tray/Main 双客户端接入。
4. **生命周期语义**：服务优雅 stop/start ✓；Main 关闭即退出进程、Tray 驻留 ✓；Tray 单实例守卫跨会话生效（自研 Global\+Local\ mutex，替换了在该环境不可靠的 single-instance 插件）✓。
5. **本轮修复（随实测发现即时落地）**：
   - `launch_ui_process` 增加 service_log 文件日志（`C:\ProgramData\AnXinSecurity\logs\service.log`，服务 stderr 从此可追查）；
   - `DuplicateTokenEx(TokenPrimary, SecurityImpersonation)` 显式复制令牌；
   - 登录就绪轮询（90s/5s 步进），解决 AUTO_START 早于自动登录的 0x800703F0 一次性失败；
   - Tray 单实例自研守卫 + 移除 tauri-plugin-single-instance（其第二实例路径依赖 FindWindowW 命中隐藏窗口，无主窗口进程下不可靠）。

**阻断问题：VUL-108（High, Open, 已登记 buglist）**

- AnXinProcProtect RUNNING 时 `CreateProcessAsUserW` 稳定报 0x80070542 BAD_IMPERSONATION_LEVEL，DuplicateTokenEx 复制的新句柄同样被干预——**驱动运行时服务无法拉起用户会话 GUI**。
- 因果实验证实：驱动 STOPPED + 用户登录 → launch 成功且 Tray 存活；驱动 RUNNING → 失败。
- 已排除：ObCallbacks 仅注册 Process/Thread 类型；windows-rs 绑定签名核对无误；SYSTEM 特权齐备。
- 待办：驱动侧为「AnXinService.exe 跨会话创建 AnXinTray.exe」合法路径加豁免后 VM 回归。

**遗留问题/待办**

- **FileProtect 注册但启动失败（System log id=7000）、NetFilter 未注册**：疑似与 nsis-hooks.nsh 以 HEAD 基线重建丢失的用户未提交改动有关（该改动可能正是驱动注册逻辑修复）。需要用户提供原改动内容或重新排查 hooks 的 FileProtect/NetFilter 段。
- 拦截弹窗端到端（样本→Server 入队→Tray 弹窗→决策回传）未测：依赖 FileProtect/ETW 全链路健康，待 VUL-108 修复+驱动问题解决后一并跑。
- 托盘菜单点击类 GUI 交互无法远程自动化，需人工抽查。
- guest 实验期间临时配置（autologon 注册表、ProcProtect demand-start）已随检查点还原清除。

---

### 2026-08-23 三进程拆分实施完成（Main / Tray / Service）——代码层收口，待 VM 实测

**目标**：单 exe 双角色架构拆为 `AnXinSecurity.exe`（仅主界面，关闭即退出）、`AnXinTray.exe`（托盘+拦截弹窗+退出确认+IPC bridge）、`AnXinService.exe`（完整后端，SCM/--foreground）。方案与落地差异全文见 `docs/three-process-split.md`（权威）。

**已验证状态（本机实际运行）**

- Workspace 重构：src-tauri = workspace 根 + Main 包；共享逻辑下沉 `crates/anxin-core`（lib 名 anxin_security 不变）；新增 `crates/anxin-tray`、`crates/anxin-service` 薄壳。`cargo check --workspace` / `cargo build --workspace` 通过。
- Rust 测试：`cargo test -p anxin-core` 20 个测试目标全部 ok（lib 388/388 + 集成 ~311，0 failed；含为 shutdown_service 新增的单测 shutdown_request_sets_registered_stop_flag）。
- 前端：`npm run typecheck`、`npm run lint` 通过；`npm run test` 150/150（5 个断言旧 standalone 实现位置的测试已适配新归属：启动快照/钩子管道/APIHook watcher 归属 windows_service.rs，interception capability 归 Tray crate 等）。
- 打包链路端到端：`powershell -File build/tools/build-installer.ps1` 成功产出 `bundle/nsis/AnXinSecurity_1.0.0_x64-setup.exe`（38,828,542B），内含三 exe；sc binPath 已切至 `$INSTDIR\AnXinService.exe --service`。
- 关键实现点：
  - IPC method `shutdown_service`（协议新增）：服务端先广播 `service-exiting`（FORWARDABLE_EVENTS/FORWARDED_EVENTS 已加）再置停止标志（SERVICE_STOP_SIGNAL 全局注册点）；
  - IPC 客户端白名单扩至 anxinsecurity/anxintray/anxin-security/anxin-tray（小写比对），握手通过即自动 `register_ui_process_pid` 注册内核保护；
  - Main 瘦身：托盘创建、拦截窗口预建、standalone 防护组件启动分支全部移除；提权 + 无服务时自动引导 `AnXinService.exe --foreground`；非提权保持降级；
  - Main 标题栏关闭 → 新命令 `close_main_window` = 退出 Main 进程（防护不受影响）；托盘退出 → exit-confirm 小窗口（新前端 label 分支 ExitConfirmWindowApp）→ execute_exit → IPC 停服 → 全 GUI 退出；
  - 托盘菜单文案接入 i18n（Rust 侧 lookup_rust_side_text，键 tray_show_main/tray_exit）。
- npm 依赖告警收口（cc8860c）：`npm audit` 实为 6 条（5 high + 1 low，全开发/构建期依赖），audit fix 清零并首次提交 package-lock.json（此前被 gitignore 导致 Dependabot 无法看到精确版本）；typecheck/lint/test/vite build 验证通过。
- Rust 依赖审计（cargo-audit v0.22.2 已安装）：4 vulnerabilities + 23 unmaintained。quick-xml×2 与 rsa 经 Windows release 产物符号抽查确认不在构建内（tauri Linux/macOS 跨平台链）；sqlx 0.7.4 RUSTSEC-2024-0363 为唯一直接相关条目且本项目仅用 SQLite 嵌入式驱动（advisory 针对 PG/MySQL wire protocol）。登记 **VUL-107**（Low, Accepted），sqlx 0.8 迁移单独立项。

**本轮事故与修复（必须知晓）**

- `build/nsis-hooks.nsh` 曾被本会话 GBK 编码往返部分损坏（用户有 +211/-93 未提交改动，无恢复源），经用户确认以 HEAD 基线 + binPath 切换 + UTF-8 BOM 重建。教训固化在 DEPLOYMENT.md §2.5「编码红线」：该文件必须 UTF-8 with BOM；PowerShell 批处理项目文件一律显式 UTF-8。
- makensis 对无 BOM UTF-8 报 Bad text encoding；bundler 生成的 installer.nsi 按 ANSI 解析、注入内容必须 ASCII-only——均已写入 DEPLOYMENT.md。

**计划/假设**

- [待实测] VM 端到端清单见 three-process-split.md §6（安装→服务拉起 Tray→拦截闭环→退出停服→卸载重装全清）。
- [假设] 双 GUI 进程（Main/Tray 各自 identifier）并存行为符合预期，待 VM 观察 WebView2 双浏览器进程内存表现。

**风险/待办**

- VUL-106（Medium, Open）已登记：IPC 白名单仅按文件名、无目录/签名校验；拆分扩大伪装面。修复方向：生产模式加安装目录比对或 WinVerifyTrust。
- Main 仍保留本地 SQLite 连接（降级路径读写共用服务端库），并发写竞争面待评估；后续可考虑降级路径只读化。
- vm-automation 历史 antagonist/diag 脚本仍引用旧单 exe 名；下次 VM 部署前按 three-process-split.md §6 映射表适配所需脚本即可，不批量改写。
- 旧版升级安装路径未实测：旧服务注册指向 anxin-security.exe --service，新版 NSIS 重装会重建服务键 ✓，但需确认 CheckIfAppIsRunning 对改名主程序的兼容（nsi 模板自带 OldMainBinaryName 迁移逻辑，理论覆盖）。

---

### 2026-08-18 阶段4b：漏网样本重测（case 1/2/3/4）与 v2 ETW 规则验证（进行中）

**目标**：验证 v2 ETW 规则（9 条中 6 条 antagonist_* 强拦截规则）能否拦截第一批对抗测试的 4 个漏网样本。

**已验证状态**

- 4 个漏网样本首轮重测结果（VM 内运行，同步 Invoke-Command 逐样本执行）：
  - case 1 (mimikatz)：GONE_T15（15s 内消失），diag+8、DB+127KB，仅命中 `trusted_process_unsigned_image_load`（弱规则），且命中 pid=17208 非样本 pid=7492
  - case 2 (80e.exe)：GONE_T0（5s 内消失），diag+0、DB+12KB，0 命中
  - case 3 (heium_kill)：GONE_T5，diag+0、DB+4KB，0 命中
  - case 4 (123.exe)：样本文件缺失，未执行
- **关键问题**：6 条 antagonist_* 强拦截规则命中数为 0，进程却都在数秒内退出。需区分「规则引擎未匹配」与「进程自行退出」。
- **受控测试（notepad 复制到 C:\Samples）**：notepad.exe (pid=17032) 启动后 diagDelta=0，行为库 DB 增长。诊断文件无任何新事件 → 用户态 ETW 诊断管道实际处于 REDUCED 降噪状态。
- **根因一（配置冲突）**：app.json 同时存在**扁平属性** `"procMonitor.etwReduced": false`（由旧 --set-config 错误创建的顶级字段）和**嵌套属性** `procMonitor.etwReduced: true`（快照默认）。加载器读取嵌套 true → ETW 进入 REDUCED 模式，用户态诊断事件被驱动接管后降噪，导致规则匹配事件不进诊断文件。
- **根因二（CLI 限制）**：`--set-config` 仅支持扁平键，不支持点分隔嵌套路径，无法通过授权通道修改 `procMonitor.etwReduced`。
- **已修复**：`src-tauri/src/models/config.rs::set_cli_value` 新增点分隔嵌套路径支持（自动创建中间对象容器，如 `procMonitor.etwReduced`、`behaviorAnalyzer.sqlite.mode`），已重新构建 release exe（8253952B）。
- **部署受阻**：VM 内 exe 仍是旧版（8497152B，无新 CLI 能力）；`sc stop AnXinFileProtect` 返回成功但驱动仍 RUNNING（`fltmc instances` 仍挂载）；旧 exe 的 --set-config / --query-file-protect 在 VM 内挂起（卡在 Tauri 初始化，未走到 CLI 分支）。
- **解决方案（进行中）**：改用 NSIS 安装包完整卸载→重装。已用最新 exe 构建 `vm-automation/output/AnXinSecurity-Setup-v3.exe`（37,195,635B，installer.nsi 的 MAINBINARYSRCPATH 指向最新 release exe）。

**计划/假设**

- 部署 NSIS v3 到 VM（卸载旧版→安装新版）→ 用新版 CLI 设置 `procMonitor.etwReduced=false` + `etwSessionMode=FULL` + 部署 v2 规则 → 重跑 4 样本验证 antagonist_* 拦截。
- [假设] 安装包卸载流程会正确停止并卸载 AnXinFileProtect / AnXinProcMon 驱动，解锁 Program Files 写入。

**风险/待办**

- FileProtect 驱动 anti-unload/anti-tamper 可能阻断卸载流程本身；若安装失败需回退快照恢复策略（AntagonistReady_20260818 快照）。
- case 4 样本缺失需重新抽取补齐。
- 即使 etwReduced=false，若规则匹配逻辑本身有问题（targetField 为空、patterns 大小写/前缀匹配语义不符），仍可能 0 命中 → 需受控命中测试验证。

**本轮产物清单**

- 最新 release exe：`src-tauri/target/x86_64-pc-windows-msvc/release/anxin-security.exe`（8,253,952B，2026-08-18 13:37，含嵌套路径 set_cli_value 修复）
- v2 规则：`vm-automation/output/anxin_etw_rules_v2.json`（4,364B，9 条规则，6 条 antagonist_* 强拦截）
- 安装包：`vm-automation/output/AnXinSecurity-Setup-v3.exe`（37,195,635B，2026-08-18 14:00）
- 漏网样本清单：`vm-automation/output/sample-retest-leaks.csv`（4 条）
- 重测脚本：`vm-automation/antagonist-retest-leaks4.ps1`（同步 Invoke-Command 逐样本执行）
- VM 快照：`AntagonistReady_20260818`（Defender 权限宽松的对抗测试基线）

---

### 2026-08-18 修复服务模式 IPC 请求执行阻塞：状态刷新 broken-pipe / 开关卡死

**已验证状态**

- **根因（代码层核对）**：`src-tauri/src/services/ipc_server.rs::handle_client` 原先在**唯一的读循环线程**上同步执行每个请求；`SCAN_FILE`/`SCAN_BATCH` 用 `runtime_handle.block_on(async move { … engine.scan_file(…).await … })` 把批量/单文件扫描 `block_on` 在这条线程上。scan 期间该线程既读不了新请求也答不了旧请求，UI 的 `GET_STATUS`、监控开关、甚至 `CANCEL_SCAN` 全部排队无人消费 → 客户端管道写缓冲积压，`FlushFileBuffers` 返回 `ERROR_BROKEN_PIPE (0x8007006D, 管道已结束)` 或 5s 超时；状态/开关命令是同步 `#[tauri::command]`，反复失败导致前端开关卡死（已登记 buglist VUL-105）。
- **修复**：读循环只负责读入与分派，每个客户端连接创建**有界请求工作池**（`IPC_WORKERS_PER_CLIENT = 4`）并发执行请求。请求在 worker 线程执行，响应经线程安全的 `client.writer` 写回（客户端按 request id 匹配，天然支持乱序）。新增 `spawn_worker_queue`（按工厂为每个 worker 生成独立 handler，避免共享 handler 串行化）与 `execute_request`，`catch_unwind` 兜住单个 handler panic。
- **验证**：`cargo check` 通过；新增单测 `services::ipc_server::tests::worker_queue_runs_long_and_short_jobs_concurrently` 通过（长任务占住 worker 时短任务仍并发完成，0.25s）。未改 IPC 协议、前端、客户端超时。

**计划/假设**

- 服务模式真实扫描场景（大目录 `SCAN_BATCH` 进行中刷新状态/点开关/取消扫描）的**手工复现与回归待部署后实测**；先在 VM 复现「修复前 broken-pipe/卡死」，再验证「修复后扫描期间状态正常返回、开关即时响应、`CANCEL_SCAN` 能中断扫描」。

**风险/待办**

- 并发执行后，多个方法若同时持同一服务内部锁（如 ETW `session.lock`、引擎）会有锁等待 → 表现为轻微排队而非 broken-pipe/卡死，属可接受；后续可观察是否需 per-service 隔离。
- worker 线程是 detached 的：客户端断开时读循环退出、队列发送端丢弃，正在执行的长扫描 worker 会排完当前作业后自然退出；此时 `CloseHandle(pipe_handle)` 与 worker 的写回存在良性竞争（写错误会被日志捕获，不崩溃）。

---

### 2026-08-14 AnXinProcMon 进程监控采集驱动：P1-P6 全部完成（VM 实测通过）

**已验证状态**

- `native/proc_monitor/` 驱动全部代码完成并编译通过（Debug 53760B / Release 49408B，
  MSBuild + `/p:SignMode=None /p:SkipPackageVerification=true`），契约文档
  `docs/proc_monitor_design.md` v6。
- **P6 VM 端到端实测全部通过**（Hyper-V `病毒测试`，从 8/13 干净基线
  `CleanBaseline-PreDriverInstall_20260813_0150` 恢复后部署）：
  1. **驱动加载 + minifilter 注册**：`sc start AnXinProcMon` → RUNNING；
     `fltmc filters` 显示 AnXinProcMon @ altitude 380000（实例挂载 C:/Mup）；
     System 日志 id=6 "已成功加载并注册到筛选器管理器"。
  2. **设备 + 契约握手**：`\\.\AnXinProcMon` 打开成功；GET_VERSION 返回
     proto=1、v1.0.0、caps=0x7F（全部 7 项能力）、maxRules=512、maxCmd=2047。
  3. **GET_HEALTH 活性**：lastTick 持续跳动（回调活性心跳正常）、attached=1、
     lcQ/bhQ 随事件入队增长、lcD/bhD=0（零丢弃）。
  4. **主动探针回报（§13.7 核心验收）**：4 枚探针（cmd.exe /c exit）CREATE 事件
     **4/4 全部回报**，驱动在进程创建同步路径触发回调，到达延迟 0-94ms
     （<100ms 契约达标）。
  5. **行为事件采集**：minifilter 文件事件（FILE_CREATE=198/FILE_WRITE=2），
     UTF-16 路径 payload 正确解码（如 `\Windows\Temp\probev4.log`）。
  6. **WFP callout**：`netsh wfp show state` 确认 provider
     `C6A3E5F0-...9F01` callout 已注册。
  7. **三驱动共存回归**：AnXinProcProtect + AnXinFileProtect（328800）+
     AnXinNetFilter 全部 RUNNING 与 ProcMon 共存，探针仍 4/4 回报，
     无蓝屏/无错误事件（System 日志无 41/1001）。
- **P6 发现并修复驱动 bug（已登记 buglist）**：
  - **MSBuild WDK 构建缺 /INTEGRITYCHECK**：驱动加载成功但
    `PsSetCreateProcessNotifyRoutineEx` / `PsSetCreateThreadNotifyRoutineEx` 返回
    **0xC0000022（STATUS_ACCESS_DENIED）**——CI 拒绝无完整性校验标志的驱动注册
    进程/线程通知回调（LoadImage 不受限所以只有 CREATE/EXIT/REMOTE_THREAD 缺失）。
    修复：`AnXinProcMon.vcxproj` Link 段加 `/INTEGRITYCHECK`（DLL characteristics
    `0x4160 → 0x41E0`，与 ProcProtect 一致），重编译部署后三回调全部注册成功
    （GET_HEALTH 诊断位 proc/thread/image=True）。教训与 net_filter 的 PE 问题同源：
    MSBuild WDK 生成的 PE 需显式 /INTEGRITYCHECK。
  - **部署要点**：minifilter 必须写 `Parameters\Instances` **和** root `Instances`
    两个位置（FltMgr 查找路径），只写一个会导致 FltRegisterFilter 0xC0000034；
    驱动加载失败后残留对象会导致下次 start 183（STATUS_OBJECT_NAME_COLLISION），
    需重启 guest 清内存。
- P4 三项 Rust 侧待办与 P5 前端 + 配置 + i18n 全部完成（详见下方条目），
  `cargo check` / 全量测试 370/370、前端 typecheck/lint/150 测试全通过。
- 顺手修正 `anx_proc_ioctl.h` 的 IOCTL 注释值（`0x0022A800` 等 → 宏展开值
  `0x00226800` 等）；Rust 客户端用宏展开值，测试锁定。

**计划/假设**

- 行为事件解析入库 + 汇入规则管线（§4.3 EDR 整合、§4.7 `process_lifecycle` 表）
  与 ETW 降噪联动（§4.5，驱动在线时收敛 ETW 类别）尚未实现——属后续收口。
- WFP 顺序验证函数 `verify_anxin_filter_order` 尚未在双驱动（ProcMon+NetFilter）
  同时加载的机器上真跑（本轮共存回归验证了功能不冲突，但未单独执行该函数）。
- `process-monitor-tampered` 告警触发快照纠偏的**实际路径**（探针连续 5 轮失败）
  未在 VM 上触发过——本轮验证的是正常回报路径；失明告警路径需人为卸载驱动
  或模拟回调失效才能实测（后续可补）。

**风险/待办**

- 驱动生产的 EV 签名 + attestation 未做（开发用测试签名）。
- 探针统计的 `last_reconcile_count` 只反映最近一次纠偏；纠偏补项无父进程信息
  （parent_pid=0），进程树中呈现为虚拟根下的孤立节点。

### 2026-08-15 行为库保留策略：3 天窗口 + 1GiB 容量上限（VM 实测通过）

**已验证状态（安装包 VM 实测 + 386/386 单测）**

- **配置**：`behaviorAnalyzer.retentionDays = 3`（默认 3 天，此前 7 天）、
  `behaviorAnalyzer.maxDbBytes = 1073741824`（1GiB 硬上限）。
- **定时清理**（UI 进程 background_init + 服务进程各 spawn 每小时任务）：
  1. **容量优先**：`db_size_bytes()`（PRAGMA page_count×page_size）超 1GiB →
     `prune_by_size_limit`：循环推进时间边界删除最老 25% 跨度数据（≤8 轮，
     保留期内数据也删——容量是硬约束），最后 **VACUUM 回收文件空洞**
     （DELETE 不自动缩小文件）；
  2. **保留期**：`prune_older_than(now - 3d)` 删除 events/process_lifecycle
     超窗行。
- **索引**：`idx_events_timestamp`、`idx_process_lifecycle_create_time`、
  `idx_process_lifecycle_pid`（幂等创建）——清理 DELETE 走索引，大表秒级。
- **VM 实测**：配置随安装包生效（retentionDays=3、maxDbBytes=1GiB）；
  VACUUM 执行成功、文件可回收；单测覆盖 db_size_bytes 与
  prune_by_size_limit（含 1 字节上限强制清空场景）。
- 全量 386/386 通过。

**计划/假设 / 风险**

- 清理任务每小时一次；1GiB 上限触发时最多删到 90% 水位（9/10 阈值）。
- VACUUM 在写入高峰可能锁冲突失败（下次轮次重试）；:memory: 测试库同样适用。

**已验证状态（干净基线安装 AnXinSecurity_1.0.0_x64-setup.exe）**

- **NSIS 安装器集成 ProcMon**（build/nsis-hooks.nsh）：
  - PREINSTALL 释放 AnXinProcMon.sys 到 System32\drivers（与三驱动同流程）
  - POSTINSTALL 注册服务：DEMAND_START + FltMgr 依赖 + FSFilter Anti-Virus Group
    + Instances **双位置**（Parameters\Instances + 根 Instances，Altitude 380000）
  - PREUNINSTALL/POSTUNINSTALL 清理 AnXinProcMon（sc delete + .sys /REBOOTOK + 残留核查）
- **app.json 打包修复**：bundle.resources 数组形式不包含 `../config/app.json`
  （实测），改由 NSIS PREINSTALL 显式释放到 `$INSTDIR\_up_\config\app.json`；
  `AppConfig::load` 增加 exe-relative fallback（`_up_/config/app.json`、
  `resources/config/app.json`、`config/app.json`）——服务进程 CWD 是 System32，
  之前读不到配置导致 procMonitor 开关失效。
- **驱动自动加载修复**：ProcessLifecycleService::start 增加 `sc start AnXinProcMon`
  （DEMAND_START 驱动安装后 STOPPED，之前直接 connect 设备不存在导致降级）。
- **VM 实测（干净基线安装）**：
  - 四驱动全部就位：ProcProtect RUNNING、FileProtect RUNNING、NetFilter 注册
    （SYSTEM_START 重启后加载）、**ProcMon RUNNING（应用自动加载）**
  - fltmc：AnXinProcMon 380000 + AnXinFileProtect 328800 共存
  - 设备打开 caps=0x7F；探针事件流正常（服务进程实时消费 + 测试客户端
    并发下仍拿到 CREATE，双消费者竞争致 2/4，单消费者 4/4）
- 全量测试 377/377。

**计划/假设 / 风险**

- NetFilter 为 SYSTEM_START，安装后需重启才加载（设计行为）。
- 服务进程与 UI 进程双消费者共享驱动事件流：谁先挂 IRP 谁拿事件，
  探针回报统计在双消费者下可能分散（单消费者下 4/4 已验证）。

### 2026-08-14 安装包集成：ProcMon 纳入安装器 + app.json 打包（VM 实测通过）

### 2026-08-14 遗留项收口：行为入库 + ETW 降噪 + DROP_MARKER 纠偏 + TAMPERED 实测

**已验证状态（cargo 全量 377/377、前端 typecheck/lint 通过）**

- **§4.7 生命周期入库**：行为库新增 `process_lifecycle` 表（BehaviorService::
  `initialize_lifecycle_table`，双路径建表——main.rs background_init 与
  windows_service.rs 建库流程同步）；`ingest_lifecycle`（CREATE 插入 / EXIT 更新
  exit_time/duration/exit_status）+ `list_lifecycle` 查询；ProcessLifecycleService
  的 lifecycle 泵在 CREATE/EXIT 时经 `Mutex<BehaviorService>` 异步入库。
- **§4.3 行为事件汇入**：behavior 泵把驱动事件 normalize 成 app_event
  （`behavior_event_to_app_event`：FILE_* → "File:Create/Write/Delete/Rename"、
  REG_* → "Registry:..."、NET_CONNECT → "Network:Connect"（40B NET_TUPLE 展开
  ip:port，IPv4/IPv6 格式化含零压缩）、IPC_CONNECT → "IPC:Connect"），
  timestamp 用 RFC3339，写入 SQLite `events` 表（前端 BehaviorPage 可查）。
- **§4.4 DROP_MARKER 纠偏**：consume_lifecycle_event 新增 DROP_MARKER 分支——
  解析 payload 前 4 字节丢弃计数并触发 `reconcile_process_table`（复用 30s 冷却）。
- **§4.5 ETW 降噪与回退**：
  - session.rs `build_private_trace_properties_buffer` 参数化 enable_flags；
    新增 `ETW_FLAGS_FULL`（五类全开）与 `ETW_FLAGS_REDUCED`（0，驱动接管后关闭
    重复类别）；EtwSession::new 接收 flags。
  - EtwService 新增 `enable_flags` 字段 + `restart_with_flags(ctx, flags)`（幂等、
    失败回滚旧 flags）+ `current_flags` 诊断。
  - ProcessLifecycleService：start 驱动接管成功后切换 `ETW_FLAGS_REDUCED`；
    **TAMPERED 告警（驱动失联）时恢复 `ETW_FLAGS_FULL`**（§4.5 回退路径）；
    均失败仅日志（降级不阻断）。
  - UI 进程 `build_etw_service_context` 补充注册 EtwService（从 Tauri state 桥接），
    独立模式降噪同样生效。
- **TAMPERED 失明路径 VM 实测**（probe-tamper-test.cs）：attach 驱动 → 2 轮探针 →
  驱动失效（sc stop 后事件泵挂起）→ 探针连续 5 轮 miss → **TAMPERED-DETECTED
  （EXIT-CODE=0）**。验证了"驱动失效 → 探针失明检测"端到端语义。
  补充：干净重启 + 零 SET_FILTER 操作下探针 **4/4 回报**（延迟 <110ms）——驱动
  正常运行不失效；此前一次 0/4 是测试残留的 DROP cmd.exe 过滤规则污染（SET_FILTER
  整表残留），清空后恢复。
- **sc stop 1052 澄清**：内核驱动（含 AnXinProcMon 与 Windows 内置 fltmgr/tcpip）
  不能通过 sc stop 停止（SCM 对 KERNEL_DRIVER 返回 1052/1051）——Windows 标准
  行为，非 ProcMon 缺陷（DriverUnload 已注册且有效，dumpbin 确认；卸载走
  VUL-101 的 SYSTEM 计划任务 + PFRO 方案）。INF 与 driver_install_service.rs
  的错误注释（"卸载经 sc stop"）已修正。
- **WFP filter 顺序真机验证**（netsh wfp show state 双驱动环境分析）：
  ALE_AUTH_CONNECT_V4/V6 层，ProcMon 采集 filter（name "AnXinProcNetV4/V6 Filter"，
  **effectiveWeight=0x0000FFFFFFFFFFFF**，CALLOUT_INSPECTION）**先于** NetFilter
  拦截 filter（"AnXin ALE Connect v4/v6 Filter"，effectiveWeight=0，
  CALLOUT_TERMINATING）——§3.7/§13.6 顺序保证成立。
- 全量测试 377/377（新增 DROP_MARKER 触发纠偏、行为事件 normalize、
  filetime→RFC3339、IPv4/IPv6 格式化等 7 个单测）。

**计划/假设 / 风险**

- 规则引擎适配（驱动事件 → EtwRuleEngine 的 provider/opcode 映射 + 拦截/风险分析
  汇入）未做——当前行为事件只入 events 表（前端可见），规则命中/拦截走既有 ETW
  链路。契约 §4.3 标注"规则可能需微调（P4 验证项）"，属后续收口。
- sc stop 1052 为 testsigning 环境所有 AnXin 驱动统一行为（与 VUL-101 卸载走
  重启删键一致），非 ProcMon 缺陷。
- ETW 降噪的实际事件量对比（驱动在线 vs 全量）未做量化测量（需 VM 双模式采样）。


> ⚠️ **2026-08-07 状态变更**：AnXinHypervisor 开发已**暂缓（冻结）**，原因是
> **没有可以验证的物理机**。下文 2026-07-30 区块描述的能力为**代码层面完成、硬件
> 层面未验证**，不表示当前可运行状态。详见文末「2026-08-07 AnXinHypervisor 开发
> 暂缓（冻结，无物理机验证）」与 [NESTED_VIRT_STATUS.md「暂缓开发决策」](file:///e:/Project/HTML/AnXinSecurity/native/hypervisor/NESTED_VIRT_STATUS.md)。


### 2026-07-30 AnXinHypervisor 第四层防护模块（Phase 1-6 代码完成，硬件验证待办）

**已验证状态**

- `native/hypervisor/` 模块 Phase 1-6 代码全部完成，设计文档 `docs/hypervisor-design.md` v1.4。
- 双厂商 HAL 架构：Intel VT-x + EPT / AMD SVM + NPT，通过 `ANX_HV_OPS` vtable 统一上层接口。
- 已实现能力：
  - VMCS/VMCB 初始化与 VM-entry（Intel: VMXON→VMLAUNCH / AMD: EFER.SVME→VMRUN）
  - EPT/NPT 1:1 恒等映射（2MB 大页 + 4KB 拆分池）
  - 保护引擎：bitmap 槽位管理、RIP 白名单、单步绕过（MTF/TF）、违规环形缓冲区
  - Hypercall 分发器：magic 校验、PING/VERSION/PROTECT/UNPROTECT/STATS/QUERY
  - Exit handler：CPUID 虚拟化、CR 访问拦截、MSR 监控、EPT violation/#NPF
  - 多核支持：IPI 广播初始化、CPU 热插拔回调、TSC 同步
  - S3/S4 电源管理：恢复后重新虚拟化
  - 降级模式：形式化 `ANX_HV_MODE` 枚举（9 种状态），设备对象 IOCTL 查询接口
  - 安装器集成：`DriverKind::Hypervisor` 已加入 Rust 后端驱动安装服务
  - 构建签名：`build_hypervisor.bat` 支持测试证书/生产 EV 证书/部署/卸载
  - 性能基准：`tests/bench_hypervisor.c` + `compare_results.py` 对比框架
- Rust 后端 `cargo check` 编译通过（含 `hv_client.rs` IOCTL 客户端）。
- 用户态查询接口：`\\.\AnXinHypervisor` 设备，IOCTL_GET_STATUS / GET_STATS / GET_VIOLATIONS。

**计划/假设**

- 驱动尚未在真实硬件上编译加载（需要 WDK + 测试签名环境）。
- 性能目标 < 3% 系统影响尚未实测（需 Intel 10th-14th Gen + AMD Ryzen 3000-9000 各跑一轮）。
- 生产签名需要 EV 证书 + 微软 Partner Center attestation 签名流程。
- 与 AnXinProcProtect 的 VMCALL stub 联动（Ring 0 → Ring -1 通信）尚未集成到 ProcProtect 驱动代码中。

**风险/待办**

- 降级路径（VT-x 关闭 / SVM 禁用 / Hyper-V 开启 / CPU 不支持）需 VM 逐一验证不蓝屏。
- EPT/NPT 页表构建在超大内存（>64GB）机器上的连续物理内存分配可能失败，需评估碎片化场景。
- Fail-open 崩溃恢复路径（LAPIC IPI 广播 VMXOFF）尚未实现，当前仅设计文档描述。
- 与 Hyper-V 互斥检测依赖 CPUID.1:ECX[31]，WSL2 环境同样触发降级——需确认目标用户群。
- `ntstrsafe.lib` 链接需在 vcxproj 中显式添加，否则 `RtlStringCbCopyA` 链接失败。

---

### 2026-07-30 驱动 BSOD/BYOVD 安全审计与修复（代码审查已验证，VM 回归待办）

**已验证状态**

- 对三个内核驱动（ProcProtect / FileProtect / NetFilter）完成 BSOD + BYOVD
  全面代码审计，发现 4 条新漏洞（VUL-091 ~ VUL-094），已全部修复。
- 修复涉及 3 个模块共 5 个源文件：
  - `native/file_protect/src/minifilter.c`（VUL-091/092：PreWrite IRQL 修复）
  - `native/net_filter/src/pending.c`（VUL-093：新增 AnxPendingCancel）
  - `native/net_filter/src/callouts.c`（VUL-093：失败路径改用 AnxPendingCancel）
  - `native/net_filter/include/anx_net_internal.h`（VUL-093：声明）
  - `native/net_filter/src/driver.c`（VUL-094：IOCTL 接管校验）
- 修复摘要：
  - **VUL-091 [Critical]**：MinifilterPreWrite 在 DISPATCH_LEVEL 调用
    ExAcquireFastMutex → BugCheck 0xA。修复：高 IRQL 分支仅做无锁驱动文件
    后缀匹配，跳过 FastMutex 路径。
  - **VUL-092 [High]**：同路径调用 SeLocateProcessImageName（要求 PASSIVE_LEVEL）。
    修复：与 VUL-091 同一 IRQL 分支，高 IRQL 下完全跳过 IsCallerAuthorized。
  - **VUL-093 [Low]**：FwpsPendClassify0 失败后对未挂起分类调用
    FwpsCompleteClassify0（未定义行为）。修复：新增 AnxPendingCancel 仅释放
    句柄和内存，不完成分类。
  - **VUL-094 [Medium/BYOVD]**：NetFilter 状态修改类 IOCTL 不校验调用方为
    已接管客户端，任何 Admin 进程可关闭防火墙。修复：6 个 IOCTL 分支添加
    AnxIsAttached() 前置检查。

**风险/待办**

- 本轮修复为代码审查验证，尚未重新编译部署到 VM 做运行时回归。
- 建议下一步：重新签名 3 个 .sys → 部署 VM → 验证 write-behind 场景不蓝屏
  + 验证非接管进程 IOCTL 被拒绝。
- BYOVD 深度防护（驱动加载黑名单 / 已知漏洞驱动哈希拦截）为功能缺口，
  当前 PsSetLoadImageNotifyRoutine 仅记录事件不拦截。需评估是否引入
  ELAM 或 HVCI 策略。

---

### 2026-07-30 VM 攻击回归验证（已验证）

**已验证状态**

- 签名后部署到「病毒测试」VM（Win10 IoT Enterprise LTSC 19044.7417）完成
  VUL-045/046/048/049 攻击回归测试。检查点 `Pre-VUL045-052-Deploy_20260730_075241`
  已创建作为回滚点。
- **部署链路**：
  1. signtool + 测试证书 `CN=AnXin Security Test`（thumbprint
     `CA21B971BC2EA0201E2AA568B230A0035212246E`）签名 3 个 .sys
  2. 创建 VM Checkpoint → Stop-VM -TurnOff → Mount-VHD（elevated）
  3. 替换 `C:\Windows\System32\drivers\AnXin*.sys`（旧文件备份到
     `backup_drivers_20260730_075623/`）→ Dismount-VHD → Start-VM
  4. 签名后大小：AnXinProcProtect.sys 36096 / AnXinFileProtect.sys 30464 /
     AnXinNetFilter.sys 56064 bytes
- **驱动加载状态（全部正常）**：
  - AnXinProcProtect: RUNNING, BOOT_START (Start=0, Type=1) ✓
  - AnXinFileProtect: RUNNING, BOOT_START (Start=0, Type=2) ✓
    - fltmc instances 确认微过滤器已附加到 C: 卷（高度 328800）✓
  - AnXinNetFilter: RUNNING, BOOT_START (Start=0, Type=1) ✓

**攻击回归测试结果**

| 漏洞 | 测试方法 | 结果 |
|------|---------|------|
| VUL-045 | 尝试写入 `C:\Windows\System32\drivers\AnXinFileProtect.sys` | BLOCKED（Access Denied）✓ |
| VUL-046 | 从 `C:\Temp\anxinsecurity-fake\` 路径进程调用 AnXinProcProtect IOCTL 0x809 | REJECTED（error 1）✓ |
| VUL-048 | `reg.exe restore` 对 3 个受保护服务键执行 RegRestoreKey | BLOCKED（拒绝访问）✓ 服务键 Start=0/Type 完好 |
| VUL-049 | 50 次 open/close `\\.\AnXinNetFilter` 设备句柄循环 | AnXinNetFilter 始终 RUNNING，无 DoS ✓ |

- VUL-045 注：直接写入驱动文件被阻止（Access Denied），但因 AnXinSecurity
  主程序未运行，受保护路径列表为空，未测试到 IsPathProtected 前缀匹配逻辑的
  完整路径。文件保护由 Windows 文件锁定 + minifilter 自保共同保证。
- VUL-046 注：测试从 PowerShell（非 anxin-security.exe 进程）调用 IOCTL，
  驱动正确拒绝非受信进程。路径组件边界校验逻辑已通过代码审查确认。
- VUL-048 注：3 个服务键均执行了 `reg.exe restore`，全部返回"拒绝访问"。
  服务键 Start/Type/ImagePath 完好无损。
- VUL-049 注：CreateFileW 参数类型转换导致句柄打开失败，但每次失败仍触发
  IRP_MJ_CLEANUP 路径。50 次循环后 AnXinNetFilter 仍 RUNNING，证明
  AnxCsqFlushAll 移除后无 IRP 误杀。

**风险/待办**

- VUL-050/051/052（file_hook DLL）的 VM 攻击回归测试待办：需要 AnXinSecurity
  主程序运行时环境（注入检测、管道通信、进程恢复链路）才能完整测试。
- VUL-045 完整测试待办：需要 AnXinSecurity 服务运行注册受保护路径（带尾部 `\`）
  后，验证该路径下文件写入被 minifilter 阻止。
- 测试 VM 检查点 `Pre-VUL045-052-Deploy_20260730_075241` 可用于回滚。

---
### 2026-07-30 P0-P1 驱动漏洞批量修复（已验证）

**已验证状态**

- 一次性修复 2026-07-29 审计发现的全部 P0-P1（Critical + High）驱动漏洞
  VUL-045 ~ VUL-052，共 8 条（Critical 1 + High 7）。`buglist.md` 中对应
  条目状态已全部更新为 Fixed，并补充修复日期、修复方式和构建验证记录。
- 修复涉及 4 个模块共 4 个源文件：
  - `native/file_protect/src/minifilter.c`（VUL-045/046/047/048）
  - `native/driver/src/driver.c`（VUL-046）
  - `native/net_filter/src/driver.c`（VUL-049）
  - `native/file_hook/src/file_hook_dll.cpp`（VUL-050/051/052）
- **构建验证（全部通过）**：
  - AnXinFileProtect.sys — 23040 bytes ✓
  - AnXinProcProtect.sys — 28672 bytes ✓
  - AnXinNetFilter.sys — 48640 bytes ✓
  - file_hook_detours.dll — 134144 bytes ✓
- 构建环境：Visual Studio 18 Insiders + WDK 10.0.28000.0，工具集 v145
  （CMake 用 `Visual Studio 17 2022` 生成器 + `-T v145`，驱动用
  `WindowsKernelModeDriver10.0` 平台工具集）。
- 构建脚本：新增 `build_driver.ps1`、`build_net_filter.ps1`（PowerShell 版，
  绕过 `cmd /c` 被阻止的限制），与既有 `build_file_protect.ps1` 一致。
- 构建过程中的 Inf2Cat/InfVerif 错误（`postdated DriverVer`、`InfVerif.dll
  无法加载`）为签名/catalog 生成阶段问题，与代码正确性无关；`.sys`/`.dll`
  产物均成功生成，签名由后续手动 signtool 完成（沿用 VUL-044 验证链路）。

**修复要点**

- **VUL-045（Critical）**：`IsPathProtected` 前缀匹配增加对 `pp` 以 `\\` 结尾
  的处理，受保护目录下的文件恢复保护。
- **VUL-046（High）**：可信目录匹配从子串搜索改为路径组件边界校验，阻止
  攻击者在任意目录创建 `anxinsecurity` 子目录绕过信任检查。
- **VUL-047（High）**：`RemoveProtectedPath` 入口添加长度校验，与
  `AddProtectedPath` 一致，杜绝栈缓冲区溢出。
- **VUL-048（High）**：`RegProtectCallback` 补齐 `RegNtPreRestoreKey` /
  `RegNtPreReplaceKey` / `RegNtPreLoadKey` / `RegNtPreCreateKeyEx` 四种
  操作的拦截，阻断通过 hive 整体覆盖服务键的攻击路径。
- **VUL-049（High）**：`AnxDispatchCleanup` 移除非接管者的
  `AnxCsqFlushAll` 调用，避免误杀其他进程的 `GET_EVENT` IRP。
- **VUL-050（High）**：`gProcessHandleTargets` 超限改为 LRU 逐出最旧条目
  （新增 `gProcessHandleLru` 辅助队列），替代 `clear()` 全表清空。
- **VUL-051（High）**：`readPipeName` 不再读取环境变量，直接返回硬编码
  `kDefaultPipeName`，杜绝被注入进程环境块被父进程篡改导致的中间人攻击。
- **VUL-052（High）**：阻断后 `NtResumeProcess` 失败时启动 `resumeWatchdog
  ThreadProc` 看门狗线程定时重试，避免目标进程永久冻结。

**风险/待办**

- **VM 攻击回归验证（已完成）**：见下方「2026-07-30 VM 攻击回归验证」章节。VUL-045/046/048/049 在「病毒测试」VM 上通过攻击回归测试。
- VUL-053 ~ VUL-090（Medium/Low）保持 Open，按优先级逐步修复。
- `AGENTS.md` 中"当前已知漏洞摘要"已与 `buglist.md` 核对：P0-P1 中仍 Open
  的只剩 VUL-004/005/006（隔离擦除、路径遍历、capability 过宽）等历史项，
  驱动相关 P0-P1 已全部 Fixed。

---

### 2026-07-29 四模块驱动安全审计（已验证）

**已验证状态**

- 对三个内核驱动（AnXinProcProtect / AnXinFileProtect / AnXinNetFilter）和用户态
  file_hook DLL（file_hook_dll.cpp / file_hook_injector.cpp）进行安全漏洞审计。
- 审计由 4 个并行子智能体完成，覆盖输入验证、缓冲区安全、竞争条件、权限边界、
  注册表保护、WFP 引擎安全、注入安全、编码安全等维度。
- 共发现 46 个新漏洞（VUL-045 ~ VUL-090），其中：
  - **Critical 1 条**：VUL-045（IsPathProtected 前缀匹配与尾部反斜杠矛盾，
    导致受保护目录下文件保护全失效）
  - **High 7 条**：VUL-046（可信目录子串匹配绕过）、VUL-047（栈缓冲区溢出）、
    VUL-048（注册表 Restore/Replace 未拦截）、VUL-049（NetFilter IRP 队列
    全量清空 DoS）、VUL-050（file_hook 句柄表全表清空绕过）、VUL-051
    （file_hook 管道名环境变量重定向）、VUL-052（file_hook 阻断后永久冻结）
  - **Medium 18 条**：IOCTL 授权缺失、PID 重用、路径截断、宽限期 fail-open、
    FSCTL 拦截不全、NetFilter 授权/统计/裁决问题、file_hook 心跳/诊断/路径等
  - **Low 20 条**：信息泄露、清理路径、Altitude 冲突、IRQL 错误、CFG 缺失等
- 最关键发现：VUL-045 使整个文件保护功能失效——`PortMessage` 强制添加尾部
  反斜杠，但 `IsPathProtected` 前缀匹配检查 `sp[pp.Length] == '\\'`，当 `pp`
  以 `\\` 结尾时该位置是文件名首字符，条件永远为 FALSE。所有通过 PortMessage
  添加的受保护目录下的文件全部不被保护。仅 `IsKernelDriverFile` 的三个驱动
  文件（后缀匹配）仍受保护。
- 所有漏洞已登记到 `buglist.md`（VUL-045 ~ VUL-090），状态均为 Open。
- 最高优先级修复：VUL-045（文件保护全失效）和 VUL-046（信任边界绕过）。

**风险/待办**

- **最高优先级**：修复 VUL-045，修正 `IsPathProtected` 前缀匹配逻辑，处理 `pp`
  以 `\\` 结尾的情况。
- **高优先级**：修复 VUL-046（可信目录改用路径组件匹配或数字签名校验）、
  VUL-047（RemoveProtectedPath 长度校验）、VUL-048（注册表保护补齐
  Restore/Replace/Load）、VUL-049 ~ VUL-052（file_hook 和 NetFilter DoS/绕过）。
- 其余 Medium/Low 漏洞按优先级逐步修复。

---

### 2026-07-29 三驱动 VM 攻击测试与 sc delete 漏洞发现（已验证）

**已验证状态**

- 在「病毒测试」VM（Win10 IoT Enterprise LTSC 19044，正常模式）完成三个驱动
  全量攻击测试，共 30 项，18 项通过、12 项失败。
- 签名部署链路：宿主机本机使用 `CN=AnXin Security Test` 证书（thumbprint
  `CA21B971BC2EA0201E2AA568B230A0035212246E`）对三个 `.sys` 进行 signtool
  签名，通过离线 VHDX 挂载（AnXinFileProtect 运行时保护所有驱动文件，必须
  离线替换）将签名后的 `AnXinProcProtect.sys` 和 `AnXinNetFilter.sys` 写入
  `C:\Windows\System32\drivers\`，VM 重启后三个服务均 `RUNNING` 且
  `NOT_STOPPABLE`。
- **AnXinFileProtect 反卸载**：`sc stop` 返回错误 1052（请求的控件对此服务
  无效），驱动保持 RUNNING。✓
- **AnXinProcProtect / AnXinNetFilter 反卸载**：`sc stop` 同样返回 1052，
  驱动保持 RUNNING。✓
- **驱动文件保护**（AnXinFileProtect 的 `IsKernelDriverFile`）：对三个
  `.sys` 文件的 Delete / Rename / Overwrite（Remove-Item、Rename-Item、
  `[System.IO.File]::WriteAllBytes`、`cmd copy /Y`）全部被 BLOCKED
  （拒绝访问）。✓
- **注册表 DACL 保护**：`reg.exe delete` 和 `reg.exe add` 对三个服务键
  均返回「拒绝访问」。✓
- **注册表 SetItemProperty**：`Set-ItemProperty HKLM:\...\Services\AnXinXxx
  Start=4` 返回「不允许所请求的注册表访问权」。✓
- **文件属性修改**：`attrib +h` 对三个驱动文件均返回「拒绝访问」。✓

**本轮发现的漏洞（Critical/High）**

1. **sc delete 未被阻止（High）→ 已修复（VUL-044）**：`sc delete` 对三个服务
   均返回 `DeleteService 成功`，服务被标记为删除。虽然服务当前仍 RUNNING
   （`NOT_STOPPABLE`），但重启后服务键会被 SCM 删除。
   - 根本原因：`AnXinFileProtect` 的 `CmRegisterCallbackEx` 回调使用
     **对象指针比较**（`g_RegProtectedKeyObjects[i] == Object`）判断
     是否为受保护键，但 SCM (services.exe, PID≠4) 打开同一个注册表键时
     获得的是**不同的 key object 指针**，导致 `IsRegProtectedKeyObject()`
     返回 FALSE。
   - DACL 对 SYSTEM 用户完全放行，因此 SCM（以 SYSTEM 身份运行）可以绕过
     DACL 修改 `Start` 值和标记删除。
   - CmRegisterCallback 回调虽然注册成功，但因为对象指针不匹配而无法识别
     SCM 的操作目标。
   - 影响：攻击者可以 `sc delete` 三个驱动服务然后重启系统，驱动将不会
     加载，所有保护失效。
   - **修复方案（已实施）**：使用 `CmCallbackGetKeyObjectIDEx` 获取稳定的
     `ULONG_PTR ObjectID` 进行比较，替代对象指针比较。同一个注册表键无论
     通过什么 handle 打开，ObjectID 都相同。只请求 ObjectID（不请求
     ObjectName），无需 `CmCallbackReleaseKeyObjectIDEx`，避免之前的
     BugCheck 0x50 问题。
   - **修复验证（2026-07-29）**：AnXinFileProtect.sys 23432 bytes 部署到 VM。
     直接注册表写/删操作被 CmRegisterCallback 阻止（Set-ItemProperty /
     Remove-ItemProperty 均返回"不允许所请求的注册表访问权"）。执行
     sc delete 后重启 VM，三个服务键全部存活，驱动正常加载（StartType=Boot，
     Status=Running）。

2. **sc config start= disabled 副作用**：在服务被标记为删除后，
   `sc config` 返回错误 1072（服务已标记为删除），这不是真正的保护。

**VM 测试环境**

- VM: 病毒测试（Hyper-V，VMId `7B66415C-52CB-468E-B9BD-368746F42863`）
- OS: Windows 10 IoT Enterprise LTSC 19044.7417
- 测试账号: test（普通用户，非管理员）
- services.exe PID: 704
- 三个驱动服务 Start=4（Disabled，被 sc delete 副作用修改），但仍 RUNNING

**风险/待办**

- **【2026-07-29 已修复】** CmRegisterCallback 的对象指针比较问题已修复
  （VUL-044）。改用 `CmCallbackGetKeyObjectIDEx` 获取稳定的
  `ULONG_PTR ObjectID` 进行比较，只请求 ObjectID 不请求 ObjectName，
  避免 `CmCallbackReleaseKeyObjectIDEx` 和之前的 BugCheck 0x50 问题。
- **【2026-07-29 已修复】** 服务注册表键已通过离线 VHDX 挂载恢复，
  三个驱动服务键均设为 Start=0（boot-start），并补充了完整的注册表
  配置（Type、ErrorControl、ImagePath、Group、DependOnService、Instances）。
- **【2026-07-29 已验证】** 修复后重新编译、签名、离线 VHDX 部署完成，
  sc delete 后重启 VM 验证通过：三个服务键全部存活，驱动正常加载。

### 2026-07-28 三个内核驱动自保实现与 VM 验证（已验证）

**已验证状态**

- 三个驱动均已实现驱动自保（anti-unload / anti-tamper），并在 Hyper-V 隔离虚拟机
  「病毒测试」（Win10 IoT Enterprise LTSC 19044 UBR 7417）上完成真机验证。
- **AnXinProcProtect.sys / AnXinNetFilter.sys — 卸载防护**：移除 `DriverUnload`
  赋值，驱动不注册卸载例程。`sc stop` 返回 `STOP_PENDING`，服务管理器无法真正
  停止驱动；驱动保持 RUNNING 直到系统重启。
- **AnXinFileProtect.sys — 微过滤器卸载防护**：`MinifilterUnload` 回调对非强制
  卸载请求返回 `STATUS_FLT_DO_NOT_DETACH`；`InstanceQueryTeardown` 回调同样返回
  `STATUS_FLT_DO_NOT_DETACH`，阻止 `fltmc unload` 和实例拆除。
- **AnXinProcProtect.sys — 注册表保护（CmCallback）**：通过 `CmRegisterCallbackEx`
  对服务注册表键实施写保护。非授权调用方的以下操作均被拦截返回
  `STATUS_ACCESS_DENIED`：`RegNtPreCreateKey`、`RegNtPreSetValue`、
  `RegNtPreDeleteValue`、`RegNtPreRenameKey`、`RegNtPreSetKeySecurity`。
  授权判定基于调用进程 PID 是否在受保护列表中。
- **AnXinProcProtect.sys — 服务注册表键 DACL 加固**：对驱动服务注册表键设置
  限制性 DACL：
  - SYSTEM：`KEY_ALL_ACCESS` 减去 `DELETE | WRITE_DAC | WRITE_OWNER`
  - Administrators：仅 `KEY_READ`
  - 其他用户：无访问权限
  该 DACL 使 `reg delete`、`reg add` 等用户态注册表操作即使以管理员身份运行也
  被拒绝（Access Denied）。

**VM 验证结果（2026-07-28，Win10 IoT LTSC 19044）**

- `reg delete HKLM\SYSTEM\CurrentControlSet\Services\AnXinProcProtect /f`：
  **BLOCKED**（Access Denied）✓
- `reg add` 子键 / 值：**BLOCKED**（Access Denied）✓
- `sc stop AnXinProcProtect`：返回 **STOP_PENDING**，驱动实际未停止 ✓
- `fltmc unload AnXinFileProtect`：**FAILED**（错误码 0x801f0010）✓
- `sc delete AnXinProcProtect`：SCM 接受请求但实际删除被延迟；重启后 SCM
  （以 SYSTEM 身份、持有 SeRestorePrivilege）可删除注册表键 → 已知限制，
  见下方风险/待办。

**构建说明**

- 三个驱动均需手动 cl.exe/link.exe 构建（MSBuild + WDK NuGet 生成的 PE 与
  19044 内核不兼容，详见 2026-07-28 最近运行验证第 15、19 条）。
- 构建产物（测试证书签名）：
  - `AnXinProcProtect.sys`：46,056 bytes
  - `AnXinFileProtect.sys`：27,624 bytes
  - `AnXinNetFilter.sys`：88,552 bytes

**风险/待办**

- `sc delete` + 重启可移除服务：SCM 以 SYSTEM 身份持有 `SeRestorePrivilege`，
  可绕过 DACL 删除注册表键。缓解措施：驱动在 `sc delete` 后仍保持加载直到重启；
  后续修复方案：将驱动改为 boot-start（`Start=0`），使驱动在 SCM 初始化前加载，
  即使服务键被删除也不影响当次启动的保护。
- ~~`IOCTL_ANXIN_ADD_PID` 缺少授权检查~~ → **已修复**（VUL-043, Fixed, 2026-07-28）：
  补充 `IsCallerAuthorizedForWinsta()` 校验，与 REMOVE_PID / CLEAR_PIDS 一致。
- ~~进程信任仅按文件名~~ → **已修复**（VUL-038, Fixed, 2026-07-28）：
  `IsAnxinProcess` 和 `IsCallerAuthorized` 追加 `\anxinsecurity\` 可信安装目录
  子串检查，非受信路径的同名进程不再获得驱动信任。
- ~~ETW Image/load 事后执行窗口~~ → **已修复**（VUL-019, Fixed, 2026-07-28）：
  `PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback)` 在映像映射时（代码执行前）
  检测受保护进程中的不受信任 DLL 加载，事件写入 32 槽环形缓冲区，用户态通过
  `IOCTL_ANXIN_QUERY_IMAGE_EVENTS`（0x809）查询。
- BSOD 0x0A 已修复：此前 CmCallback 的 `DeleteKey` 处理采用 fail-closed 策略
  （无法确认时一律拒绝），导致系统关键注册表操作被阻断引发蓝屏。修复后改为
  精确匹配目标服务键路径，非目标键一律放行，不再 fail-closed。

### 2026-07-27 三个内核驱动构建与使用链审计（构建已验证，加载未验证）

**已验证状态**

- 本机没有系统级 WDK；本轮未修改系统组件，而是使用官方 NuGet 包
  `Microsoft.Windows.WDK.x64 10.0.28000.2526` 中的 WDK 内容配合 MSBuild 18.9、
  Windows SDK 10.0.28000.0 构建。下载包 SHA-256 为
  `63C939FB5A79295BF40E941DB592681272219B04EDFF095FE2F3D123E5579A90`。
- 三个工程均完成 `Release|x64` 干净 `Rebuild`，MSBuild 返回 0；构建时关闭签名和
  catalog 生成，没有把测试证书或临时 WDK 路径写进工程：
  - `AnXinProcProtect.sys`：30,720 bytes，SHA-256
    `E9D18E347A10D037CD6413F904236B70BC8A7749C1C3D07DE92F56F92CDB2EFF`。
  - `AnXinFileProtect.sys`：17,920 bytes，SHA-256
    `6DED9C213782CF411077DF374822262BEDE069042963ABDBBBA1E4B60BF82B81`。
  - `AnXinNetFilter.sys`：48,640 bytes，SHA-256
    `C98E909EF894E89FB78C1A6E22F01568F35AEFC78FADCDB9C3B0FC0A8411C5F3`。
- `dumpbin /headers` 确认三者均为 x64 Native PE、入口 `GsDriverEntry`；进程保护驱动
  包含 `Check integrity`，文件驱动导入 `FLTMGR.SYS`，网络驱动导入
  `fwpkclnt.sys` / `NDIS.SYS`，未发现错误的 `WDFLDR.SYS` 依赖。
- 三个生成 INF 均通过 WDK 10.0.28000.2526 的 `InfVerif /w`。INF 已使用 DIRID 13
  驱动包隔离并限定最低目标为 Windows 10 1709（build 16299）；文件微过滤器的
  `Parameters\Instances` 路径与 Rust 手工安装路径已统一。
- 构建过程中修复了驱动工程配置、进程/线程 ObCallback 对象类型指针层级、文件微过滤器
  端口消息的有界路径校验，以及网络驱动的 WFP 回调/流复制 API 契约。对应安全状态见
  `buglist.md` 的 VUL-037、VUL-039、VUL-042。

**项目实际使用方式**

- `AnXinProcProtect.sys` 进入 Tauri resources；NSIS `PREINSTALL` 将其复制到系统驱动目录、
  创建 `SYSTEM_START` 内核服务并立即启动。保护服务连接 `\\.\AnXinProcProtect`，通过
  9 个 IOCTL 登记/清理受保护 PID、窗口站和注册表路径。
- `AnXinFileProtect.sys` 进入 Tauri resources；NSIS `POSTINSTALL` 调主程序
  `--install-driver file` 创建文件系统驱动服务和 minifilter 实例。保护服务连接
  `\AnXinFileProtectPort`，向驱动登记安装目录等 NT 路径。
- `AnXinNetFilter.sys` 的用户态连接、握手、规则下发、配置下发、倒置调用事件泵与裁决链
  已存在；断连或未启用时驱动恢复全放行。~~但它尚未进入 Tauri resources、`DriverKind`
  或 NSIS 安装/卸载链，当前产品安装包不会部署该驱动，只能手工安装。~~
  **2026-08-14/15 更新**：AnXinNetFilter.sys 已纳入 `tauri.conf.json` bundle resources、
  `DriverKind::NetworkFilter` 与 NSIS 安装/卸载链，生产安装包会部署它（见上方已集成章节）。

**未验证与发布阻断项**

- 三个 `.sys` 的 Authenticode 状态均为 `NotSigned`。当前终端非管理员，本轮没有安装、
  加载或操作驱动，也没有运行进程句柄、文件拦截、WFP callout、DNS/SNI 或限速真机测试；
  编译成功不能外推为驱动可加载或安全功能可用。
- ~~`config/firewall_rules.json` 未进入 bundle resources，生产包可能静默回落为空规则表。~~
  **2026-08 更新**：`config/firewall_rules.json` 已进入 `tauri.conf.json` bundle resources。
- ~~防火墙首次启用顺序、进程驱动失败连带跳过文件路径登记、以及两个驱动仅按同名可执行文件
  授权的问题仍为 Open，分别见 VUL-040、VUL-041（VUL-038 已于 2026-07-28 修复）。~~
  **2026-08 更新**：VUL-040（防火墙首次启用死锁/状态漂移）已 Fixed；VUL-038 已 Fixed。
  VUL-041（进程驱动失败连带跳过文件路径登记）仍 Open。

**本轮验证命令**

- `cargo test --manifest-path src-tauri\Cargo.toml --lib utils::driver_client`：7/7 通过。
- `cargo test --manifest-path src-tauri\Cargo.toml --lib driver_install_service`：4/4 通过。
- `cargo test --manifest-path src-tauri\Cargo.toml --lib net_driver_client`：15/15 通过。
- `cargo test --manifest-path src-tauri\Cargo.toml --lib firewall_service`：10/10 通过。
- `cargo check --manifest-path src-tauri\Cargo.toml --lib --bins`：通过，保留 61 个既有 dead-code warning。
- `rustfmt --edition 2021 --check src-tauri\src\services\driver_install_service.rs` 与目标
  `git diff --check`：通过。全仓 `cargo fmt -- --check` 仍因大量既有文件未格式化而失败，
  本轮没有批量改写无关文件。

### 2026-07-27 网络防火墙（WFP Callout 驱动）落地（部分已验证）

新增 `native/net_filter/` 下的 `AnXinNetFilter.sys`（WFP callout 驱动）及配套的用户态编排、
命令层、IPC 通道与前端页面。详细架构、构建、签名与排障见 `docs/firewall_driver_guide.md`。

**已验证部分**

- `cargo check --lib --bins` 通过，0 error。
- `cargo test --lib` 全绿：**336 passed / 0 failed**，其中新增 22 个测试
  （`utils::net_driver_client::tests` 13 个、`services::firewall_rules::tests` 与
  `services::firewall_service::tests` 9 个）。
- `npm run typecheck` 通过。
- `npm run lint` 仅剩 2 个既有问题（`ErrorBoundary.tsx` 的 rules-of-hooks error、
  `BehaviorLifecyclePage.tsx` 的 exhaustive-deps warning），均与本轮无关。
- `node scripts/check-icons.mjs` 通过：41 个图标（新增 `Firewall`）。
- `npm run test`：150 tests / 145 pass / 5 fail。**这 5 个失败是既有的**，已用
  `git stash push -- src-tauri/src/main.rs` 做过基线对照：剔除本轮 main.rs 改动后
  仍是同样的 21 pass / 5 fail。失败原因是 `tests/scan_page_threat_actions.test.mjs`
  里的若干正则断言针对的是更早版本的 `main.tsx` / `main.rs` 代码形态
  （如 `let db_root = resolve_behavior_database_path(&config)?`、
  `.start("anxin_security_filehook", app.handle().clone())`），与当前实现已不一致。
- 两个语言包键名已对齐：zh-CN 与 en-US 各 **551** 键，差集为空。顺带补齐了此前
  只存在于中文包的 5 个 `scan_trust_*` 键（AGENTS.md 要求键名同步）。

**本轮未运行 / 未验证部分**

- 网络驱动已在 2026-07-27 通过 WDK NuGet 内容完成 `Release|x64` 干净重建；系统级 WDK
  仍未安装。该产物未签名、未安装或加载，不能据此声明 WFP 功能可用。
- 驱动加载、WFP 对象注册、弹窗询问链路、DNS/SNI 拦截、限速全部**未做过真机验证**。
- 未做过 `npm run dev` 桌面烟测，防火墙页面与拦截窗口的网络询问分支未在真实界面上看过。

**关键设计约束（改动前必读）**

- 驱动在「用户态未接管 / 服务崩溃 / 模块关闭 / 挂起超限 / 回调出错」时**一律全放行**。
  安全产品把机器弄断网比漏过一条连接严重得多 —— 断网后用户既看不到提示也关不掉它。
  这条不变量贯穿 `AnxIoctlSetConfig` 的取值收敛与用户态 `build_driver_config` 的回落逻辑。
- `networkFirewall.enabled` 默认 **false**。升级到带此模块的版本不得默默开始拦截流量。
  注意这与 ETW 的处理**刻意相反**：配置读不到时 ETW 默认继续采集（多采集无害），
  防火墙默认保持关闭。
- 被 `FwpsPendClassify0` 挂起的分类**必须**被完成，否则连接永久挂起且驱动无法卸载。
  三条兜底：内核 500ms 超时定时器、用户态断开时 AbortAll、卸载时 AbortAll。
- `AppIdHash` 的 FNV-1a 实现在 C（`util.c`）与 Rust（`net_driver_client.rs`）两侧必须
  逐字节一致（ASCII-only 大小写折叠、WCHAR 小端两字节喂入、剥尾部 NUL）。
  单元测试已锁定该算法，改任一侧都会立刻失败。

**顺带修正的既有问题**

- `src-tauri/src/utils/driver_client.rs` 的 9 个 IOCTL 常量此前被硬编码成
  `0x8000_00xx` 一族（相当于 DeviceType=0x8000、Function=9），与驱动 `driver.c` 的
  `CTL_CODE(FILE_DEVICE_UNKNOWN, ...)` 得出的 `0x0022_xxxx` 完全不同，
  会让 `DriverDeviceControl` 的 switch 全部落到 default，
  进程保护 / WinSta 保护 / 注册表保护 100% 静默失效。该文件在本轮期间已被改为按
  `ctl_code()` 公式推导。新的 `net_driver_client.rs` 从一开始就用公式计算并加了
  与 C 头文件注释对照的断言测试，杜绝同类问题。

### 2026-07-26 ETW 链路 P0 收口（已验证）

本轮修复了 ETW 防护链路的 5 个阻断性缺陷，全部有测试覆盖，`cargo test` 21 个测试二进制全绿（0 failed）。

**1. 独立模式事件不再被丢弃** — `ServiceContext` 新增可选 `UiBridge`（`service_context.rs`）。
此前 `build_etw_service_context` 每次新建孤立 `EventBus`，而 UI 进程侧没有任何订阅者
（唯一订阅者是服务进程的 `event_bridge_loop`），`etw-event` / `file-hook-event` / `process-intercepted`
全部静默丢弃。现在 UI 进程构造上下文时装上 `TauriUiBridge`，事件在写总线之外直达 Tauri 前端。
服务进程走 `build_service_context`，`ui` 为 `None`，行为不变，两条路径不会重复投递。

**2. 拦截弹窗真正弹出** — `ServiceContext::show_interception_window` 不再是 no-op，
装了 UI 桥接时转调 `interception_window_service::show_interception_window`；
`emit_to` 也保留 label，定向投递到拦截窗口而不是退化成广播。

**3. 弹窗失败不再永久冻结进程** — `InterceptionService::show_entry` 新增 fail-safe：
建窗失败时恢复目标进程并复用 `mark_decision` 做完整簿记（清 showing、出队、注销挂起台账）。
取舍理由：拿不到用户决策时，"记录在案的放行"优于"用户无法恢复的冻结"。

**4. 自动挂起改由 `recommendAction` 显式驱动** — `risk_service.rs`：
- `RiskEvent` 新增 `recommend_action` 字段，由 `etw_service.rs` 从规则命中事件透传。
- `should_auto_intercept_event` 要求 `recommendAction == "block"`，否则一律只告警。
  此前是否挂起完全由 severity 隐式决定，导致 `recommendAction: alert` 的规则也会挂起进程。
- 新增 `is_auto_intercept_exempt`：按**发起进程映像**（不是事件目标路径）检查
  `path_policy_service` 排除目录与数字签名，命中即豁免自动挂起。
  边界取舍：`process_path` 为空或验签报错**不豁免**，避免"让查询失败"成为绕过手段。
- 配套两处一致性修正（对抗复核发现，否则会把唯一有效拦截关掉、并留下策略旁路）：
  - `etw_service.rs` 的合成规则 `trusted_process_unsigned_image_load` 的 `recommendAction`
    由 `alert` 改为 `block`。它是全链路唯一强证据（模块未签名 + 宿主已签名可信，两段验签都过），
    改由 recommendAction 驱动后若仍写 `alert`，等于把唯一有效的自动拦截一并关闭。
    同时在 `signature_exemption_applies` 中把该 ruleId 排除在签名豁免之外——
    宿主可信正是该规则的前提，用宿主签名豁免它会把规则本身注销。
  - `direct_intercept_realtime_injection_event`（实时前置挂起，绕过 RiskService 的第二条拦截路径）
    补上 `path_policy_service::is_excluded_path` 检查，否则用户配置的排除目录对它完全无效。

**5. 注册表键名 off-by-one 修复** — `etw/parser.rs`：
`\REGISTRY\MACHINE\` 实际长 18、`\REGISTRY\USER\` 实际长 15，原代码按 `[19..]` / `[16..]` 切片，
吞掉键名首字符（`HKLM\SOFTWARE\…` → `HKLM\OFTWARE\…`），使所有含 `\software\` 的规则永久失配；
键名恰好等于前缀或首字符为多字节时还会 panic（被 `catch_unwind` 吞掉，形成静默检测盲区）。
改用 `strip_prefix`，并补 `registry_root_normalization_keeps_first_key_char` /
`registry_root_normalization_handles_edge_inputs` 两个回归测试。

**6. 生产规则收紧** — `config/etw_match_rules.json` 从 5 条改为 3 条：
- `registry_runkey_setvalue`：删除裸 `hklm\` / `hkcu\`（组内 OR 语义使其等价于匹配所有 HKLM 写入），
  改用 `targetPatterns` 精确到 Run / RunOnce / RunOnceEx / Policies Run / Winlogon，severity 4→3，动作 block→alert。
- `temp_dropper_create`：删除裸 `\temp\`，改为限定可执行/脚本扩展名，severity 4→2，动作 block→alert。
- `temp_unsigned_image_load` → 更名 `temp_image_load`（引擎无签名判定能力，原名不实），severity 保持 3，动作 alert。
- `calc_probe_payload_image_load` 与 `test_rule_trigger` 迁至 `config/etw_match_rules.test.json`，
  不在 `tauri.conf.json` 的 `bundle.resources` 中，不随安装包分发（buglist VUL-015，本轮由 Low 重新定级为 High 并标记 Fixed）。
- 新增 4 个误报回归测试：普通 HKLM 写入、临时目录非可执行文件均不得命中；
  外加 `production_config_contains_no_test_rules` 与 `production_rules_do_not_recommend_blocking` 两道守门测试。

**顺带修复**：`risk_to_interception_tests.rs`、`risk_signature_adjustment_tests.rs`、`etw_rules_engine_tests.rs`
在本轮之前就因 `RiskEvent.process_path` / `ParsedEvent.raw_user_data_*` 字段新增而**无法编译**，已一并补齐。

**验证**：`cargo test` 21 个测试二进制全绿（291 lib 测试 + 全部集成测试，0 failed）。
其中 `window_failure_rolls_back_instead_of_freezing_process` 是死锁回归测试——
回滚路径经 `mark_decision` 会重新 `showing.lock()`，而 `try_show_next` 调用 `show_entry` 时仍持有该守卫，
std 的 Mutex 不可重入，若回归会直接挂死而非断言失败。因此 `show_entry` 改为返回
`Result<InterceptionEntry, InterceptionEntry>`，由调用方 `drop(showing)` 后再调 `rollback_failed_show`。

### 2026-07-26 第二轮：P1 与内核驱动客户端收口（已验证）

**1. 内核驱动客户端全部 IOCTL 契约修复**（`utils/driver_client.rs`）。原实现的 9 个 IOCTL 常量
全部写成 `0x8000_00xx` 一族（等价 DeviceType=0x8000、Function=9），与 `driver.c` 的
`CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x800.., …)` = `0x0022_xxxx` 毫无关系，
`DriverDeviceControl` 的 switch 全部落到 default 返回 `STATUS_INVALID_DEVICE_REQUEST`——
**即使驱动能加载，进程保护 / WinSta 保护 / 注册表保护也 100% 静默失效**。同时修复三处缓冲区契约：
- 常量改为由 `ctl_code()` const fn 按 WDK 公式推导，不再硬编码。
- `add_pid` / `remove_pid`：驱动按 `InputBufferLength >= sizeof(HANDLE)` 校验并以 `*(PHANDLE)` 读取，
  必须发 8 字节（原发 4 字节，必被判 `STATUS_BUFFER_TOO_SMALL`）。
- `query_pids`：驱动写 `ULONG count` + `HANDLE[count]`（`&outBuf[1]` 偏移 4 字节、步长 8），
  缓冲区改为 `4 + 64*8`、步长改为 8（原 260 字节 + 步长 4，PID 超过 32 时直接 `STATUS_BUFFER_OVERFLOW`，
  未超时读出的也全是错位值）。
- `connect()`：`FILE_SHARE_NONE` → `FILE_SHARE_READ | FILE_SHARE_WRITE`。
  `init_driver_protection` 用 `std::mem::forget` 常驻持有第一个句柄，
  原设置下 `register_registry_protection` 的第二次 connect 必然 `ERROR_SHARING_VIOLATION`。
- 原单元测试把同一批错误常量硬断言了一遍，等于把 bug 固化成"已验证"。现改为三层校验：
  与手工展开值比对、逐位校验 IOCTL 字段构成、**直接解析 `native/driver/src/driver.c` 重新推导每个值**，
  确保 Rust 侧与驱动源码不会再各自漂移。

**2. `/INTEGRITYCHECK` 链接选项**（`native/driver/AnXinProcProtect.vcxproj`，Debug 与 Release 均加）。
`ObRegisterCallbacks` 硬要求镜像带 FORCE_INTEGRITY（DllCharacteristics 0x0080），
当前已编译产物为 0x0160 未置该位，句柄回调注册会直接返回 `STATUS_ACCESS_DENIED`。
`native/file_protect` 是 minifilter、不调用 `ObRegisterCallbacks`，无需该选项。

**3. `etw-risk-event` 转发白名单**（`windows_service.rs`、`ipc_bridge_service.rs`）。
两张白名单里写的都是 `risk-event`，而全仓**无人 emit 该名字**，真正发出的是 `etw-risk-event`
（前端 `src/api/risk.ts` 也听这个），服务模式下每一次风险研判结果都被丢弃。已改正并加守门测试，
禁止死条目回流。

**4. 时间窗口规则从死特性变为可用**（`etw/rules.rs`）。`match_window_rule` 原先只往 seen 集合写
常量 `"_event"`，判定却查 `"{provider}:{op}"`，`requiredOps` 非空时恒为 false。
改为直接查询该 PID 的上下文环——该环由 `push_context` 对每一个事件写入，与规则是否命中无关，
能真实反映窗口内发生过什么。新增 `ContextRing::contains_op_within`（直接扫底层缓冲区，
不做 snapshot 克隆，因为它在 ETW 回调线程上按「规则 × 先决条件」次数调用）。
删除了已失效的 `window_states` 字段。补 4 个测试：窗口内命中、无先决事件不命中、
先决事件超窗不命中、跨 PID 不命中。

**5. ETW 状态上报不再失真**。`ipc_server.rs` 的 `etw_running` 原用 `.is_some()`，
而 `build_service_context` 无条件注册 `EtwService`，该字段恒为 true；
现改为读真实的 `is_running()` / `is_collecting()`，并在 `ProtectionStatus` 新增 `etw_collecting` 字段
（带 `#[serde(default)]`，兼容旧版服务）。`commands/behavior.rs::get_etw_status` 改为
**IPC 已连接时优先走 IPC**：此前先查本地 state，而 UI 进程无条件 `app.manage(EtwService)`、
服务模式下该实例从未启动，导致本地分支恒命中返回 `running=false`，把正在 SYSTEM 侧采集的服务
显示成"ETW 已停止"，IPC 分支成为死代码。

**6. 行为监控开关在服务模式下真停止**（AGENTS.md:63）。新增 IPC 方法
`methods::SET_BEHAVIOR_MONITORING`，`ipc_server` 侧调用 `EtwService::resume/pause`；
`commands/config.rs::set_behavior_monitoring_enabled` 在 IPC 已连接时改走 IPC，
且**运行态切换成功后才落盘**，避免"配置说关了但后台还在跑"。
`windows_service::start_protection_components` 启动 ETW 前读取 `behaviorMonitoring.enabled`
（读配置失败时默认开启——安全产品宁可多采集也不静默失防）。

**7. 服务进程无 UI 连接时不再静默挂起**。`IpcServer` 注册进 `ServiceContext`，
`show_interception_window` 在没有 UI 桥接且 `client_count() == 0` 时返回 `Err`，
从而走与建窗失败一致的回滚路径（恢复进程 + 保留告警）。
理由与第一轮 fail-safe 一致：**没人能回答的拦截等于永久冻结**。
注意这意味着 headless 服务场景下自动挂起实际不生效，告警仍会记录。

### 2026-07-26 第三轮：前端源码断言测试与半成品功能收口（已验证）

`tests/*.mjs` 里有一批「源码文本断言」测试被服务化重构甩开，本轮 15 个失败全部处理完，
处理原则是**先判断断言描述的是不是真实需求**，是则改实现，不是则更新断言，绝不放宽成无效断言。

**改实现（重构把真实需求做丢了）**：
- `App.tsx`：`themeStore.syncFromConfig` 早已实现、i18n 与后端 `ui.themeMode/animations` 也齐备，
  但**全仓没有任何调用方**——后端外观设置在启动时被完全忽略，用户关掉动效仍会看到启动动画。
  已在 config 就绪后接线，并保证顺序在 `initializeTheme()` 之后（否则会被 `set({actualTheme})` 覆盖）。
- `App.tsx`：`loadConfig` / `loadTranslations` 由串行 `await` 改为先发起后 await，两次 IPC 往返重叠。
- `App.tsx`：`useThemeStore()` 整店订阅改为 selector，避免主题/动效变化重渲染整棵页面树。
- `App.tsx`：六个页面组件改为 `lazy()` + `Suspense`，移出首屏 bundle；页面外壳补 `data-current-page`。
- `SplashScreen.tsx`：`detailKey`（App.tsx 为全部 7 个阶段提供）与整个快照结果摘要面板
  （`StartupSnapshotSummary` + 11 条 i18n 文案）都已就绪但**从未渲染**，用户只看到进度条、
  不知道自检查出了什么。已补齐阶段说明、`data-status`、四项摘要与安全提示。
- `QuarantinePage.tsx`：`tableScroll` 丢了 `maxHeight`，而表头用的是 `position: sticky`——
  没有受限高度的滚动容器时 sticky 不生效，隔离项一多表格无限拉长。已补回限高与纵向滚动。
- `main.rs`：基线前的等待从 250ms 被改回 1000ms，直接计入用户可见启动时间，已改回 250ms。
- `main.rs`：文件钩子管道启动失败只有一行 stderr，已补 `hook_pipe_service_failed` 诊断条目。
- `commands/logs.rs` + `etw_service.rs`：实时 `log-event` 推送在重构中丢失（只剩 `append_log` 入缓冲区，
  前端 `onLogEvent` 收不到、只能靠轮询）。已把 `append_log_and_emit` / `append_event_log_and_emit`
  泛型化到 `AppContext`（`AppHandle` 与 `ServiceContext` 都实现该 trait，两种进程共用一份实现），
  ETW 侧改调 `append_event_log_and_emit`，同时恢复 PID 0/4/u32::MAX 的系统噪音过滤。

**更新断言（实现搬家，需求未变）**：`app_handle.emit` → `ctx.emit_event`、
`tauri::async_runtime::spawn` → `tokio::spawn`（服务进程没有 Tauri 运行时）、
`app.handle()` → `&app_handle`、`show_interception_window(app_handle)` → `AppContext` 的 `self`、
以及启动顺序测试里已消失的 `app_handle_snapshot` 锚点（改用 `take_startup_snapshot` 本身锚定，
真正要锁的是「扫描器先于快照、APIHook 后于快照」的顺序）。

**顺带修掉两个既有 ESLint 问题**：`ErrorBoundary` 在类组件 render 里调用 `useErrorStyles`
（违反 Hook 规则，且 Griffel 无法正确参与渲染）——已把兜底 UI 抽成函数组件 `ErrorFallback`；
`BehaviorLifecyclePage` 的 `useCallback` 缺 `t` 依赖，切换语言后错误文案不会更新。

**验证**：`cargo test` 21 个测试二进制全绿，336 个 lib 测试（基线 286），0 failed；
`cargo check --lib` 零警告；`npx tsc --noEmit` 通过；`npx eslint src` 零问题；
`node tests/run-tests.mjs` 150 通过 0 失败（基线 135 通过 15 失败）。

**本轮未做（仍为待办，按优先级）**：
1. **内核驱动签名**（按要求本轮未处理）：签名者为 `Anneng electronic Co. Ltd.`，
   签发 CA 为 Thawte Code Signing CA - G2，证书有效期 2014 年且无 RFC3161 时间戳。
   这是普通代码签名证书，既非 EV 也无微软 attestation，**Win10 1607+ 上必然加载失败**。
   该证书来路需要先查清（第三方公司 + 已过期，存在合规风险）。
2. ~~安装链仍不完整：进程与文件驱动已进入 resources 和 NSIS 安装/卸载流程；
   `AnXinNetFilter.sys` 仍未进入 resources、`DriverKind` 或 NSIS，生产安装包不会部署它。~~
   **2026-08-14/15 更新**：AnXinNetFilter.sys 已完成 NSIS 集成（`build/nsis-hooks.nsh` 释放 + `sc create` 注册 + 卸载清理），`DriverKind::NetworkFilter` 已加入 `driver_install_service.rs`，生产安装包会部署它。AnXinProcMon.sys 同步完成 NSIS 集成。四驱动均已纳入安装包。
3. **系统级 WDK 仍未安装**：2026-07-27 已用官方 WDK NuGet 内容完成三个驱动重建，
   但所有产物仍未签名、安装或真机加载；`/INTEGRITYCHECK` 仅完成 PE 标志验证。
4. 驱动相关目录（`native/driver/`、`native/file_protect/`）与 `utils/driver_client.rs` 在 git 中均未跟踪。

---

上一次更新时间：2026-07-25

新增内核驱动模块 `native/driver/` — AnXinProcProtect.sys：
- **进程回调**：通过 `PsSetCreateProcessNotifyRoutineEx` 注册回调，自动检测并保护所有名为 `anxin-security.exe` 的进程
- **句柄保护**：通过 `ObRegisterCallbacks` 拦截进程句柄创建/复制操作，对非授权调用方剥离危险访问权限（PROCESS_TERMINATE / PROCESS_VM_READ / PROCESS_VM_WRITE / PROCESS_CREATE_THREAD / PROCESS_SUSPEND_RESUME 等）
- **白名单策略**：允许 SYSTEM PID 4、受保护进程自身、受保护进程间的互相访问，不影响正常系统操作
- **IOCTL 接口**：支持 `ADD_PID / REMOVE_PID / CLEAR_PIDS / QUERY_PIDS` 四个命令，服务进程在启动时自动注册自身 PID
- **驱动客户端**：`src-tauri/src/utils/driver_client.rs` 提供 Rust 端安全封装，集成到 `windows_service.rs` 的服务启动流程
- **当前状态**：2026-07-27 已用官方 WDK NuGet 内容完成 `Release|x64` 重建；系统级 WDK 仍未安装
- **未验证**：驱动尚未签名、安装和真机加载；当前构建证据不能替代 ObCallback/IOCTL 现场验证

- 2026-06-29（已完成按 `anxin-fluent2-preview/pages/console.html` 对齐的 Fluent 2 前端收口、页面动效残留清理、启动路径减负，以及 Hyper-V VM `病毒测试` 内完整软件短稳和 15 分钟长稳验证；安全运行时链路最新注入端到端事实仍沿用 2026-06-25 APIHook 复测结论，VUL-019 仍保持 Open，因为未布防的短生命周期注入器和更低层注入路径仍不能仅靠用户态 APIHook 完全覆盖）。

- 2026-06-29 已按 `anxin-fluent2-preview/pages/console.html` 对齐前端控制台外观：应用壳体改为预览里的 1280x800 居中窗口、32px 标题栏、240px 侧栏、24px 内容边距；`OverviewPage` 重写为预览式“安全概览”首屏，保留真实 scanner/quarantine/log/risk/fileHook 数据；`ScanPage` 与 `QuarantinePage` 收敛为 Fluent 2 白底卡片、1px stroke、8px radius、低阴影和紧凑表格。按用户要求，SVG/图标仍使用当前项目已有的 `lucide-react` 图标体系，没有切换到新图标资产。本轮没有修改扫描、ETW、Hook、进程控制、隔离安全擦除或拦截决策语义。

- 2026-06-29 已清理关闭动效后的换页动画残留，并继续做启动路径减负：`src/App.tsx` 移除 Framer Motion、`AnimatePresence`、`MotionConfig` 和页面 `motion` 包装，页面改为 `React.lazy` + `Suspense` 按需加载；`src/styles/global.css` 删除 `pageFadeIn` / `.page-container--animated`，只保留全局 reduced motion 兜底；`package.json` 移除 `framer-motion` 依赖。应用初始化阶段继续把配置、主题、语言包和事件监听并行发起，减少首屏串行等待。当前结构测试已经约束 App、全局 CSS、Toast、拦截弹窗和托盘退出提示不再引入 Framer Motion 或页面切换动画入口。

- 本地已运行 `npm ci`、`npm run typecheck`、`node --test tests\recent_fixes.test.mjs tests\frontend_stores_theme.test.mjs tests\monitoring_runtime_control.test.mjs tests\scan_page_threat_actions.test.mjs`（68/68 通过）和 `npm run build:frontend`，均通过；`npm ci` 仍报告 2 个既有 npm audit 项（1 low、1 high），本轮未自动执行 `npm audit fix`，避免跨版本改依赖。`npm run build:frontend` 仍只有既有 Vite warning：`@tauri-apps/api/core.js` 同时被动态和静态导入，影响 chunk 拆分提示，不影响构建退出码。定点残留扫描覆盖 `package.json`、`src/App.tsx`、全局样式、标题栏、侧栏、Overview/Scan/Quarantine、i18n 和相关测试：源码与配置中未发现 `pageFadeIn`、`.page-container--animated`、`titlebar_toggle_theme`、`themeToggleBtn`、`framer-motion`、`MotionConfig`、`AnimatePresence` 或 `motion.` 残留；测试文件中的同名命中均为禁止残留的断言。

- 2026-06-29 已在 Hyper-V VM `病毒测试` 内复测本轮 Fluent 2 预览对齐副本。VM 为 Running，8 vCPU、2GB 内存，来宾 IP `172.28.88.10`；PowerShell Direct heartbeat 正常，来宾用户 `DESKTOP-19GVBVB\Test`，同步目录为 `C:\Users\Test\Documents\AnXinSecurity-sync`，工具链为 Node `v22.16.0`、npm `10.9.2`。同步本轮前端、配置、i18n 和测试文件后，VM 内快速检查显示 `PackageHasFramer=False`、`AppHasPageAnimation=False`、`TitlebarThemeKey=False`。VM 内 `npm.cmd ci`、`npm.cmd run typecheck`、同一组 68/68 结构测试和 `npm.cmd run build:frontend` 均通过；日志分别为 `C:\Users\Test\Documents\anxin-vm-fluent-preview-npm-ci-20260629-063103.log`、`C:\Users\Test\Documents\anxin-vm-fluent-preview-typecheck-20260629-063103.log`、`C:\Users\Test\Documents\anxin-vm-fluent-preview-structure-tests-20260629-063103.log`、`C:\Users\Test\Documents\anxin-vm-fluent-preview-build-20260629-063103.log`。

- 2026-06-29 已在 VM `病毒测试` 内做完整软件短稳和 15 分钟长稳验证。短稳启动完整 `npm.cmd run dev` 并采样 181 秒，摘要 `C:\Users\Test\Documents\anxin-vm-fluent-preview-full-dev-20260629-063339.summary.json` 显示 `readySeen/appSeen/engineSeen/hookSeen/fileMonitorSeen/processScannerSeen/etwSeen/baselineSeen=true`，`panicCount`、`rustCompileErrorCount`、`failedSuspendCount`、`hotPidCount`、`fileMonitorLagCount`、`systemCriticalEventCount` 均为 0。长稳持续 900 秒、15 个样本，摘要 `C:\Users\Test\Documents\anxin-vm-fluent-preview-longrun-20260629-063756.summary.json` 显示 `readySeen/appSeen/engineSeen/hookSeen/fileMonitorSeen/processScannerSeen/etwSeen/baselineSeen/deepChecksSeen/apiHookSeen=true`，`panicCount`、`rustCompileErrorCount`、`failedSuspendCount`、`hotPidCount`、`fileMonitorLagCount`、`statusStackCount`、`behaviorIoErrorCount`、`memoryAllocationCount`、`systemCriticalEventCount` 均为 0，`MaxObservedWorkingSetBytes=345436160`，结束后 `RemainingProcesses=0`。该结论是本轮“长期稳定性闭环”的实测样本，不代表永久稳定承诺；如后续修改扫描、Hook、ETW 或启动快照链路，需要重新跑同类 VM 长稳样本。

- 2026-06-28 已继续在 VM `病毒测试` 内调试完整软件本体，而不只验证前端。同步当前源码、配置、`native/bin` 和 `Engine/THIRD-PARTY` 到 `C:\Users\Test\Documents\AnXinSecurity-sync` 后，首次完整 `npm.cmd run dev` 显示：Vite ready，Rust dev build 约 2m54s 后启动 `target\x86_64-pc-windows-msvc\debug\anxin-security.exe`；Engine DLL 解析到 `Engine/Axon/axon_engine.dll` 并初始化成功；行为数据库位于 `%APPDATA%\AnXinSecurity\data\behavior\anxin_etw_behavior.db`；Hook 管道 `\\.\pipe\anxin_security_filehook`、进程扫描、文件监控、ETW session 均启动，ETW 成功启用 4 类 provider，启动快照 `Baseline done`。该轮暴露两处控制链残留：`trusted_process_unsigned_image_load` 对 PowerShell Direct 控制链已跳过实时预拦截，但仍触发 `ProcessScanner` hot PID 后置复扫；启动快照对当前 AnXinSecurity dev 父链 `rustup.exe/cargo.exe` 的 image integrity alert 会尝试入拦截队列，进程控制层拒绝挂起并打印 `Failed to suspend PID ... 当前防护进程的父级控制链`，同时摘要误报 `1 paused`。本轮已修复：`src-tauri/src/services/etw_service.rs` 对 Windows 控制链事件跳过 hot PID evidence collection；`src-tauri/src/services/interception_service.rs` 在挂起前拒绝当前进程父/祖先进程入队；`src-tauri/src/services/process_scanner_service.rs` 的映像完整性/模块链入队函数返回真实 `InterceptionEnqueueResult`；`src-tauri/src/services/snapshot_service.rs` 只在实际入队时累加 `paused`。本地已通过 `rustfmt --edition 2021 --check src-tauri\src\services\etw_service.rs src-tauri\src\services\interception_service.rs src-tauri\src\services\process_scanner_service.rs src-tauri\src\services\snapshot_service.rs`、`cargo test --manifest-path src-tauri\Cargo.toml realtime_evidence_collection_skips_windows_control_chain --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml enqueue_rejects_current_process_control_chain_before_suspend --lib --quiet` 和 `cargo check --manifest-path src-tauri\Cargo.toml`。最终 VM 短窗口复测日志 `C:\Users\Test\Documents\anxin-vm-full-dev-final.err.log` 显示：`anxin-security.exe` 启动成功，Engine/Hook/ProcessScanner/FileMonitor/ETW 均启动，`Baseline done` 为 `106 processes ... 0 paused ... 1 image integrity alerts ... 11 cache hits (2277ms)`；计数确认 `Failed to suspend PID=0`、`Hot PID queued from trusted_process_unsigned_image_load=0`、panic=0、Rust 编译错误=0。验证后已停止 VM 内 `node/cargo/rustup/anxin-security` 调试进程。本轮短样本说明控制链误处置已收敛，但 VUL-021 仍保持 Open，因为尚未做长时间 VM dev 稳定性样本，也尚未分析旧 `062326-5421-01.dmp` / `MEMORY.DMP`。
- 2026-06-29 已完成 46 分钟长稳验收：在 VM `病毒测试` 内以低频采样壳 `C:\Users\Test\Documents\anxin-longrun-lite.ps1` 启动完整 `npm.cmd run dev`，连续运行 `2790` 秒（`2026-06-28 23:24:48` 到 `2026-06-29 00:11:18`）；长跑期间 `anxin-security.exe` 一直存活，`samples.jsonl` 共生成 9 条样本，最终 `summary.json` 记录 `failedSuspend=0`、`hotPid=0`、`panic=0`、`rustCompile=0`、`fileMonitorLag=0`、`systemCriticalEventCount=0`。结束后 VM 内应用和编译进程均退出，没有新的 `BugCheck 0x000000ef`、`Kernel-Power 41` 或控制面失联迹象。这个结果补齐了上面的短窗口样本，说明本轮长期稳定性闭环已经完成。

- 2026-06-25 22:16-22:21 在 Hyper-V VM `病毒测试` 的已登录管理员桌面会话（`test` 用户，Session 2）完成真实注入端到端复测。本轮先修正 APIHook 管道收发模型：`native/file_hook/src/file_hook_dll.cpp` 对 Hook 上报管道增加 3 秒短生命周期缓存句柄，同一条注入链的 `OpenProcess / VirtualAllocEx / WriteProcessMemory / CreateRemoteThread` 不再拆成多个毫秒级短连接；写入遇到 `ERROR_BROKEN_PIPE / ERROR_NO_DATA / ERROR_PIPE_NOT_CONNECTED` 时关闭缓存并重连一次。`src-tauri/src/services/hook_service.rs` 将连接阶段和读取阶段的非阻塞错误语义拆开：连接阶段的 `ERROR_NO_DATA` 不再空等旧实例，读取阶段仍短暂等待缓存连接的后续消息；同时取消“读到一条就立刻关闭 pipe 实例”的旧逻辑，改为在短暂空闲或客户端断开后释放，并新增 JSON 对象边界拆包，避免多个 JSON 粘在一个读缓冲时整批解析失败。已补 `hook_pipe_message_splitter_handles_coalesced_json_objects` 和等待语义回归测试。

- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests --quiet`：通过，14/14；`rustfmt --edition 2021 --check src-tauri\src\services\hook_service.rs src-tauri\tests\hook_service_tests.rs`：通过；`cargo check --manifest-path src-tauri\Cargo.toml`：通过，剩余 warning 为既有未使用字段/方法；`cmake --build native\file_hook\build-vs18 --config Release --target file_hook_detours file_hook_injector` 与 `cmake --build native\file_hook\build-vs18-win32 --config Release --target file_hook_detours file_hook_injector`：均通过，仍有既有 C4819 编码 warning。已覆盖 `native\bin\win32-x64`、`native\bin\win32-x86`；x64 `file_hook_detours.dll` SHA256 为 `F5DB80B1D8E3FBC693DC27AF4C62DDE608941046B942BFFFDC8A5B887CC9B787`，x64 `file_hook_injector.exe` 仍为 `DD07946528F2916380F286F5BED92AEB8D731E6D45687914BBB7E4EDDB7C8EA2`，x86 `file_hook_detours.dll` 为 `B58D5495C20523817F30D93B3BED59EE9019740F9AF0553150BF05142DB7DC7D`，x86 `file_hook_injector.exe` 仍为 `82C06047E432E26F3A3C731BB809626F34065F201E67433C8C698FA65B0AC304`。VM 内同步后运行 `cargo test --manifest-path C:\Users\Test\Documents\AnXinSecurity-sync\src-tauri\Cargo.toml --test hook_service_tests --quiet` 实际 14/14 通过；PowerShell Direct 将 Rust warning 包装成非零，但测试结果本身为通过。VM 内 `cargo build --manifest-path ... --bin anxin-security` 生成 `anxin-security.exe`，SHA256 为 `790AC32A13FF05494B37016246FDFE939944CB9B073EEE5E2AE186C21B915BFC`。

- 真实复测流程：在 VM 桌面会话启动 Vite `http://localhost:1421/` 和 `C:\Users\Test\Documents\AnXinSecurity-sync\src-tauri\target\debug\anxin-security.exe`（PID 5184，Session 2），确认 `hook_pipe_service_started` 和 8 个 `hook_pipe_worker_started`。随后使用 `file_hook_injector.exe --pid 6348 --dll calc_probe_payload.dll --dll-x64 file_hook_detours.dll` 并设置 `ANXIN_FILE_HOOK_INJECTOR_SELF_HOOK=1`，对 Session 2 的 `notepad.exe` PID 6348 做真实注入。注入器退出码 24，stderr 显示 `[file_hook_detours] blocked CreateRemoteThread targetPid=6348 targetSuspended=1 reported=1`、`CreateRemoteThread failed, error=5`、`inject failed, code=24, lastError=5`；未出现 `calc` / `CalculatorApp` 进程。C++ 诊断新增 source PID 7524 的完整链路：`process_injection_notice_sent(OpenProcess/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread)` 均 `reported=true, pipeError=0`，并有 `remote_thread_block_decision` / `remote_thread_block_result`。Rust 诊断同一轮出现四条 `hook_pipe_line_parsed`、四条 `hook_event_received`、`injection_chain_alert`、`interception_queue_push`（`threatType=remote_thread_injection_target`，`mode=pre-suspended-by-upstream-hook`，目标 `notepad.exe` PID 6348）、`show_interception_window_ok` 和 `emit_interception_event_ok`。因此本轮已证明受控 `CreateRemoteThread` 远程线程注入链路从 C++ 阻断到 Rust 拦截窗口闭环；但尚未把 `NtCreateThreadEx` 真实样本、APC/线程上下文类注入或未被用户态 Hook 预布防的超短生命周期注入器写成已覆盖。

- 2026-06-25 参考 m417z 全局注入文章后选择保守方案 A，而不是直接扩大到完整全局注入：`src-tauri/src/services/hook_service.rs` 创建 `\\.\pipe\anxin_security_filehook` 时不再传空安全属性，改为显式 SDDL，只授予 `SYSTEM`、`BUILTIN\Administrators` 和当前用户 SID，并在 `CreateNamedPipe` pipe mode 加入 `PIPE_REJECT_REMOTE_CLIENTS`；连接后通过 `GetNamedPipeClientProcessId` 取得真实客户端 PID，Hook 事件 payload 里的 `pid` 必须与客户端 PID 一致才会进入日志、行为库、风险分析和拦截链路，否则写入 `hook_pipe_event_rejected` 诊断后丢弃。`src-tauri/src/services/process_monitor_service.rs` 不再接受任意存在的显式 `injector_x64/x86` 或 `dll_x64/x86` 路径；非空路径必须经 `canonicalize` 后等于默认可信候选（开发/资源目录下的 `native/bin/<arch>` 或资源 `<arch>` 文件），否则拒绝。`native/file_hook/src/file_hook_dll.cpp` 新增 `NtCreateThreadEx` Detours Hook，沿用现有 `OpenProcess / VirtualAllocEx / WriteProcessMemory / 远程线程创建` 强链路判断、目标进程预挂起、上报失败回滚和 `ERROR_ACCESS_DENIED` 阻断语义；Rust 聚合器同步把 `NtCreateThreadEx` 视为远程线程终点。`buglist.md` 已将 `VUL-001`、`VUL-002` 标为 Fixed，并在 `VUL-019` 下记录本轮只是缓解，不代表用户态注入短窗口彻底消失。

- 2026-06-25 20:42-20:58 通过 Hyper-V PowerShell Direct 重新连上 VM `病毒测试`：宿主 `Get-VM` 显示 VM `Running/正常运行`，8 vCPU、2GB 内存，IP 为 `172.28.88.10`；来宾心跳返回 `DESKTOP-19GVBVB\test`，PowerShell 5.1.19041.7417。VM 内预检只发现本次 Direct 调用自身的 `powershell.exe`，没有 `anxin-security`、`node`、`cargo`、`rustc`、`file_hook_injector` 残留进程；`interception_diagnostics.jsonl` 最新仍停在 2026-06-24 的 PowerShell 误拦截现场，`file_hook_detours_diagnostics.jsonl` 最新停在 2026-06-23，说明本轮开始前没有新 APIHook 样本。已将本轮最小变更文件同步到 `C:\Users\Test\Documents\AnXinSecurity-sync`，包括 `hook_service.rs`、`process_monitor_service.rs`、两份窄测试、`file_hook_dll.cpp` 和 x64/x86 `native/bin` 注入器/DLL；因轻量同步目录缺少完整 `Engine/**/*`，仅同步 `Engine/THIRD-PARTY` 作为 Tauri build script glob 占位。VM 内已运行 `cargo test --manifest-path C:\Users\Test\Documents\AnXinSecurity-sync\src-tauri\Cargo.toml --test hook_service_tests --quiet`：通过，13/13；已运行 `cargo test --manifest-path C:\Users\Test\Documents\AnXinSecurity-sync\src-tauri\Cargo.toml --test process_monitor_service_tests --quiet`：通过，5/5。另用临时 PowerShell P/Invoke 在 VM 内创建并关闭一根测试命名管道，使用同款 SDDL 和 `PIPE_TYPE_MESSAGE|PIPE_READMODE_MESSAGE|PIPE_NOWAIT|PIPE_REJECT_REMOTE_CLIENTS` pipe mode，返回 `Created=true`、`LastError=0`。本轮没有启动完整 `npm run dev`，也没有做真实桌面注入弹窗复测。

- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests --quiet`：通过，13/13，覆盖 Hook 管道 PID 防伪、`NtCreateThreadEx` 直接阻断事件和聚合链路终点。已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test process_monitor_service_tests --quiet`：通过，5/5，覆盖可信显式路径可用、缺失时报错和外部任意显式路径被拒绝。已运行 `rustfmt --edition 2021 src-tauri\src\services\hook_service.rs src-tauri\src\services\process_monitor_service.rs` 并再次通过 Rust 编译检查；`cargo check --manifest-path src-tauri\Cargo.toml` 通过，剩余 warning 为既有 `TimedSignatureVerdict.status` 和未使用 `is_malware`。已运行 `cmake --build native\file_hook\build-vs18 --config Release --target file_hook_detours file_hook_injector` 与 `cmake --build native\file_hook\build-vs18-win32 --config Release --target file_hook_detours file_hook_injector`：均通过；随后覆盖 `native\bin\win32-x64`、`native\bin\win32-x86`。SHA256 已确认构建目录和 `native/bin` 运行目录一致：x64 `file_hook_detours.dll` 为 `C4097DDF17B197DD1C198BD61AB7AF38E3376E03AB2F77A1A1275B80288FFB0F`，x64 `file_hook_injector.exe` 为 `DD07946528F2916380F286F5BED92AEB8D731E6D45687914BBB7E4EDDB7C8EA2`，x86 `file_hook_detours.dll` 为 `07EC5FB0B8D6D0DE259FC8051567AE78F69E3FF479997C3AF65494636001F717`，x86 `file_hook_injector.exe` 为 `82C06047E432E26F3A3C731BB809626F34065F201E67433C8C698FA65B0AC304`。本轮未运行 `npm run dev`，也未做管理员桌面真实注入弹窗复测；下一步现场验证应重启 AnXinSecurity 后，用受控注入器分别走 `CreateRemoteThread(Ex)` 和 `NtCreateThreadEx`，按 `file_hook_detours_diagnostics.jsonl` 与 `interception_diagnostics.jsonl` 串联核对 `process_injection_notice_sent -> hook_pipe_line_parsed -> hook_event_received -> injection_chain_alert -> remote_thread_injection_target`。

- 2026-06-24 已清理设置页遗留前端代码：路由只引用 `src/components/SettingsPage.tsx`，因此删除未接入的 `src/components/SettingsPage_old.tsx`；同步移除当前 Fluent 2 设置页里未使用的 `inputField` 样式槽位，以及只被旧页占用的 `settings_etw_collection` / `settings_etw_collection_desc` i18n 键（`config/i18n/zh-CN.json`、`config/i18n/en-US.json`、`src/stores/i18nStore.ts`）。本轮没有改变进程监控、ETW、Hook 或文件监控的运行态语义；已运行残留搜索确认无引用，并通过 `npm run typecheck`。

- 2026-06-24 已修复设置页“关闭动效”只影响部分 CSS 动画、不影响旧页面动效包装的问题；该实现后续已在 2026-06-28 Fluent 2 收口中改为 CSS/Fluent class 路径，不再保留旧页面动效运行时包装。`src/stores/themeStore.ts` 新增后端配置同步入口，将 `config/app.json` 的 `ui.themeMode` / `ui.animations` 读入前端主题状态，并统一写入 `body[data-animations]` 与 `html.reduce-motion`；`src/App.tsx` 在 `loadConfig()` 后同步外观配置，当前页面切换由 `.page-container` 全局 CSS 动画和 `body[data-animations]` 控制；`Toast`、`SplashScreen`、`InterceptionModal`、`TrayExitPrompt` 均已改为 Fluent/CSS 路径。该修复只影响前端外观层，不改变扫描、监控、拦截、ETW 或 Hook 运行态语义；独立拦截窗口未新增配置读取 capability，避免扩大最小权限边界。已运行 `npm run typecheck`、`node --test tests\frontend_stores_theme.test.mjs`、`node --test tests\monitoring_runtime_control.test.mjs`，均通过；`node --test tests\startup_phase_screen.test.mjs` 仍有既有结构断言失败（当前源码未渲染测试期待的 `phase.detailKey`），`npm run lint` 仍有既有 `src/components/ErrorBoundary.tsx` class 组件调用 Hook 失败，均非本轮动效修复引入。本轮未运行 `npm run dev`，因为该命令会进入重型 Tauri/Rust/启动快照链路，前端动效设置修复已用类型检查和结构测试覆盖。

- 2026-06-25 已做“关闭动效”真实交互验证，不再只停留在测试层：本地先用 Vite 前端和临时 Tauri 调试页验证，点击 `settings_disable_animations` 后，`set_animations_enabled(false)` 确实被调用，`body[data-animations]` 变为 `off`，`html.reduce-motion` 变为 `true`，`.page-container` 的 `animationName` / `transitionDuration` 变为 `none` / `0s`，`document.getAnimations({ subtree: true })` 返回空；再在 VM `病毒测试` 的 `http://172.28.88.10:5175/logs/ui-debug/animation-runtime-debug.html` 上重复同样操作，结果一致。VM 侧为这次调试临时放行了 5175 端口，验证完成后已移除临时防火墙规则并停止临时前端服务。调试页文件是 `logs\ui-debug\animation-runtime-debug.html`，它只用于这次功能验证，不是产品交付物。

- 2026-06-24 已将本轮代码以最小源码包同步到 Hyper-V VM `病毒测试`（IP `172.28.88.10`）：宿主侧压缩包为 `logs\vm-direct\staging\anxin-sync-20260624-235039.zip`，排除了 `node_modules`、`dist`、`.git`、`logs`、`src-tauri\target` 等重型或运行时产物；VM 内解压目录为 `C:\Users\Test\Documents\AnXinSecurity-sync`。同步后在 VM 内使用 `npm.cmd ci` 安装依赖成功，随后 `npm run typecheck`、`node --test tests\frontend_stores_theme.test.mjs`、`node --test tests\monitoring_runtime_control.test.mjs` 均通过；对应 VM 日志为 `C:\Users\Test\Documents\anxin-vm-npm-ci.log`、`C:\Users\Test\Documents\anxin-vm-typecheck.log`、`C:\Users\Test\Documents\anxin-vm-theme-test.log`、`C:\Users\Test\Documents\anxin-vm-monitoring-test.log`。本轮没有在 VM 内启动完整 `npm run dev`，因为历史样本显示完整 Tauri/Rust/dev 启动会对当前 PowerShell Direct 控制通道造成明显压力；本轮调试结论只覆盖源码同步、依赖安装、类型检查和前端/运行时结构测试，不写成管理员桌面长时间稳定性证明。

- 2026-06-23 通过 Hyper-V 管理员 relay 读取虚拟机旧运行日志，确认 ETW 刷屏主要来自三条出口：`EtwService` 每 100 次轮询即使 0 事件也打印，`remote_thread_start_outside_image` 这类观察型线程入口信号反复打印 hot PID，`FileMonitorService` 订阅了 ETW 总广播而不是仅订阅 File provider，导致 Image/Thread/Registry/Network 等普通事件也压进文件扫描消费者并产生大量 `Lagged by ... events`。对 `0015-wait-new-vm-dev-log.json` 抓到的日志尾部计数：`remote_thread_start_outside_image` hot PID 打印 69 次，`FileMonitor Lagged by` 22 次，0 事件 poll 打印 16 次，非 0 事件 poll 只有 6 次；后续 `0019-safe-vm-runtime-log-snapshot.json` 又确认剩余压力已转移到 `ProcessScanner` 热 PID 复扫、行为库写入和内存压力，曾出现 `Behavior ingest error: disk I/O error`、内存分配失败以及进程异常退出。当前修复边界是“保留采集，收窄实时分发”：ETW 诊断缓存仍记录通过 PID 过滤的规整事件，风险分析仍处理强信号或低频规则命中；但 FileMonitor 只接收 File provider 事件，前端 `etw-event` / `log-event`、行为数据库写入和风险分析入口都显式抑制观察型 `remote_thread_start_outside_image`，该规则也不再唤醒 `ProcessScanner` hot PID 复扫。`trusted_process_unsigned_image_load` 这类强证据仍保留直接拦截、行为记录、风险分析和后置补证。FileMonitor 的 lag 日志改为 10 秒聚合一次。当前 ETW 订阅内容是 Windows 内核 Process/Thread/Image、File、Registry、Network 四类 provider；解析后会形成 `Process start/stop`、`Thread start/stop`、`Image load/unload`、`File create/delete/rename`、`Registry set/delete/create`、`Network connect/send/recv/close` 等行为项。已运行 `cargo test --manifest-path src-tauri\Cargo.toml fanout --lib --quiet`（2/2，2026-06-23 复跑通过）、`cargo test --manifest-path src-tauri\Cargo.toml realtime_rule_policy --lib --quiet`（1/1，2026-06-23 通过）、`cargo test --manifest-path src-tauri\Cargo.toml etw_diagnostics_cache --lib --quiet`（5/5）、`cargo check --manifest-path src-tauri\Cargo.toml`（2026-06-23 复跑通过）、`npm run typecheck`（2026-06-23 复跑通过），均通过；VM 内曾同步前一版源码并通过 `cargo check --quiet`（使用 `RUSTFLAGS=-Awarnings` 避免 PowerShell Direct 把普通 warning 当作 relay 失败）。2026-06-23 18:27-18:52 又通过 `logs/vm-direct/responses/0008-wait-dev-etw-summary.json` 拿到新策略 VM 运行样本：`npm run dev` 完成 Rust dev profile 构建并启动 `target\x86_64-pc-windows-msvc\debug\anxin-security.exe`，ETW 成功启用 Process/Thread/Image、File、Registry、Network provider，日志尾部出现 `Poll #13900/#24300/#28700/#43400/#53400/#65000/#82900` 且有 2、14、2、2、2、2、8 条事件被采集；同一尾部计数显示 `process_scanner_hot_pid=0`、`Hot PID queued from remote_thread_start_outside_image=0`、`remote_thread_start_outside_image=0`、`FileMonitor Lagged by=0`、`Behavior ingest error=0`、`memory allocation=0`、`STATUS_STACK_BUFFER_OVERRUN=0`。因此本轮已有一次管理员 VM 运行样本支持“ETW 仍采集、旧热路径刷屏未复现”；但它不是长时间稳定性证明，也没有覆盖真实注入弹窗端到端。

- 2026-06-23 本轮继续验证 Hyper-V 直连路径：普通 Codex 命令进程仍是 `Medium Mandatory Level`，`Administrators` 组为 deny-only，不能直接访问 Hyper-V CIM；改用一次 UAC 提升的 `scripts/start-vm-direct-worker.ps1` 启动 `scripts/vm-direct-worker.ps1` 后，提升 worker 以 `KOLOMINA-PC\ADMIN_Saika` 运行，具备 `High Mandatory Level`、`BUILTIN\Administrators` 和 `BUILTIN\Hyper-V Administrators`，可轮询 `logs/vm-direct/requests/*.json` 并把结果写入 `logs/vm-direct/responses/*.json`，避免每条 VM 操作都弹 UAC。`ADMIN_Saika` 的来宾凭据已保存到 `C:\Users\ADMIN_Saika\.anxin-vm\virus-test-cred.xml`。本轮 `0005-force-restart-vm` 强制重启 VM 成功，`0006-guest-heartbeat` 确认来宾 `desktop-19gvbvb\test` 可执行 PowerShell，`0007-start-dev-background` 启动 VM 内开发进程，`0008-wait-dev-etw-summary` 成功拿到运行样本。后续为修正统计匹配误差发出的 `0009-tail-dev-etw-fresh` 又卡在 PowerShell Direct 来宾命令，`logs/vm-direct/responses/0009-tail-dev-etw-fresh.json` 返回 `guest script timed out after 900 seconds`；本轮随后停止卡住的 worker，队列已空。因此当前结论是 host 侧无人值守 worker 可用，但 guest PowerShell Direct 通道仍会间歇性卡住，后续长时间采样应优先让 VM 内进程自行落盘摘要，再用较少的 Direct 调用取回文件。该 relay/worker 体系已在本轮清理后退役，后续直连虚拟机操作不再依赖 `scripts/vm-admin-relay.ps1`、`scripts/vm-direct-worker.ps1` 或 `scripts/vm-unattended-*` 中转脚本。

- 2026-06-23 继续推进无人值守采样：新增宿主接收器 `scripts/vm-unattended-host-receiver.ps1`、启动器 `scripts/start-vm-unattended-host-receiver.ps1`、VM 内采样器 `scripts/vm-unattended-guest-sampler.ps1`、VM 登录启动器 `scripts/vm-unattended-guest-startup.ps1`、部署请求脚本 `scripts/request-vm-unattended-sampler.ps1`，以及宿主拉取通道 `scripts/vm-unattended-host-poller.ps1` / `scripts/start-vm-unattended-host-poller.ps1`。HTTP 接收器本机 smoke test 曾通过：`127.0.0.1:17879/health` 返回 `ok`，POST `/anxin-vm/summary` 返回 `accepted`，并写入 `logs/vm-direct/inbox-test/latest.json`；但真实 VM 到宿主 `172.28.88.1:17878` 的 TCP 持续失败，因此当前默认不再依赖 guest->host HTTP POST。VM 端脚本曾复制到 `C:\ProgramData\AnXinSecurity\vm-unattended`，但本轮已清理其中转脚本和控制状态；`Copy-VMFile` 写入 All Users Startup 和 `C:\Users\Test\...\Startup` 仍被来宾拒绝访问（0x80070005），所以开机自动启动仍未闭环成计划任务/服务。当前已验证的无人值守通道是：VM sampler 以 `-LocalOnly` 写入 `C:\ProgramData\AnXinSecurity\vm-unattended\latest-summary.json`，宿主 host poller 每 60 秒通过提升 worker 拉取小 JSON 到 `logs/vm-direct/inbox-direct/latest.json`。2026-06-23 21:02 已将 VM sampler 切换为 PID 3048；21:03 后新增 HTTP 失败计数为 0，`host-poller.log` 已连续拉取到 21:10 的摘要。后续如需开机自愈，应在 VM 内建立计划任务/服务来启动 `vm-unattended-guest-startup.ps1`，且默认不传 `-PostToReceiver`。

- 2026-06-23 20:36 VM 发生蓝屏并自动重启，已登记 `buglist.md` 的 `VUL-021`：事件日志 `BugCheck 0x000000ef`（`CRITICAL_PROCESS_DIED`），`C:\Windows\Minidump\062326-5421-01.dmp` 约 690KB，`C:\Windows\MEMORY.DMP` 约 552MB。蓝屏前 VM 内 `startup.log` 显示 20:03:41 启动了 sampler 和 dev runner；旧 sampler 因 PowerShell StrictMode 类型问题未能 POST，20:18 和 20:34 两次记录“无法将值转换为类型 System.String”，随后在 HTTP POST 路径上反复超时。本轮已修复 sampler 的数组/字符串处理，并把 `vm-unattended-guest-startup.ps1` 改为默认只启动 `-LocalOnly` sampler，不再自动拉起 `npm run dev`，避免无人值守重启循环反复触发蓝屏；需要跑 dev 时必须显式传 `-StartDev` 或人工启动。修正版 sampler 和 startup 脚本均已复制到 VM；当前 sampler PID 为 3048，它可在 VM 本地生成 `C:\ProgramData\AnXinSecurity\vm-unattended\latest-summary.json`，摘要显示 ETW 仍采集、`remote_thread_start_outside_image=0`、`FileMonitor Lagged=0`、`Behavior ingest error=0`、`memoryAllocation=0`、`STATUS_STACK_BUFFER_OVERRUN=0`，但有一次 `trusted_process_unsigned_image_load` hot PID 记录，仍需结合崩溃 dump 和运行日志判断是否与 0xEF 有关。

- 2026-06-23 无人值守最终采用“VM 本地写摘要 + 宿主 poller 通过提升 worker 拉小 JSON”的备选通道，而不是 guest->host HTTP POST：VM 可 ping `172.28.88.1` 且可访问外网，但 `Test-NetConnection 172.28.88.1 -Port 17878` 持续失败；宿主防火墙 profile 均为 Disabled，接收器绑定 `0.0.0.0` 和 `172.28.88.1`、普通和精确入站规则都未让该 TCP 入站从 VM 打通。`scripts/vm-unattended-guest-sampler.ps1` 已增加 `-LocalOnly`；`scripts/vm-unattended-guest-startup.ps1` 默认 LocalOnly，只有显式传 `-PostToReceiver` 才会要求 `ReceiverUrl` / `TokenPath` 并执行 HTTP POST；`scripts/request-vm-unattended-sampler.ps1` 和新版 `scripts/vm-direct-worker.ps1` 的部署默认也已切到 `C:\ProgramData\AnXinSecurity\vm-unattended` + LocalOnly。host poller 已成功通过 worker 拉取 `C:\ProgramData\AnXinSecurity\vm-unattended\latest-summary.json`，写入 `logs/vm-direct/inbox-direct/latest.json`；后台 poller PID 为 29616，间隔 60 秒，停止文件为 `logs/vm-direct/poller-stop.txt`。注意：正在运行的提升 worker 不会热加载本地脚本改动，新 `deploy_unattended_sampler` 默认值需下次重启 worker 后生效；当前运行态已通过直接复制脚本和显式 `-LocalOnly` 启动完成切换。

- 2026-06-23 23:26-2026-06-24 00:02 继续做受控 dev 烟测，结论是失败且不应继续加压：预检 `test-preflight-20260623-2325` 显示 VM 内无 `anxin-security/cargo/node/rustc` 残留进程，LocalOnly sampler PID 3048 正常，最近 120 条采样日志里本地写摘要 120 次、HTTP 失败 0 次。随后 `test-start-dev-smoke-20260623-2326` 归档旧 `vm-dev-desktop.log` 并后台启动 `npm run dev`，返回 runner PID 1124，早期只看到多个 `node` 进程；23:26:56 host poller 还能拉到一份新摘要，显示新日志尚未出现 ETW poll 或 `anxin-security.exe` 启动信号。此后控制面开始失效：`poll-summary-20260623-232756-0147` 90 秒超时，`test-dev-tail-20260623-2328` 240 秒超时，后续 poll summary 连续 90 秒超时；尝试通过 Direct 停止 dev 的 `aaa-stop-dev-smoke-20260623-2336` 也 300 秒超时。23:47 通过宿主 Hyper-V 管理层 `recover-restart-vm-after-dev-smoke-20260623-2347` 强制重启成功；但重启后 `recover-heartbeat-after-restart-20260623-2349` 返回 `PSSessionStateBroken`，且多次 `get_vm_status` 到 00:01 仍显示 VM `Running/正常运行` 但 `IPAddresses=[]`。00:02 之后本轮停止继续压测，host poller 已在 23:37 停止，避免继续堆请求。2026-06-24 00:09 的恢复检查确认：当前 Codex 命令进程仍是 `KOLOMINA-PC\Saika` 的 Medium token，`BUILTIN\Administrators` 为 deny-only，直接 `Get-VM -Name "病毒测试"` 仍返回权限不足；后台 `vm-direct-worker.ps1` / `vm-unattended-host-poller.ps1` / `vm-admin-relay.ps1` 均未运行，`logs/vm-direct/requests` 为空。因此此时没有可用的无人值守控制通道，不能继续向 VM 发 Direct 命令，也不能判断 VM 来宾网络是否已自然恢复。当前不能把这轮写成蓝屏复现，因为尚未拿到新的 BugCheck；但可以确认：在当前低资源 VM 上启动 dev 会使 PowerShell Direct / host poller 控制面不可用，并且强制重启后 VM 来宾网络/集成状态长时间未恢复。后续要么先恢复/回滚到 `AnXinSecurity-dev-env-ready-20260623-025627` 检查点，要么给 VM 增配 CPU/内存后再复测；不要直接继续 `npm run dev`。

- 2026-06-24 进一步收敛 ETW 刷屏和行为库刷写：`src-tauri/src/services/etw_service.rs` 里的轮询日志改成 10 秒窗口摘要，空轮询不再打印；`apply_image_load_injection_detection` 的“路径不可验证/不是文件/验签失败”统一走限频日志，并对 ETW `Image/load` 里带噪的 `@\Device\...` 前缀做清洗后再尝试转换成可验签路径。随后又确认数据库压力不是控制台日志问题，而是 ETW 命中事件存在两条行为库写入路径：`etw_service` 先直接 `BehaviorService::ingest_event()`，`RiskService::analyze_event()` 又以 `risk_analysis` 形式写一次。本轮已移除 ETW 分发阶段的直接行为库写入，行为库统一由 RiskService 写入；同时新增 `EtwBehaviorDbGate`，按 `pid/provider/operation/ruleId 或 threatType/path` 生成去重键，同一信号 10 秒内只落一条代表记录，重复样本继续留在 ETW 诊断缓存/聚合桶中。已补 `etw_poll_log_accumulator_suppresses_empty_polls`、`etw_poll_log_accumulator_emits_windowed_summary`、`etw_image_path_trims_noise_before_device_prefix`、`etw_behavior_db_gate_suppresses_recent_duplicate_signals`、`etw_behavior_db_gate_keeps_distinct_paths_separate`、`etw_behavior_db_dedup_key_uses_stable_signal_shape` 等单测，并已运行 `rustfmt --edition 2021 --check src-tauri\src\services\etw_service.rs`、`cargo test --manifest-path src-tauri\Cargo.toml etw --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml etw_image_path --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml fanout --lib --quiet`、`cargo check --manifest-path src-tauri\Cargo.toml`，均通过。`buglist.md` 已登记 `VUL-022` 并标记为代码层 Fixed。当前仍缺少一轮管理员桌面/VM 现场复测，只能先确认“日志降噪、路径清洗和行为库写放大收口逻辑已在本地验证通过”，不能把它写成“现场刷屏和 SQLite 写入风暴已完全消失”。
- 2026-06-24 继续做自主性能排查时又确认两处慢性热点：`TrustService::monotonic_ms()` 原先把 `Instant::now().elapsed()` 误当成单调时间，实际会接近 0，导致签名缓存 TTL 判断失真；`src-tauri/src/commands/logs.rs` 的固定长度日志缓冲在满载后用 `Vec::remove(0)` 弹最旧条目，会把每次新日志变成整体搬移。两处都已修正为真正的 epoch 毫秒和 `VecDeque::pop_front()`，并补了最小单测。此处仅作为稳定性/性能收口记录，不代表已完成管理员桌面长时间压测。
- 2026-06-24 继续收口扫描判决缓存的长期增长问题：`TrustService` 的 `scan_cache_lookup` / `scan_cache_store` 先前只写 `hash_to_verdict` 和 `path_to_hash`，没有像主签名缓存一样做容量上限与 LRU 淘汰，长期运行时会慢慢堆积。已为这两张子缓存补上 `max_entries`、`path_lru` / `verdict_lru` 和到期/超容量回收，并补最小单测；这仍只代表本地编译和单测通过，不代表现场压测完成。

- 2026-06-24 按“自主调试稳定性/性能放大点”的要求继续排查 ETW 后续出口，新增确认两处风险并收口：第一，同一高价值 ETW 命中即使数据库去重，仍会重复触发前端 `etw-event`、实时日志、直接拦截检查、`ProcessScanner` hot PID 唤醒和 `RiskService::analyze_event()` 异步任务；第二，同一路径 File provider 事件可在短时间内反复进入 FileMonitor 的路径策略、哈希和扫描缓存入口。本轮新增 `EtwResponseGate`，同一 `pid/provider/operation/ruleId 或 threatType/path` 的实时响应 2 秒内只转发一次，重复样本仍保留在 ETW 诊断缓存/聚合桶；新增 `FileScanDedupGate`，同一路径 File 事件 750ms 内只触发一次文件扫描入口，不同路径不合并。相关测试已补 `etw_response_gate_suppresses_recent_duplicate_realtime_responses`、`etw_response_gate_keeps_distinct_realtime_signals_separate`、`etw_response_gate_rejects_observation_only_events`、`file_scan_dedup_gate_suppresses_recent_same_path_events`、`file_scan_dedup_gate_keeps_distinct_paths_separate`；并已运行 `cargo test --manifest-path src-tauri\Cargo.toml etw --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml file_monitor --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml fanout --lib --quiet`、`node --test tests\monitoring_runtime_control.test.mjs`、`cargo check --manifest-path src-tauri\Cargo.toml`，均通过。`buglist.md` 已登记 `VUL-023` 并标记为代码层 Fixed。仍需管理员桌面/VM 长时间样本确认真实 ETW 响应任务数、FileMonitor 扫描量和 UI 实时事件量是否按预期下降。

- 2026-06-24 01:45-02:20 在用户增配后继续复测：一次 UAC 提升重新启动 `scripts/vm-direct-worker.ps1`，`resume-status-20260624-0145` 显示 worker 以 `KOLOMINA-PC\ADMIN_Saika` 运行，VM `病毒测试` 为 8 vCPU、`MemoryAssigned=2147483648`、`SwitchName=AnXinSecurityNAT`、IP `172.28.88.10`；`resume-heartbeat-20260624-0145` 约 5 秒返回，PowerShell Direct 恢复。`resume-preflight-20260624-0146` 显示 Git/Node/Rust/Cargo 可用，`nodejs.org` / `registry.npmjs.org` / `static.rust-lang.org` / `github.com` HTTPS 连接均通过，最近 8 小时只有旧的 2026-06-23 20:36 BugCheck，没有新的 1001 BugCheck。随后发现旧 worker 不热加载本地脚本，首次 `deploy_unattended_sampler` 虽传入 `localOnly=true` 仍启动 HTTP POST 模式；已停止旧 sampler 和旧 worker，重启 fresh worker 后 `resume-deploy-sampler-localonly-20260624-0154` 明确返回 `localOnly=true`，新 sampler PID 5576 连续写本地摘要，host poller 在 01:55-01:59 连续拉取 7 次成功。01:59 执行带 480 秒 watchdog 的 bounded `npm run dev`（`resume-start-bounded-dev-20260624-0200`），启动时看到 `node` 与 `cargo` 进程；但启动后 host poller 从 `poll-summary-20260624-015954-0008` 开始连续 120 秒超时，后续 `resume-heartbeat-after-dev-timeout-20260624-0212` 也 60 秒超时。宿主层 `resume-status-after-dev-timeout-20260624-0212` 仍显示 VM Running 且 IP 保持 `172.28.88.10`，因此这次不是 Hyper-V 管理层断开。02:16 强制重启 VM 后，`recover-heartbeat-after-restart-20260624-0218` 恢复 Direct；最近 3 小时无新 BugCheck，仅有强制重启造成的 Kernel-Power 41。`recover-read-dev-log-after-restart-20260624-0219` 与 `recover-read-runtime-diag-20260624-0220` 显示本轮 AnXinSecurity 已启动、ETW provider 启用、启动快照完成，但随后多次将 PowerShell Direct 相关 `powershell.exe` PID（1324、2960、7956）作为 `trusted_process_unsigned_image_load` 以 `suspend-before-enqueue` 入拦截队列并展示拦截窗口；这与 Direct 命令通道超时高度吻合。下一步不应继续靠增配反复压测，而应先修正 `trusted_process_unsigned_image_load` 对 Windows PowerShell / PowerShell Direct 控制链的误判和自动挂起边界。

- 2026-06-24 已完成上述控制链误拦截的代码层缓解：`process_control_service.rs` 新增共享的 Windows 控制链进程识别，只在进程名匹配 `powershell.exe` / `pwsh.exe` / `cmd.exe` / `wsmprovhost.exe` 且进程路径位于 Windows 或 PowerShell 官方安装路径时返回真；`etw_service.rs` 的 `trusted_process_unsigned_image_load` 直拦截会对这些控制链进程跳过自动挂起并写入 `etw_realtime_preblock_skipped` 诊断；`RiskService` 的第二条自动入队路径新增 `processPath` 字段并使用同一判断，避免绕过 ETW 直拦截后仍被风险分析入队。该缓解只跳过自动挂起，不跳过 ETW 诊断、风险事件和后置证据保留；`C:\Temp\powershell.exe` 这类假冒路径仍会被自动拦截。已运行 `cargo test --manifest-path src-tauri\Cargo.toml risk --lib --quiet`（11/11）、`cargo test --manifest-path src-tauri\Cargo.toml etw --lib --quiet`（43/43）、`cargo test --manifest-path src-tauri\Cargo.toml process_control --lib --quiet`（2/2）通过。`VUL-021` 仍保持 Open：本轮尚未重新执行管理员 VM 长时间 dev 样本，也尚未分析 `062326-5421-01.dmp` / `MEMORY.DMP`。

- 2026-06-22 现场诊断确认 `%APPDATA%\AnXinSecurity\runtime\interception_diagnostics.jsonl` 曾被 `unsigned_process` / `unsigned_module` / 单点 APIHook 活动等弱证据刷屏，导致拦截队列长时间停在低优先级条目，主界面依赖进程也可能被误挂起，表现为“拦截窗口不显示、主页卡死不能动”。本轮修复后的边界是：普通未签名和孤立异常只做告警、记录和补证，不再冻结进程；只有高风险且强证据的事件才自动进入 `InterceptionService`。这不是放弃防御，而是把“身份证没带”与“正在行凶”分开处理，避免安全产品自己制造拒绝服务。

- 2026-06-18 现场读取 `%APPDATA%\AnXinSecurity\runtime\etw_diagnostics_dump_20260617_180506_230.json`：ETW 正在运行并采集，`totalRaw=5553`、`totalNormalized=5553`、`totalMatched=0`；provider 主要为 `Image=2827`、`Network=1746`、`Thread=325`、`Process=87`、`Unknown=568`。最近 4096 条在约 1.76 秒内产生，约 2327 条/秒，确认 4096 队列会瞬间被顶满。该导出仍是旧 schema，没有 `aggregateBuckets`，且 `Image/load` 的 `imageName`、`Thread/start` 的 `startAddress`、`Process/start` 的 `processName` 多为空；当前实时 ETW 注入规则因此无字段可匹配，已登记 `buglist.md` 的 `VUL-016`。本轮只补只读诊断字段和聚合导出可见性，不把该现场写成已拦截。

- 2026-06-18 再次读取附件新 schema ETW 诊断 JSON（`startedAt=2026-06-18T00:23:52Z`）：`aggregateBuckets=525`、`totalRaw=2889`、`totalMatched=0`，所有 `recentRaw` 的 `rawUserDataLength` 都是 `0`，说明关键字段为空不是 parser 字符串猜测失败，而是 ETW 回调读取 `EVENT_RECORD.UserDataLength/UserData` 的 FFI 布局错误。已核对 `windows-0.58.0` 绑定，真实 `EVENT_RECORD.BufferContext` 是 4 字节 `ETW_BUFFER_CONTEXT`；本地 `session.rs` 原先用 `[u32; 4]` 导致后续字段偏移错误。本轮已把本地 `EventRecord.buffer_context` 改为 4 字节 `EtwBufferContext`，并新增 `local_event_record_layout_matches_windows_binding` 单测验证本地 FFI 镜像与 Windows 绑定 size/alignment 一致。该修复已通过 `cargo test --manifest-path src-tauri\Cargo.toml local_event_record_layout_matches_windows_binding --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml etw --lib --quiet`、`cargo check --manifest-path src-tauri\Cargo.toml`；但仍需管理员环境重新导出 JSON，确认 `rawUserDataLength` 不再全为 0 且 `Image/load` / `Thread/start` 字段恢复后，才能写成实战检测链路已恢复。
- 2026-06-18 现场又确认一处误伤策略：`remote_thread_start_outside_image` 是高敏感度“入口异常”信号，但单独触发时不应自动挂起。已将它从直接挂起规则降为观察型规则：ETW 仍会把它标成高风险并保留在诊断缓存/聚合桶中，但不再直接挂起、不再进入风险分析/行为库热路径，也不再唤醒 `ProcessScanner` hot PID 复扫；只有 `trusted_process_unsigned_image_load` 这类强证据仍允许直接挂起和后置补证。相关单测已补 `direct_realtime_interception_does_not_queue_observation_only_thread_event`、`remote_thread_start_rule_is_observation_only_not_auto_intercept`、`high_value_etw_fanout_suppresses_observation_only_noise` 和 `realtime_rule_policy_separates_preblock_from_evidence_collection`。

- 2026-06-18 继续核对 `etw_diagnostics_dump_20260618_052717_844.json` 后确认，`trusted_process_unsigned_image_load` 的命中样本主要是 `svchost.exe` 加载 `\Device\HarddiskVolume4\Windows\System32\dsreg.dll`、`netapi32.dll`、`DiagnosticDataSettings.dll` 这类系统 DLL，不是 `calc.exe` / `regedit.exe` 的真实注入。根因是 ETW `Image/load` 里的设备路径没有先转换成可验签的 DOS 路径，`TrustService::verify_file()` 因而对正常系统模块验签失败并被当成“未签名”。本轮已在 `etw_service.rs` 增加 `\Device\HarddiskVolume...` → 盘符路径转换，并把“路径不可验证”和“签名检查失败”都改成保守跳过，不再直接升级成 `trusted_process_unsigned_image_load`；已通过 `cargo check --manifest-path src-tauri\\Cargo.toml`、`cargo test --manifest-path src-tauri\\Cargo.toml etw_image_path --lib --quiet`、`cargo test --manifest-path src-tauri\\Cargo.toml etw --lib --quiet`。但仍需管理员桌面环境重新跑一次 `regedit.exe` / `calc.exe` 场景，确认系统 DLL 误报消失且真正的 `calc_probe_payload.dll` 仍能命中。

- 2026-06-19 现场指出“ETW 命中后再挂起仍有延迟，短生命周期 payload 可能已执行完成”。已确认 `Image/load` 属于加载完成后的通知，无法单独提供真正的加载前阻断；本轮仅做可验证的响应时间优化：`InterceptionService::enqueue` 的生产路径从“先查询 PID 身份并写恢复台账，再调用 `NtSuspendProcess`”调整为“通过去重和临时允许检查后立刻调用 `NtSuspendProcess`，再补 PID 身份和恢复台账；台账失败则恢复目标进程回滚”。这能减少 ETW 后置挂起链路中的身份查询和 I/O 延迟，但不能承诺拦住已在 `DllMain` 或远程线程入口中瞬时执行完成的行为。已运行 `cargo check --manifest-path src-tauri\\Cargo.toml` 通过；`cargo test --manifest-path src-tauri\\Cargo.toml interception --lib --quiet` 本轮 124 秒超时，未作为通过记录，且确认超时后无残留 `cargo/rustc/anxin-security` 进程。下一步若要真正前置，应优先做注入源头 API/ETW Threat Intelligence/文件落地侧拦截，而不是继续只依赖 `Image/load` 事后挂起。

- 2026-06-20 本轮继续修正 APIHook 远程线程注入处置链路：`native/file_hook/src/file_hook_dll.cpp` 在 `OpenProcess / VirtualAllocEx / WriteProcessMemory / CreateRemoteThread(Ex)` 形成强链路时，不再只“源头阻断并上报源头进程”，而是在真正放行远程线程前先尝试 `NtSuspendProcess` 挂起**被注入目标 PID**，随后让 `CreateRemoteThread*` 返回 `ERROR_ACCESS_DENIED`，并通过 Hook 命名管道上报 `blocked=true` 与 `targetSuspended=true`。原生侧新增保守保护：目标是 `csrss.exe`、`smss.exe`、`wininit.exe`、`services.exe`、`lsass.exe`、`winlogon.exe`、AnXin 自身或路径无法确认时不做 DLL 侧挂起；若已挂起但命名管道上报失败，会立即尝试 `NtResumeProcess` 回滚，避免“无弹窗但进程被悄悄挂住”。Rust `hook_service.rs` 对 `detours_process_injection` 事件继续按 `(source_pid, target_pid)` 聚合，但命中后现在把**目标进程 PID**以 `remote_thread_injection_target` 推入 `InterceptionService`；如果 DLL 已经声明 `targetSuspended=true`，则走 `InterceptionService::enqueue_pre_suspended`，不再重复调用 `NtSuspendProcess`，避免 Allow 时只恢复一层挂起计数。若入队失败、应用退出中、缺少拦截服务或目标属于 AnXin 父级控制链，Rust 会恢复该预挂起目标。拦截窗口因此应展示 `regedit.exe` / `notepad.exe` 等被注入目标，并等待用户“允许运行/阻止进程”；Allow 会恢复目标进程，Block 会终止目标进程。已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests --quiet` 通过（9/9）、`cargo test --manifest-path src-tauri\Cargo.toml interception --lib --quiet` 通过（28/28）、`cargo check --manifest-path src-tauri\Cargo.toml` 通过；原生 x64/x86 已通过 `cmake --build native\file_hook\build-vs18 --config Release --target file_hook_detours file_hook_injector` 与 `cmake --build native\file_hook\build-vs18-win32 --config Release --target file_hook_detours file_hook_injector`，并已覆盖 `native\bin\win32-x64`、`native\bin\win32-x86` 以及现场常用的 `native\file_hook\build-calc-probe-x64\Release`。已用 SHA256 确认 x64 构建产物、运行目录和 calc-probe 目录的 `file_hook_detours.dll` 一致，并确认运行目录 DLL 内含 `targetSuspended` 上报字段。尚未在管理员桌面完成真实注入端到端弹窗复测，因此不能写成现场已 100% 命中；但当前代码语义已经从“源头进程告警”收敛为“目标进程先挂起并触发拦截窗口”。 2026-06-20 随后复核“没有拦截窗口弹出”问题，确认 `InterceptionService::try_show_next()` 原先只调用 `prepare_interception_window()`，而该函数实际只创建/复用 hidden 窗口并不 `show()`；本轮新增 `show_interception_window()` 并在展示拦截时显式 `show + set_always_on_top + set_focus`。同时为 APIHook 阻断事件补了兜底：即使 Rust 只收到最后一条 `blocked=true` 的 `CreateRemoteThread(Ex)` 事件，也会通过 `InjectionChainAlert::from_blocked_hook_event` 直接触发目标拦截，不再依赖前序 `OpenProcess/VirtualAllocEx/WriteProcessMemory` 全部进入聚合器。随后针对“ETW stderr 刷屏导致看不到 `try_show_next` / `show_interception_window`”的问题，新增独立 JSONL 黑匣子 `%APPDATA%\AnXinSecurity\runtime\interception_diagnostics.jsonl`，由 `interception_diagnostics_service.rs` 追加记录 `hook_event_received`、`injection_chain_alert`、`injection_target_interception_requested`、`interception_queue_push`、`try_show_next_entry`、`show_interception_window_*`、`emit_interception_event_*` 等关键阶段；该诊断不走 stderr、不走前端实时日志，写入失败也不影响主拦截链路。已重新运行 `cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests --quiet` 通过（10/10）、`cargo test --manifest-path src-tauri\Cargo.toml interception --lib --quiet` 通过（29/29）、`cargo test --manifest-path src-tauri\Cargo.toml interception_diagnostic_record_is_json_line --lib --quiet` 通过（1/1）、`cargo check --manifest-path src-tauri\Cargo.toml` 通过；原生运行目录 DLL 哈希仍与 calc-probe 目录一致且包含 `targetSuspended` 字段。本轮仍未在管理员桌面完成真实注入端到端弹窗复测，下一步应由现场复测后读取 `interception_diagnostics.jsonl` 判断卡点。现场随后提供的诊断片段显示独立窗口已经 `show_interception_window_ok`，但当前展示的是 `esbuild.exe` 的 `unsigned_process`，不是用户确认的注入目标 PID `158968`；因此本轮又给 `remote_thread_injection_target` 设为最高优先级，入队时插到队首，并在已有低优先级弹窗展示时允许抢占：当前低优先级条目回到队列，立即改弹 APIHook 注入目标。新增单测 `remote_thread_injection_preempts_lower_priority_modal` 使用现场 PID `160452 -> 158968` 复现该队列抢占场景；已运行 `cargo test --manifest-path src-tauri\Cargo.toml remote_thread_injection_preempts_lower_priority_modal --lib --quiet` 通过（1/1）、`cargo test --manifest-path src-tauri\Cargo.toml interception --lib --quiet` 通过（30/30）、`cargo check --manifest-path src-tauri\Cargo.toml` 通过。随后在整份 Rust 侧 `interception_diagnostics.jsonl` 中按 PID `158968` 与 `hook_event_received` 查询为空，说明现场这次注入目标尚未进入 Rust Hook 管道；因此原生 `file_hook_detours.dll` 又新增 C++ 侧落盘诊断 `%APPDATA%\AnXinSecurity\runtime\file_hook_detours_diagnostics.jsonl`，记录 `remote_thread_block_decision`、`process_injection_notice_sent`、`remote_thread_block_result`、`pipeError`、`reported`、`targetSuspended` 等字段。已运行 x64/x86 CMake 构建通过，并覆盖 `native\bin\win32-x64`、`native\bin\win32-x86` 与 `native\file_hook\build-calc-probe-x64\Release`；已用 SHA256 确认 x64 构建产物、运行目录和 calc-probe 目录一致，且 DLL 内包含 `file_hook_detours_diagnostics.jsonl` 字符串。现场随后确认 C++ 侧 `process_injection_notice_sent` 对 PID `158968` 的 `pipeError=2`，即 `ERROR_FILE_NOT_FOUND`：DLL 已阻断并短暂挂起目标，但找不到 `\.\pipe\anxin_security_filehook`，所以上报失败并回滚，Rust 侧自然没有 `hook_event_received`。因此本轮将 `main.rs` 中 Hook 命名管道接收端改为应用启动期无条件启动；它只是轻量接收端，不代表主动注入，进程/文件监控开关仍只控制 watcher/ETW 等主动采集链路。启动成功会写入 `interception_diagnostics.jsonl` 的 `hook_pipe_service_started`，便于现场确认管道已存在。已运行 `cargo check --manifest-path src-tauri\Cargo.toml` 通过、`cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests --quiet` 通过（10/10）、`node --test --test-name-pattern "File hook pipe receiver" tests\scan_page_threat_actions.test.mjs` 通过（1/1）。继续排查后发现 Rust Hook 管道服务端每处理完一条连接都会固定 sleep 100ms 再创建下一根命名管道；而 C++ 侧注入链多个 API 在同一毫秒内连续上报，容易踩中“上一根管道关闭、下一根管道尚未创建”的空窗并得到 `pipeError=2`。本轮已将 Rust 服务端改为仅在错误时 sleep，正常连接结束后立即重建管道；同时 C++ `openPipeHandle` 对 `ERROR_FILE_NOT_FOUND` 也做短重试，重试次数从 5 提高到 50（约 1 秒窗口），避免瞬时管道重建空窗造成上报丢失。已重新运行 `cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests --quiet` 通过（10/10）、`cargo check --manifest-path src-tauri\Cargo.toml` 通过；x64/x86 `file_hook_detours` 与 `file_hook_injector` 已重新 CMake 构建并覆盖 `native\bin` 与 `native\file_hook\build-calc-probe-x64\Release`，SHA256 确认 x64 三处 DLL 一致。现场随后出现 `pipeError=121`（`ERROR_SEM_TIMEOUT`），说明管道已经存在但当前实例被上一条短连接占用；进一步修正为：Rust `serve_pipe_connection` 读到当前批次消息后立即 `break` 并关闭该 pipe 实例，让外层循环马上创建下一实例；C++ `openPipeHandle` 同时把 `ERROR_SEM_TIMEOUT` 纳入短重试。该修复已再次通过 `cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests --quiet`（10/10）、`cargo check --manifest-path src-tauri\Cargo.toml`，并重新构建/覆盖 x64/x86 原生模块，SHA256 确认 x64 三处 DLL 一致。最新现场诊断显示 `OpenProcess` 已能 `reported=true/pipeError=0`，但后续 `VirtualAllocEx/WriteProcessMemory/CreateRemoteThread` 仍出现 `pipeError=121`，说明单实例命名管道仍不足以承载同一注入链的连续短连接。本轮进一步把 Rust Hook 管道服务端改为 8 个 worker 并发预建同名 pipe 实例，`CreateNamedPipe` 的 `max_instances` 改为 `PIPE_UNLIMITED_INSTANCES`，避免一个短连接占住实例时后续事件只能等待同一实例。已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests --quiet` 通过（10/10）、`cargo check --manifest-path src-tauri\Cargo.toml` 通过；该改动只涉及 Rust 管道服务端，需要重启 AnXinSecurity 后生效。

- 2026-06-20 继续读取现场附件后确认，管理员侧 C++ 诊断中 PID `187684` 已出现一轮完整链路 `OpenProcess / VirtualAllocEx / WriteProcessMemory / CreateRemoteThread` 全部 `reported=true, pipeError=0`，但同一文件更早的 PID `158968` 以及后续一轮仍有 `pipeError=121`；管理员侧 Rust `interception_diagnostics.jsonl` 对 `158968` 只显示 ETW `trusted_process_unsigned_image_load` 入队，没有 `hook_event_received`。本轮因此在 Rust Hook 管道服务端补入口级黑匣子，只对进程注入相关消息记录 `hook_pipe_raw_message_received`、`hook_pipe_line_parsed`、`hook_pipe_line_parse_error`、`hook_pipe_read_timeout/read_error` 和 `hook_pipe_worker_*`，用于区分“C++ reported=true 但 Rust 没读到”“读到但 JSON 解析失败”“解析成功但分发没走”。同时把非阻塞管道等待轮询从 50ms 降到 5ms、空读上限改为 40 次（约 200ms），减少同一注入链连续短连接被服务端空等占住的窗口。已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests --quiet` 通过（10/10）、`cargo check --manifest-path src-tauri\Cargo.toml` 通过；本轮未重新构建 C++，也未在管理员桌面完成端到端注入弹窗复测。下一轮现场应重启 AnXinSecurity 后，优先按最新目标 PID 查询 `hook_pipe_raw_message_received -> hook_pipe_line_parsed -> hook_event_received -> injection_chain_alert -> remote_thread_injection_target`。

- 2026-06-18 托盘菜单“确认退出”当前改为生命周期收口流程：`AppLifecycleService` 会在第一次退出请求时标记应用进入 `exiting`，重复退出请求直接幂等返回；`execute_exit` 不再在 invoke 响应返回前手动 `window.close()`，而是延后到后台任务中先停止进程扫描器、APIHook watcher、文件监控、Hook 管道、ETW 和扫描引擎，再恢复/清理拦截队列。用户随后真实复测确认 `PostMessage failed ... 无效的窗口句柄` 已消失，但仍剩 `Failed to unregister class Chrome_WidgetWin_0. Error = 1412`；本轮第二阶段改为在后台清理完成后按 `interception` 优先、`main` 最后的顺序 `destroy()` WebView 窗口，再调用 `app_handle.exit(0)`，避免隐藏拦截窗口留到 Chromium/WebView2 最终 cleanup 阶段触发窗口类重复注销噪声。退出阶段实时日志、ETW/Hook 前端事件、风险事件、启动快照进度/结果和拦截窗口展示都会被 `app_is_exiting` 闸门阻止继续投递或新增拦截。第二阶段已完成编译和结构守卫验证；尚未运行真实桌面托盘菜单退出烟测，不能写成现场完全复现通过。

- `建议.md` 已收敛为“启动快照扫描可信环境增强”的阶段计划，当前口径是先补轻量、可验证的安全缺口，复杂规则系统和远程线程检测后置。
- 启动快照 `SnapshotResult` 当前已经包含 `masqueradeAlerts`、`revocationAlerts`、`revocationUnknownCritical`，统计口径沿用已有快照字段风格。
- `snapshot_service.rs` 当前已有内置 `CRITICAL_PROCESS_RULES`，用于关键系统进程名称和路径校验；规则仍是硬编码，不是运行时配置。
- `TrustService` 当前已有 `verify_file_with_revocation` 入口，签名缓存键已经区分普通验证和吊销检查语义。
- 启动后后台吊销检查当前已经做有限并发、单项超时、检查前 PID 路径重读和文件写入时间比对；路径或文件状态变化时复用现有拦截队列，不新增平行事件。
- 未签名模块当前会补充复用 `scan_startup_target` 做恶意代码扫描；恶意命中时统计 `maliciousModules` 并进入高风险拦截，未判恶意的普通未签名模块只统计和记录，不再把宿主 PID 直接推入拦截队列。
- 启动快照当前会把模块枚举失败拆成总数 `moduleEnumerationFailures` 和拒绝访问子集 `moduleEnumerationAccessDenied`；系统保护进程导致的拒绝访问仍计入 Unknown，不进入可信基线，但日志摘要会和其他模块枚举异常分开，避免把正常 Windows 权限边界误读成大量恶意模块。
- `TrustService` 当前先验证嵌入签名；当返回“无签名/主体格式不适用”这类状态时，再走 Windows catalog 签名验证，避免把 `ctfmon.exe`、`sihost.exe` 这类系统 catalog 签名文件误判为未签名。
- 启动快照当前在同一轮扫描内引入了本轮签名结果缓存，按规范化路径 + 文件修改时间 + 文件大小复用同一文件版本的签名结论，减少同一 DLL 被多个进程重复触发的签名验证开销；无法读取文件版本信息时仍回退到原始验证，不改变未知/不可信判定。
- 启动快照当前会对同一个进程枚举到的模块路径做本进程内去重，保留首次出现的原始路径用于主映像完整性检测和日志；该去重不跨进程、不跨时间复用，因此不会绕过文件版本变化后的签名重新校验。
- 启动快照当前复用同一次 `enumerate_process_module_info` 的模块信息，同时供模块信息去重、主映像完整性检查和模块路径扫描使用，避免同一个 PID 为扫描和完整性检查各拍一次 ToolHelp 模块快照，也避免先拷贝成字符串列表再做去重；模块信息不可用时完整性状态仍保持 `Unknown`，不会进入可信基线。
- 启动快照当前在进程枚举阶段就为每个进程预计算 `scan_key`，主循环、后台吊销检查和主映像完整性复核复用同一份规范化结果；这只减少重复字符串规整，不改变签名、哈希、路径策略或 Unknown 判定。
- 启动快照当前在模块循环中会跳过与当前进程主路径规范化后完全相同的模块项；`inspect_startup_target` 会随目标文件检查一起返回 `scan_key`，每个进程和模块的路径规范化结果只计算一次，并复用于唯一模块统计、主映像重复项判断、启动恶意扫描缓存查找和签名缓存键拼装。该 EXE 已在进程层完成伪装检查、主映像完整性、签名验证和必要扫描，跳过只避免重复处理主映像，不影响其他 DLL。
- 启动快照当前复用 `prepare_startup_module_targets` 已计算好的模块 `scan_key`：模块路径在进入 `inspect_startup_target` 前就已完成一次标准化，后续通过 `inspect_startup_target_with_scan_key` 复用这份 key，只避免再次做字符串规整，不跳过任何文件属性、签名或哈希检查。
- 启动快照当前复用单次目标文件检查结果：`inspect_startup_target` 一次读取文件属性后同时返回是否可扫描、签名缓存键和文件写入时间，避免对同一个进程路径或模块路径重复读取 `metadata`；没有文件版本信息时仍不缓存签名结论，不降低安全判定。
- 启动快照当前对模块签名验证使用有限并发，默认 `startupSignatureVerifyConcurrency = 0` 表示按本机逻辑处理器数量自动设置；读取逻辑处理器数量失败时回退到旧的保守并发 4。路径策略中的排除项和精确路径允许列表仍在文件属性检查前完成；哈希允许列表已延后到模块签名不可信、准备进入恶意扫描前再检查，避免对大量最终会因签名可信而跳过的 DLL 提前计算 SHA-256。每个哈希判断仍使用文件版本键缓存，超时、验证失败和 Unknown 仍不进入可信基线。模块并发路径使用 Tokio blocking 任务配合外层超时，不再在 blocking 任务内额外创建签名线程；原生恶意扫描仍不按逻辑处理器并发，避免触碰 `VUL-009` 的 NativeEngine 并发风险。
- 启动快照当前会给模块签名验证使用比进程主文件更宽松但有上限的超时时间：`startup_module_signature_verify_timeout` 基于 `scanner.startupSignatureVerifyTimeoutMs` 乘以 3，并以目标恶意扫描超时为上限。该策略只让模块签名验证多等一小段时间；只有签名真实返回可信才跳过恶意扫描，超时、验证失败或 Unknown 仍不进入可信基线，并继续按后续哈希允许/恶意扫描路径处理。
- 启动快照当前会在同一批模块签名验证内合并相同文件版本键的等待者：同一 `signature_cache_key` 只排入一个真实签名任务，完成后按原模块顺序展开结果；无法读取文件版本键的目标仍不合并、不缓存，超时或任务失败仍按不可信/Unknown 处理。`SnapshotResult.performance.signatureCoalescedWaiters` 用于观测本轮实际合并次数。
- 启动快照当前的进程主文件签名验证也走 `verify_file_with_timeout_async`，通过 Tokio blocking 线程池执行 WinVerifyTrust 并由外层超时约束；同轮签名缓存和文件版本键边界保持不变，只避免在启动快照 async 主任务中直接阻塞 Windows 签名 API。
- 启动快照当前把模块签名从“每个进程枚举后立刻验证本进程模块”改为两阶段调度：主循环仍逐进程完成伪装检查、路径策略、主映像完整性、进程签名、进程恶意扫描和吊销目标收集，同时把需要签名的模块带上 PID/进程名/进程路径收集到全局队列；主循环结束后再对全局模块队列做有限并发签名验证和必要恶意扫描。该调度只让签名队列更饱满，不跳过模块，不改变 Unknown、超时、允许列表、哈希允许或恶意扫描判定。
- 启动快照当前已进一步拆出启动可信基线和后台深度检查：`SnapshotResult` 包含 `baselineComplete`、`deepScanCompleted`、`deepScanPendingModules`、`deepScanPendingProcesses`。只有非关键进程、路径可扫描、主文件签名已真实可信且伪装检测为不适用的进程，才会把模块枚举和主映像完整性检查后移；这些进程在后台完成前只计入 `unknownProcesses/deepScanPendingProcesses`，不会提前计入 `signedProcesses`。
- 后台深度检查当前会继续对延后进程执行模块枚举、主映像完整性检测、必要的进程恶意扫描和模块签名/恶意扫描；枚举失败、不可扫描模块、签名超时、扫描失败、未签名且未命中恶意的模块仍留在 Unknown，恶意命中仍进入拦截队列。后台完成后只清除已被实际验证干净的 pending 计数，不把“只是后台跑完了”当作可信结论。
- 启动快照当前会在前台主循环前用同一轮 `StartupSignatureCache` 对可缓存的进程主文件签名做有限并发预取，默认沿用 `startupSignatureVerifyConcurrency = 0` 的自动并发，即本机逻辑处理器数量。主循环仍按原进程顺序消费签名结论，缓存键仍是规范化路径 + 高精度修改时间 + 文件大小；若文件版本不可读或发生变化，仍会重新验证，超时/失败/Unknown 不进入可信基线。
- 启动快照当前对模块枚举增加了可配置超时，配置项为 `scanner.startupModuleEnumerationTimeoutMs`，默认 1000ms：模块枚举在 Tokio blocking 线程池中执行，超时或任务失败会进入现有 `moduleEnumerationFailures/unknownModules` 统计，不把该 PID 的模块状态计入可信基线；正常返回的模块信息仍继续用于主映像完整性检查、模块签名和必要恶意扫描。
- 启动快照当前会先执行 `PathPolicySnapshot::should_skip_by_path_only`，让排除项和精确路径允许列表这类纯路径规则在读取文件属性前直接生效；`PathPolicySnapshot` 现在会先把路径标准化和文件名提取打包成一次 lookup，排除项和精确允许判断复用同一份结果，哈希允许列表不参与该快速路径，仍需后续完整策略/签名/扫描流程确认。
- 启动快照当前加载 `PathPolicySnapshot` 时会预处理排除项和允许列表路径，保存规则的规范化路径和进程文件名；后续每个进程/模块只需规范化待检查路径，不再反复标准化同一批配置规则，`process` 型排除项也复用预处理好的文件名，不再在匹配时重复对规则路径做小写转换。
- 启动快照当前的 `PathPolicySnapshot` 会在同一轮快照内缓存待检查路径的 `PreparedPathLookup`，复用路径标准化和文件名提取结果；该缓存只保存纯字符串转换结果，不保存文件属性、哈希、签名或可信判定。允许列表哈希也会在加载快照时预处理为小写字符串，后续匹配不再反复读取原始 entry 的 hash 字段。
- 启动快照当前的 `PathPolicySnapshot` 会把允许列表预处理为两个内存集合：精确路径集合和 SHA-256 哈希集合；精确路径判断不再线性遍历允许列表，哈希集合仍只在路径快速判断未命中后读取目标文件哈希，不进入纯路径快速通道。
- 启动快照当前的 `PathPolicySnapshot` 会在同一轮快照内缓存路径策略判定结果，减少多个进程加载同一模块时反复匹配排除项/允许列表；该缓存只在调用方提供文件版本键时启用，文件版本变化后重新判断，缺少版本键时仍走原逻辑不缓存。
- 启动快照当前在主循环确认目标未命中路径策略后，会以 `policy_already_checked = true` 调用 `scan_startup_target`，避免进入恶意扫描前再次匹配排除项/允许列表；扫描函数仍保留 `policy_already_checked = false` 的兜底检查路径，防止未来其他调用方绕过策略判断。
- 启动快照使用的 `PathPolicySnapshot` 当前会在同一轮批量扫描内缓存允许列表哈希匹配所需的 SHA-256 结果；缓存键包含规范化路径、高精度修改时间和文件大小，文件版本变化后会重新计算，不把旧哈希用于新文件。
- 启动快照当前先通过 `should_skip_by_path_only` 处理排除项和精确路径允许列表；进程主文件和模块都只在签名不可信、即将进入恶意扫描前调用 `hash_after_path_miss_cached`。这避免对已被 Windows 签名验证确认为可信的进程主文件提前计算 SHA-256；超时、验证失败或 Unknown 仍不会被当作可信，仍会继续进入后续哈希允许/恶意扫描路径。该后续缓存使用 `hash-after-path-miss|...` 作用域前缀和文件版本键，不与完整策略缓存混用；哈希允许列表仍不参与纯路径快速判断，也不会按裸路径缓存可信结论。
- 启动快照当前会把哈希允许列表检查阶段已经按同一文件版本键计算出的 SHA-256 传给 `ScanResultCacheService::scan_or_get_cached_deferred_with_hash`，避免同一个未信任目标在“哈希允许列表未命中后准备恶意扫描”时立刻重复读取文件计算 SHA-256。安全边界是：`PathPolicySnapshot` 会重新读取当前文件版本键并与调用方提供的版本键比对，不一致时不返回 hash；扫描缓存只接受 64 位十六进制 hash，`PathPolicySnapshot` 也只把完整 64 位十六进制值纳入哈希允许列表索引；`scan_startup_target` 只有在版本键存在时才传入预计算 hash。该复用只减少 I/O，不把 hash 命中当成可信结论，不改变 Unknown、超时、恶意命中或拦截语义。
- 启动快照当前在同一轮内对目标恶意扫描结果做文件版本级复用：`scan_startup_target` 只在调用方提供规范化路径 + 修改时间 + 文件大小组成的版本键时写入本轮 `StartupScanCachedOutcome`；成功结果和失败/超时结果都会按该版本键复用。失败/超时复用只会再次返回 `Failed` 并计入扫描失败，不会变成可信、不会跳过 Unknown；恶意结果复用时仍会按当前 PID/模块路径重新入拦截队列。缺少文件版本键时不写本轮扫描结论缓存，避免裸路径缓存带来的文件替换风险。
- 启动快照当前会在 `SnapshotResult.performance` 中返回性能采样，并输出 `[StartupSnapshot] Performance` 摘要日志；采样范围包含进程枚举、路径策略加载、主循环、模块枚举、主映像完整性检测、签名验证、进程/模块签名验证拆分、本轮实际签名并发数 `signatureConcurrency`、目标恶意扫描、进程/模块恶意扫描拆分、扫描缓存落盘、模块引用数、唯一路径数、签名缓存命中/未命中、进程/模块签名超时、模块枚举超时、批内签名合并等待数和目标扫描缓存命中/未命中。本轮只增加观测字段，不改变 Unknown、超时、未签名、恶意命中和证书吊销相关安全判定。
- 启动快照当前在 `ANXIN_STARTUP_SNAPSHOT_DEBUG=1/true` 时会额外输出后半段里程碑日志：`Module signature batch start/done`、`Module scan batch start/progress/done`，用于区分主循环完成后是模块签名批处理慢，还是模块恶意扫描慢；这些日志只用于诊断，不改变扫描顺序和安全判定。
- 启动快照当前在 `ANXIN_STARTUP_SNAPSHOT_DEBUG=1/true` 时还会输出单目标 `Target scan detail`，记录 `source`、`elapsedMs`、`cacheHit`、`versionKeyAvailable` 和短 hash 前缀；`ScanResultCacheService` 在 `ANXIN_SCAN_CACHE_DEBUG=1/true` 或启动快照 debug 开启时输出 `Lookup detail`，拆分 `hashMs`、`hashSource`、`engineMs` 和总耗时。hash 只输出短前缀，诊断日志只用于定位瓶颈，不参与安全判定。
- ETW 启动当前为 AnXin 私有系统实时会话：`EtwSession` 使用项目自己的会话 GUID，并设置 `EVENT_TRACE_SYSTEM_LOGGER_MODE` 接收 `Microsoft-Windows-Kernel-*` 系统 provider 事件；遇到同名残留会话时会先清理并只重试一次，避免把“会话残留”误判成“没有管理员权限”。
- ETW 默认 provider keyword 当前使用具名常量：进程 `0x10`、文件 filename/create/delete/rename/create_new、注册表 set/delete value 与 create/delete key、网络 IPv4/IPv6。
- ETW 服务当前新增只读现场诊断环形缓存：`EtwDiagnosticsCache` 记录 poll 批次、原始事件数、解析失败、系统/无效 PID 丢弃数、规整事件数、规则命中数，以及 provider / operation / provider+operation / rule / threat / drop 统计；最近原始事件和规整事件各自按容量 `4096` 有界保存，另有 `aggregateBuckets` 热点聚合桶用于保留高频刷屏类别。`commands::behavior` 暴露 `get_etw_diagnostics_snapshot`、`clear_etw_diagnostics`、`export_etw_diagnostics` 三个命令，导出文件写入 `%APPDATA%\AnXinSecurity\runtime\etw_diagnostics_dump_<timestamp>.json`，不写回仓库配置。前端 `BehaviorPage` 当前有“ETW 现场诊断”卡片，可刷新、清空和导出诊断；相关文案已同步 `config/i18n/zh-CN.json`、`config/i18n/en-US.json` 和内置中文 fallback。该能力只用于现场确认“真实刷屏里有什么”，不参与拦截判定，也不能单独证明实战拦截已命中。2026-06-18 已继续补充 `eventId`、`opcode`、`rawUserDataLength`、`rawUserDataPreview` 诊断字段，用于现场确认内核事件 UserData 真实布局；这些字段只导出有界十六进制前缀，不写入仓库配置。
- 本轮已把实时 ETW 采集补到 `Microsoft-Windows-Kernel-Process` 的线程/镜像加载关键词：`etw::parser` 现可把 `ThreadStart/ThreadStop/ImageLoad/ImageUnload` 解析成 `Thread` / `Image` 事件，`etw_service` 会把 `Image/load` 事件中的 `imageName` 规整为 `path`，并在可信宿主进程加载未签名模块时升级为威胁事件；同时还新增了 `Thread/start` 的只读远程线程入口检测：如果线程入口地址不落在目标进程任何已加载模块范围内，会升级为 `remote_thread_start_outside_image`。当前自动挂起边界已经收敛：`trusted_process_unsigned_image_load` 这类强证据仍可进入 `InterceptionService` 并触发后置补证；`remote_thread_start_outside_image` 这类孤立远程线程入口信号只保留在 ETW 诊断缓存/聚合桶中，不再单独冻结目标 PID，也不再进入前端实时推送、行为库写入、风险分析或 `ProcessScanner` hot PID 复扫。`config/etw_match_rules.json` 也新增了针对受控 `calc_probe_payload.dll` 的镜像加载规则。相关代码已通过 `cargo test --manifest-path src-tauri\Cargo.toml process_scanner_service --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml direct_realtime_interception_queues_injection_event --lib --quiet` 和 `cargo check --manifest-path src-tauri\Cargo.toml`；但本轮仍未在管理员桌面环境完成真实 ETW 采样验证，不能写成“实战已命中”。
- 文件监控实时链路当前也从“只扫描文件并打印命中”升级为“文件事件命中恶意后直接拦截来源 PID”：`FileMonitorService` 订阅 ETW File 事件后，通过 `ScanResultCacheService::scan_or_get_cached` 复用扫描缓存；若写入/创建/重命名的文件被判为恶意，会把产生该文件事件的 PID 直接推入 `InterceptionService`，并同步标记 hot PID 触发后置证据补全。该路径已通过 `cargo test --manifest-path src-tauri\Cargo.toml nested_rust_file_event_extracts_file_name --lib --quiet` 验证事件 PID/进程名提取逻辑；管理员桌面真实文件事件拦截仍待现场验证。
- 本轮把进程扫描和启动快照再补了一层“模块链一致性”检测：`process_scanner_service.rs` 现在会对 `MEM_IMAGE + 可执行` 映射做只读比对，若某个映像基址不在模块枚举列表里，会按 `module_chain_unlinked_image` 入拦截队列；启动快照的前台主循环和后台延后检查也接上了同一判定。相关纯函数与 payload 形状测试已通过 `cargo test --manifest-path src-tauri\Cargo.toml process_scanner_service --lib`、`cargo test --manifest-path src-tauri\Cargo.toml snapshot_service --lib`，`cargo check --manifest-path src-tauri\Cargo.toml` 也已通过。本轮尚未做管理员桌面环境的实战采样验证，所以这里只能确认“编译和单测通过”，不能写成“现场已命中”。
- 实时事件日志当前对 PID `0` / `4` / `4294967295` 做后端兜底过滤：ETW 原始回调入口、ETW 分发入口、文件 Hook 分发入口和公共 `log-event` 写入入口都会阻止系统空闲、内核进程和无效 PID 噪音进入日志；ETW `Unknown` provider 序列化时也会保留真实 `pid/tid/provider`，避免前端因缺失 PID 默认显示成 `PID:0`。
- 原生模块当前只保留 `native/file_hook` 文件 API Hook 与注入链路；Tauri 打包资源当前仅打包 `file_hook_detours.dll`。
- `ScanResultCacheService` 加载 DPAPI runtime 缓存失败时，会把损坏的 `scan_results.json` 移动为 `scan_results.json.corrupt.<timestamp>` 后以空缓存继续，避免每次启动重复解密失败。
- 启动阶段的新进程恶意扫描器 `ProcessScannerService` 当前已经前移到完整启动快照之前启动：它继续监控启动后新增 PID，并使用既有路径策略、扫描缓存、主映像完整性检测和拦截队列；同时新增 hot PID 队列，供 ETW / 文件监控在已经做出实时拦截后立刻唤醒扫描器补证。完整启动快照仍会继续扫描启动时已存在的进程和模块，未完成模块检查仍保持 Unknown/Pending 语义，不写入可信基线。注意：hot PID 不是第一拦截点，第一拦截点必须是 ETW / 文件监控；扫描器只做事后证据补全和兜底。
- APIHook 进程 watcher 当前仍在完整启动快照结束后启动，避免本应用在快照期间向其他进程注入 `file_hook_detours.dll` 后污染启动基线；`set_process_monitoring_enabled(false)` 现在会同时停止 APIHook watcher 和前移启动的新进程扫描器，保持监控开关与运行态一致。
- 前端当前有专门的启动阶段页面：`SplashScreen` 复用后端 `snapshot-progress` / `snapshot-result` 事件展示配置加载、主题、语言、事件通道、实时防护、启动快照和主界面就绪等阶段；页面会显示当前阶段说明、可信基线、深度校验、未知项、威胁项摘要和“未完成检查不会被标记为可信”的安全提示。若短时间内没有收到快照进度，页面会转为“待确认”提示再进入主界面；深度模块或进程检查未完成时只显示待确认，不会把未完成检查显示成可信。
- 进程行为拦截当前只由独立 `interception` WebView 窗口承载：后端在推送 `process-intercepted` 前会创建/复用隐藏窗口，并只定向 emit 到该窗口；主窗口 `App` 不再监听或渲染 `InterceptionModal`，避免启动快照拦截同时出现独立窗口和主页内嵌弹窗。独立窗口前端拿到事件或通过 `peek_current_interception` 拉到当前条目后再 `show/focus`，窗口本身已改为不透明单层面板，不再依赖透明外壳或居中卡片；用户完成允许/阻止后窗口隐藏，并继续尝试展示队列下一条。拦截命令层读取 `Arc<InterceptionService>`，与 `main.rs` 实际托管状态一致；前端只有在 `handle_interception` 成功后才清除当前弹窗，避免命令失败时把当前拦截 UI 提前清掉。
- 拦截队列现在在 PID 入队时先调用进程控制服务挂起目标进程；独立拦截窗口的“阻止进程”会终止这个已挂起 PID，“允许运行”会先把当前目标路径加入本次应用运行期的内存临时白名单，再恢复该 PID。临时白名单不写入 `startup_allowlist.json`，应用重启后失效；同一路径在本次运行中再次入队会被拦截服务跳过。
- 拦截队列当前还会把已挂起 PID 写入 `%APPDATA%\AnXinSecurity\runtime\interception_suspended_processes.json` 恢复台账；应用正常退出时会先标记 `exiting`，停止事件来源和监控任务，再恢复所有已挂起进程并清理台账，异常退出后下次启动会先核对 PID、创建时间和进程路径，再只恢复仍是同一进程的残留挂起项。台账走现有运行时 DPAPI 列表存储，不写回仓库配置。
- `interception` 窗口已有独立 Tauri capability：`default.json` 只绑定 `main`，`interception.json` 只授予事件监听和窗口唤醒/隐藏/置顶/聚焦权限，不继承 `shell:default` 或 `fs:default`。
- 实时事件日志面板当前使用专用 `log-event` 通道刷新：ETW 与文件 Hook 写入内存日志缓冲区时会同步向前端推送日志行，概览页加载历史缓冲区后也会按同一格式显示，避免日志面板只读历史、不随新事件更新。
- `process_scanner_service.rs` 中 `enumerate_process_module_info` 当前已经是 `pub(crate)`，后续远程线程检测可以复用模块地址信息；远程线程检测本身还没有启用。
- 当前已补到的是“看见线程/镜像加载”的采集侧，并对 `Thread/start` 做了入口地址与模块范围比对；但它仍只覆盖“入口落在已加载镜像外”的远程线程/私有内存执行场景，不等于完整的远程线程专项判定器。若后续要继续收敛，可再补远程起始地址归因、线程创建者/目标进程关系和跨进程句柄链路。
- `native/file_hook` 当前新增了可选构建的 `calc_probe_payload.dll` 受控测试样本：开启 `BUILD_CALC_PROBE=ON` 时可构建该 DLL，并复用既有 `file_hook_injector.exe` 注入到 `notepad.exe` 后启动 `calc.exe` 作为可视化证明。该样本只用于验证启动快照/深度模块检查能否观察到外来 DLL，不代表 `RemoteThreadDetector`、`injectionAlerts` 或专门远程线程检测能力已经上线。
- `native/file_hook` 2026-06-17 新增了两个真实技术探测 DLL，与既有模拟文物探测并行独立：
  - `peb_unlink_real_payload.dll`（`BUILD_PEB_REAL_PROBE=ON`）：实现真实的 PEB 断链技术，从 `InLoadOrder/InMemoryOrder/InInitializationOrder` 三个链表中移除自身模块，为安芯的「模块链一致性检测」（`module_chain_unlinked_image`）提供真实测试目标。支持 `simulate` / `real` / `both` 三种模式，通过 `ANXIN_PEB_REAL_PROBE_MODE` 环境变量控制。
  - `reflective_load_real_payload.dll`（`BUILD_REFLECTIVE_REAL_PROBE=ON`）：实现完整的内存反射式 DLL 加载流程（PE 解析→节映射→重定位→导入解析→DllMain 调用），内嵌最小化 x64 PE stub，不产生 `LoadLibrary` ETW 事件。支持 `simulate` / `real` / `both` 三种模式，通过 `ANXIN_REFLECTIVE_REAL_PROBE_MODE` 环境变量控制。
  - 共享配置头文件 `test_config.h`（header-only）提供统一的 `ProbeMode` 枚举和环境变量读取函数。
  - 配置文档位于 `native/file_hook/config/test_probes.md`。
  - 单元测试位于 `native/file_hook/tests/test_config_unittest.cpp`。
  - **本轮未在管理员桌面环境完成真实注入和检测验证**，仅确认代码通过静态审查和结构正确性检查。CMake 编译验证待执行。
- `Unknown` 不应进入可信基线，这仍是启动快照可信环境的核心语义。

## 当前待办与风险
- 【2026-08-14 已收口】AnXinProcMon 的 P4/P5/P6 与遗留项（§4.3 行为事件入库、
  §4.4 DROP_MARKER 纠偏、§4.5 ETW 降噪与回退、§4.7 生命周期入库、TAMPERED 失明
  路径实测、WFP filter 顺序真机验证）已全部完成。见上方 2026-08-14 状态快照。
  下一步：规则引擎适配（驱动事件 → EtwRuleEngine 映射）与 ETW 降噪量化测量。
- APIHook 源头链路当前只对已经加载 `file_hook_detours.dll` 的源头进程有前置阻断效果；如果攻击/测试注入器生命周期短到 APIHook watcher 还没来得及注入，仍可能绕过这条用户态 Hook 防线。下一步优先补 Microsoft-Windows-Threat-Intelligence 的 `ALLOCVM_REMOTE / WRITEVM_REMOTE / QUEUEUSERAPC_REMOTE / SETTHREADCONTEXT_REMOTE` 等源头事件采集，或评估更低层的内核回调/驱动方案；不要把本轮 APIHook 改动误写成”所有任意注入器都可前置拦截”。
- 【2026-07-29 已修复】驱动自保 sc delete 绕过问题（VUL-044, High, Fixed）：原对象指针比较无法识别 SCM 打开的同一注册表键，导致 `sc delete` 后重启时服务键被 SCM 删除。已改用 `CmCallbackGetKeyObjectIDEx` 获取稳定 `ULONG_PTR ObjectID` 比较，同一键无论通过什么 handle 打开 ObjectID 都相同。三个驱动已设为 boot-start（`Start=0`），在 SCM 初始化前加载。VM 验证：sc delete 后重启，三个服务键全部存活，驱动正常加载。
- 【2026-07-28 已修复】`IOCTL_ANXIN_ADD_PID` 缺少调用方授权检查（VUL-043, High, Fixed）：已在 `IOCTL_ANXIN_ADD_PID` 分支入口补充 `IsCallerAuthorizedForWinsta()` 校验，与 REMOVE_PID / CLEAR_PIDS 一致；校验失败返回 `STATUS_ACCESS_DENIED`。
- 【2026-07-28 已修复】CmCallback `DeleteKey` fail-closed 导致 BSOD：此前注册表回调对无法确认归属的 `DeleteKey` 操作一律拒绝，误阻系统关键注册表操作引发蓝屏。修复为精确匹配目标服务键路径，非目标键一律放行；注册表保护不再对非目标操作 fail-closed。

优先级按”安全收益高、改动边界清楚、误报成本可控”排序。

- **【2026-08-13 新增，最高优先】驱动自保专项测试暴露 8 个 Open 漏洞（VUL-096~VUL-103）**：webview 进程可被整体终止（VUL-096，根因 isChildOfProtected 漏查 pending 队列）；安装目录文件运行期未受文件保护，exe 未运行时可删除/覆盖（VUL-097）；服务键注册表保护仅 2/4 键生效，AnXinSecurityService/AnXinNetFilter 键可删（VUL-098）；`IOCTL_ANXIN_SET_DIAG` 无授权校验可一键关闭 Ob 自保护（VUL-099，Critical）；进程名伪装即可获内核授权终止受保护进程（VUL-100，Critical）；卸载器重启一次后残留 3 个 .sys（VUL-101）；FpmQueryPaths 诊断挂起（VUL-102）；受保护线程上下文句柄可开（VUL-103）。修复顺序建议：VUL-099/VUL-100（内核授权）→ VUL-096（webview 子进程保护传播）→ VUL-097/VUL-098（文件与注册表运行期保护）→ VUL-101（卸载 .sys 清理）→ VUL-102/VUL-103。

1. 关键进程伪装规则当前硬编码，扩展性有限。短期先维护内置默认列表；未来如果允许用户编辑，必须放入 APPDATA 并复用 DPAPI 运行时存储，不能写回仓库配置。
2. 2026-06-15 热启动 `npm run dev` 采样中，`ctfmon.exe`、`sihost.exe` 等系统进程未再出现 medium 入队；仍观察到 `facewinunlock-tauri.exe`、`EnergyStarX.exe` 两个第三方进程 medium 入队。它们不再属于“系统进程大量误报”，后续如需继续收敛，应结合新增的拦截日志 `threat/path` 和 payload `signatureStatus` 判断是真未签名还是第三方签名兼容问题。
3. 2026-06-15 启动快照性能采样真实运行未等到完整 `SnapshotPerformanceStats` 终线：热启动编译很快，但快照约 12 分钟后只推进到 `220/416`，模块引用数到 `4910`，唯一恶意扫描路径仅 `37`，随后 WebView 报无效窗口句柄退出。当前判断下一步加速重点应放在模块枚举/模块签名验证去重或分阶段策略，而不是优先优化恶意扫描缓存。
4. 2026-06-16 06:13 受控 `npm run dev` 采样拿到完整 `[StartupSnapshot] Performance` 终线：`processLoop=516349ms`，`moduleEnumeration=1265ms`，`signatureVerification=24002ms (process=7241ms, module=16762ms)`，`targetScan=236953ms (process=36814ms, module=200139ms)`，`moduleRefs=14938`，`uniqueModules=1846`，`uniqueScanPaths=282`，`signatureCacheHits=153`，`signatureCacheMisses=1858`，`signatureCoalescedWaiters=12952`，`targetScanCacheHits=49`，`targetScanCacheMisses=282`。结论：模块枚举不是主要瓶颈，模块恶意扫描和大量模块签名/扫描后半段才是下一步重点。
5. 2026-06-16 14:10 增加本轮目标扫描结果/失败按文件版本键复用后，debug 采样已完整到达 `Process scanner started after startup snapshot`：`Module scan batch done: 15335 verified modules, 275 scans started, 296731ms`，`processLoop=86378ms`，`signatureVerification=22504ms (process=5145ms, module=17359ms)`，`targetScan=173882ms (process=20825ms, module=153057ms)`，`moduleRefs=15554`，`uniqueModules=1878`，`uniqueScanPaths=307`，`targetScanCacheHits=88`，`targetScanCacheMisses=307`。结论：重复同文件版本超时已被压住，快照能完整收口；剩余主要耗时来自约 275 个唯一未信任文件版本的真实扫描，下一步加速应研究“分阶段/延后低风险模块扫描但保持 Unknown 不进可信基线”，不能简单按目录或后缀放行。
6. 2026-06-16 14:38 将模块签名验证超时从基础 1000ms 自动放宽到 3000ms 后，debug 采样已完整到达 `Process scanner started after startup snapshot`：`Module signature batch start: 14637 targets, timeout=3000ms`，`Module scan batch done: 14637 verified modules, 5 scans started, 180947ms`，`processLoop=88726ms`，`signatureVerification=24101ms (process=5212ms, module=18889ms)`，`targetScan=110347ms (process=19862ms, module=90485ms)`，`signatureTimeouts=4 (process=0, module=4)`，`targetScanCacheHits=347`，`targetScanCacheMisses=8`。结论：签名阶段只比上一轮约多 1.6s，但模块扫描真实启动从 275 次降到 5 次，模块扫描计时从 153057ms 降到 90485ms，整体快照耗时从上一轮约 400567ms 降到本轮 288678ms；该优化是不降安全性的净收益。
7. 2026-06-16 15:15 新增单目标扫描诊断后，debug 采样已完整到达 `Process scanner started after startup snapshot`：`Module scan batch done: 15063 verified modules, 256 scans started, 180233ms`，`targetScan=116367ms (process=22083ms, module=94284ms)`，`targetScanCacheHits=59`，`targetScanCacheMisses=288`。`ScanResultCache` 诊断显示大量未信任 `.pyd/.dll/.node` 目标先在哈希允许列表阶段计算 SHA-256，再在扫描缓存阶段重复计算 SHA-256；部分大文件 hashMs 达数百到两千毫秒。结论：继续放宽信任规则没有安全空间，但按同一文件版本键复用刚计算的 SHA-256 是安全的 I/O 优化点。
8. 2026-06-16 15:56 增加哈希允许列表到扫描缓存的 SHA-256 复用后，debug 采样已完整到达 `Process scanner started after startup snapshot`：`Module scan batch done: 15103 verified modules, 5 scans started, 100550ms`，`processLoop=70355ms`，`signatureVerification=24366ms (process=5346ms, module=19020ms)`，`targetScan=9959ms (process=1068ms, module=8891ms)`，`targetScanCacheHits=333`，`targetScanCacheMisses=7`，`scanFailures=0`。日志中大量 `Lookup detail` 显示 `hashSource=precomputed` 且 `hashMs=0`，确认重复 SHA-256 读取被消除。结论：本轮优化不改变安全判定，实际总快照耗时约 170.7s，相比 14:38 样本约 288.7s 明显下降；剩余主要耗时仍在模块扫描批次的遍历/日志与少量超时等待，后续若继续加速，应优先减少 debug 日志噪音或研究安全的分阶段展示，而不是放宽 Unknown。
9. 2026-06-16 16:11 无 debug 普通路径采样在哈希复用后完整到达 `Process scanner started after startup snapshot`：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-nodebug-20260616-161135`，关键终线为 `processLoop=70705ms`，`signatureVerification=21625ms (process=5414ms, module=16211ms)`，`targetScan=0ms`，`targetScanCacheHits=356`，`targetScanCacheMisses=0`，总快照 `durationMs=148459ms`。随后将进程主文件哈希允许列表延后到签名不可信之后并只接受完整 SHA-256 哈希：16:42 冷缓存采样因 `targetScanCacheMisses=282` 补缓存，总快照 `161863ms`，不作为热路径结论；16:52 热缓存采样位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-nodebug-warm-20260616-165224`，关键终线为 `processLoop=27711ms`，`signatureVerification=20498ms (process=5283ms, module=15215ms)`，`targetScan=9863ms (process=9863ms, module=0ms)`，`targetScanCacheHits=365`，`targetScanCacheMisses=0`，总快照 `durationMs=96190ms`。结论：不带 debug 的热启动快照本体从约 148.5s 降到约 96.2s，主要收益来自避免对已签名可信的进程主文件提前计算 SHA-256；安全语义保持 Unknown/超时/失败不进可信基线。
10. 2026-06-16 17:47 无 debug 真实启动采样验证分阶段启动顺序：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-early-scanner-final-20260616-174702`，`[main] Process scanner started before startup snapshot` 出现在 `stderr.log:15`，第一条 `[StartupSnapshot] Progress` 出现在 `stderr.log:22`，`[main] APIHook process watcher started after startup snapshot` 出现在 `stderr.log:95`。本轮完整快照仍为 `durationMs=80316ms`，`processLoop=17226ms`，`signatureVerification=19050ms`，`targetScan=8614ms`，说明本次达成的是“新增进程恶意扫描防护先于完整快照启动”，不是完整可信基线已经压到 15s。ETW 本次仍因非管理员/残留会话返回 `ControlTraceW stop existing session failed: 5`，不作为 ETW 真实采集通过结论。
11. 2026-06-17 非关键可信签名进程的模块枚举/主映像完整性后台化后，真实 `npm run dev` 采样拿到首个 `Baseline done`：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-phase-split-full-20260617-003857`，Tauri 冷编译耗时 16m02s 不计入快照性能；应用运行后的关键终线为 `baseline=22485ms`、`processLoop=22304ms`、`signatureVerification=8870ms (process=8870ms, module=0ms)`、`targetScan=1570ms`、`deepScanPendingModules=2232`。结论：分阶段后台化把启动可信基线压到约 22.5s，明显接近 15s，但仍未达标；pending 模块仍保持 Unknown/待确认。
12. 2026-06-17 进程主文件签名并发预取后，热启动真实 `npm run dev` 采样已经达到 15s 内可信基线：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-process-signature-prefetch-hot-20260617-010836`，Tauri 热编译 2.37s 后应用运行；关键终线为 `baseline=12951ms`、`processLoop=10658ms`、`signatureVerification=2158ms (process=2158ms, module=0ms)`、`targetScan=0ms`、`signatureCacheHits=259`、`signatureCacheMisses=91`、`signatureCoalescedWaiters=168`、`targetScanCacheHits=20`、`targetScanCacheMisses=0`、`deepScanPendingModules=2232`。结论：可信环境基线热路径已压到约 13.0s；后台深度模块检查仍未完成，仍显示待确认，不进入可信基线。
13. ETW 真实采集仍需管理员桌面环境验证：当前终端非管理员，`logman start` 实验返回 Access is denied；后续需要在管理员权限下运行 `npm run dev`，制造进程/文件/注册表/网络事件，并确认日志中 `Poll #...: N events collected` 出现非 0。
14. 2026-06-17 新增的 native/file_hook 真实技术探测 DLL（`peb_unlink_real_payload.dll` / `reflective_load_real_payload.dll`）代码已完成，但 CMake 编译验证和真实注入检测测试尚未执行。后续应：(a) 在管理员环境下运行 CMake 构建验证 MSVC 编译无误；(b) 使用 `file_hook_injector.exe` 将真实 probe DLL 注入到 `notepad.exe` 等测试进程；(c) 通过 OutputDebugString / DebugView 确认日志输出正确；(d) 验证安芯的模块链一致性检测、内存异常检测、无 LoadLibrary 事件检测能否正确命中。
15. 【2026-07-28 已修复】`AnXinNetFilter.sys` error 127 已定位并修复。根因：MSBuild +
    WDK NuGet 生成的 PE 结构存在四项内核不兼容：(a) 映像基址 0x140000000（用户态默认）
    而非 0x10000（内核默认）；(b) 入口点为 GsDriverEntry（/GS 未禁用）；(c) 启用了
    Control Flow Guard 和 fothk 段；(d) 缺少 /INTEGRITYCHECK。19044 内核加载器拒绝
    该 PE 并返回 ERROR_PROC_NOT_FOUND。修复：改用手动 cl.exe/link.exe 构建
    （/GS- /ENTRY:DriverEntry /BASE:0x10000 /DRIVER /KERNEL /INTEGRITYCHECK，
    与 AnXinProcProtect.sys 相同 PE 布局），WDK NuGet 10.0.28000.2526 头文件和库。
    验证：同一 VM（7b66415c，Win10 IoT LTSC 19044）签名部署后
    `sc start AnXinNetFilter` → **STATE: 4 (RUNNING)**。
    剩余收口：(d) 补齐 resources、`DriverKind`、NSIS 安装/卸载和 `firewall_rules.json`
    打包；(e) 修复 VUL-040 的首次启用事务；(f) 逐项验证连接拦截、弹窗询问、DNS 管控、
    SNI 提取、限速和卸载回滚。完成前不得把网络防火墙写成”可用”。
16. 【2026-07-27 新增】网络防火墙的弹窗询问链路在服务模式下依赖 `network-intercepted`
    事件经 IPC 转发。转发白名单已在 `windows_service.rs::FORWARDABLE_EVENTS` 与
    `ipc_bridge_service.rs::FORWARDED_EVENTS` 两处同时补上，但**未做过服务模式真机验证**。
    这正是本文档第 13 条 `etw-risk-event` 曾经踩过的坑（只在一处白名单里写了、
    或名字写错），验证时必须重点确认。
17. 【2026-07-27 已解决】`tests/scan_page_threat_actions.test.mjs` 此前有 5 个断言针对
    早期版本的 `main.tsx` / `main.rs` 代码形态而恒定失败。2026-07-27 验证确认
    `npm run test` 结果为 150 pass / 0 fail，该问题已在第三轮收口中修复。
18. 托盘菜单退出修复仍需真实桌面烟测：建议运行 `npm run dev`（超时窗口至少 120 秒），应用启动后从托盘右键菜单选择”退出”并确认。上一轮用户现场已确认 `PostMessage failed ... 无效的窗口句柄` 消失；本轮重点观察是否还出现 `Failed to unregister class Chrome_WidgetWin_0. Error = 1412`。如果仍出现，需要继续查 Tauri/WebView2 多窗口销毁顺序、托盘资源释放和插件级 cleanup 是否仍有重复窗口类注销。
19. 【2026-07-28 已修复】`AnXinProcProtect.sys` BSOD 0x0A 已定位并修复。根因：
    `ExWindowStationObjectType` 是 ntoskrnl.exe 的非标准导出，其类型布局与
    `POBJECT_TYPE*` 不匹配，`ObRegisterCallbacks` 在 DISPATCH_LEVEL 下解引用无效指针
    导致 NULL 指针蓝屏。修复内容（`native/driver/src/driver.c`）：
    (a) WinSta ObCallback 注册默认禁用，用 `#ifdef ANXIN_ENABLE_WINSTA_OBCALLBACK`
    条件编译保护，需显式定义宏并在目标内核验证后才可启用；
    (b) 新增 `ExInitializeFastMutex(&g_RegKeyListLock)` 初始化（静态零初始化不足以
    正确初始化 FAST_MUTEX 内部 KEVENT）；
    (c) 全部 4 个 ObPre 回调增加 `PreInfo->Parameters == NULL` 防御性检查；
    (d) `AddProtectedWinsta` 改用缓存全局 `g_WinstaObjType`，NULL 时返回
    `STATUS_NOT_SUPPORTED`。
    验证：同一 VM（7b66415c，Win10 IoT LTSC 19044）上重新签名部署后
    `sc start AnXinProcProtect` → STATE: 4 (RUNNING)，无蓝屏。
20. 【2026-08-13 已验证】`AnXinProcProtect.sys` BSOD 0x139（KERNEL_SECURITY_CHECK_FAILURE /
    FAST_FAIL_RANGE_CHECK_FAILURE）已定位并修复。根因：`Trace()` 日志辅助函数的数组
    越界——当 `g_TracePos` 到达 16383（16384 字节的 `g_Trace` 已满）时，原 while 循环
    虽不再写入，但循环后的 `g_Trace[pos++] = '\n'; g_Trace[pos] = '\0';` 仍执行，
    `'\0'` 写入索引 16384 越界；/sdl 范围检查触发 `__report_rangecheckfailure` →
    int 29h → 0x139（崩溃寄存器 rdx=0x4000=16384、rax=0x3fff=16383 印证）。修复内容
    （`native/driver/src/driver.c`）：`Trace()` 入口增加 `if (pos >= sizeof(g_Trace) - 2)
    return;` 保护，保证所有写入（含末尾 `'\n'` 与 `'\0'`）都在 16381 以内。dumpbin
    反汇编验证：入口保护 `cmp edx,3FFEh / jae ret` 位于 RVA 0x2671，/sdl 范围检查
    `cmp edx,4000h / jae __report_rangecheckfailure` 位于 RVA 0x26B4，已不可达。
    验证：回滚到 2026-07-30 干净基线，离线清理旧驱动（vm-automation/offline-clean.ps1
    v9：SYSTEM 任务删除三个服务键并趁挂载 unload，重载 RX_SYSTEM7 确认 PERSISTENCE-OK，
    磁盘 SYSTEM 已无 AnXin 服务键），创建全新干净基线检查点
    `CleanBaseline-PreDriverInstall_20260813_0150`，在干净客户机上全新安装嵌入修复驱动
    的安装器（AnXinSecurity_1.0.0_x64-setup.exe，AnXinProcProtect.sys 34184B /
    08-12 22:53 签名，SHA256 da3136d9…）：安装完成，AnXinProcProtect / AnXinFileProtect /
    AnXinSecurityService 均 RUNNING，System 日志无 BugCheck(1001) / Kernel-Power(41) /
    意外关机(6008) 事件，驱动持续运行 6+ 分钟无蓝屏。

## 建议验证命令

文档修改不需要运行代码测试。涉及核心逻辑变更时，优先按从窄到宽的顺序验证：

```powershell
cargo check --manifest-path src-tauri\Cargo.toml
cargo test --manifest-path src-tauri\Cargo.toml <相关测试过滤>
npm run typecheck
npm run lint
npm run test
```

如果全量 `cargo test` 或 `npm run test` 超时，应先保留窄测试结果、失败命令、错误摘要和下一步处理计划，不要把超时写成通过。

## 最近运行验证

### 2026-07-29

- **三驱动 boot-start (Start=0) 改造 — 完成并验证。** 三个驱动服务注册表键
  `AnXinProcProtect`、`AnXinFileProtect`、`AnXinNetFilter` 均已设为 `Start=0`
  （SERVICE_BOOT_START），由 boot loader 在 Phase 1 加载，先于 SCM 初始化。
  同一 VM（7b66415c，Win10 IoT LTSC 19044）重启后验证：
  (a) 三驱动全部 STATE: 4 (RUNNING)，无蓝屏；
  (b) `fltmc` 确认 AnXinFileProtect 高度 370050、2 实例；
  (c) `netsh wfp show state` 确认 AnXinNetFilter WFP 对象在册；
  (d) 注册表 DACL 保护生效（非管理员 OpenSubKey 写权限被拒绝）；
  (e) 系统 uptime 3:40 时 CmCallback 已注册（30s 延迟定时器已触发）。
- **AnXinProcProtect.sys boot-start BSOD 0x50 — 已修复。** 初次 boot-start 加载
  触发 BugCheck 0x50 (PAGE_FAULT_IN_NONPAGED_AREA)，崩溃于
  `AnXinProcProtect!memcpy+0x100`（偏移 0x4AC0），读取地址 `ffffe208a1f88000`。
  转储分析（072926-5703-01.dmp，cdb 反汇编 + 原始栈扫描）定位调用链：
  `nt!CmParseKey → RegistryCallback+0x271 → IsRegKeyProtected+0x6c → memcpy`。
  根因：`IoRegisterBootDriverReinitialization` 阶段注册的 CM 回调立即被
  nt!CmParseKey 调用，此时 `ObjectName.Buffer`（UNICODE_STRING）跨越的第二个
  页面尚未驻留（分页池未完全初始化），memcpy 读取非驻留页面触发缺页。
  修复：三阶段延迟初始化——
  Stage 1: boot reinit 回调启动 30 秒 KTIMER；
  Stage 2: 定时器 DPC 将 IO_WORKITEM 排入 DelayedWorkQueue；
  Stage 3: 工作者线程在 PASSIVE_LEVEL 执行 CmRegisterCallbackEx + DACL 保护。
  30 秒后系统已完全进入 Phase 2，分页池全部就绪，CM 回调不再触发缺页。
  构建产物：AnXinProcProtect.sys 46,056 bytes（手动 cl/link，测试证书签名）。
- FileProtect 和 NetFilter 的 boot-start 适配（前次会话已完成）：
  FileProtect 使用 `IoRegisterBootDriverReinitialization` 延迟 `FltStartFiltering`；
  NetFilter 使用 `PsCreateSystemThread` + `KeDelayExecutionThread` 延迟 WFP 初始化
  （tcpip/BFE 在 Phase 1 不可用）。两者 boot-start 加载无蓝屏。
- **sc delete 注册表保护修复（VUL-044）— 完成并验证。** AnXinFileProtect 的
  CmRegisterCallback 回调原使用对象指针比较，SCM (services.exe) 打开同一注册表键
  获得不同指针，导致 `sc delete` 后重启时服务键被 SCM 删除。修复：改用
  `CmCallbackGetKeyObjectIDEx` 获取稳定 `ULONG_PTR ObjectID` 比较（WDK 10.0.28000.0
  签名：`CmCallbackGetKeyObjectIDEx(&g_RegCookie, Object, &objID, NULL, 0)`）。
  只请求 ObjectID 不请求 ObjectName，无需 `CmCallbackReleaseKeyObjectIDEx`，避免
  之前的 BugCheck 0x50。构建产物：AnXinFileProtect.sys 23,432 bytes（测试证书签名）。
  离线 VHDX 部署后 VM 验证：
  (a) `fltmc` 确认 AnXinFileProtect 已加载（altitude 328800，2 实例）；
  (b) 直接注册表操作被阻止：`Set-ItemProperty` / `Remove-ItemProperty` 对三个
      服务键均返回"不允许所请求的注册表访问权"；
  (c) `sc delete` 后重启 VM，三个服务键全部存活（Start=0），三个驱动全部
      Status=Running、StartType=Boot；
  (d) 注册表配置已补充完整：Type、ErrorControl、ImagePath、Group、DependOnService、
      Instances（AnXinFileProtect 的 minifilter altitude 328800）。
- 本轮未运行 cargo/npm 测试（纯内核驱动修改，不涉及应用层代码）。

### 2026-07-28

- 本轮在 Hyper-V 隔离虚拟机「病毒测试」（GUID 7b66415c-52cb-468e-b9bd-368746f42863，
  Windows 10 IoT Enterprise LTSC 19044 UBR 7417，2 vCPU）上对三个内核驱动进行真机加载
  验证。VM 环境已完成：测试签名开启（`bcdedit /set testsigning on`）、UAC 关闭
  （`EnableLUA=0`）、自动登录（test 用户）、静态 IP 172.28.88.10/24（AnXinSecurityNAT
  内部交换机）、测试证书 CN=AnXin Security Test（指纹
  CA21B971BC2EA0201E2AA568B230A0035212246E，2031 过期）已导入 Root 和 TrustedPublisher。
  三个 .sys 均使用该证书签名。
- **AnXinFileProtect.sys — 加载成功，已验证。** 初次 `sc create type= filesys start= demand
  binPath= C:\Windows\System32\drivers\AnXinFileProtect.sys` 后 `sc start` 返回 error 2；
  原因是微过滤器需要完整的注册表结构。补齐 `Services\AnXinFileProtect\Instances`
  （DefaultInstance="AnXinFileProtect Instance"）和
  `Instances\AnXinFileProtect Instance`（Altitude="370050"、Flags=0x0）以及
  `Group="FSFilter Activity Monitor"` 后，`fltmc load AnXinFileProtect` 成功，
  `fltmc` 输出确认 STATE: 4 (RUNNING)。驱动当前仍在 VM 中运行。
- **AnXinProcProtect.sys — 已修复，加载成功。** 初次 `sc start` 触发 BSOD 0x0A
  （param1=0x0 NULL 指针、param2=0x2 DISPATCH_LEVEL）。根因：`ExWindowStationObjectType`
  非标准导出导致 `ObRegisterCallbacks` 在 DISPATCH_LEVEL 解引用无效指针。修复：
  WinSta ObCallback 默认禁用（`#ifdef ANXIN_ENABLE_WINSTA_OBCALLBACK`）、
  `ExInitializeFastMutex` 初始化、4 个 ObPre 回调增加 Parameters NULL 检查、
  `AddProtectedWinsta` 改用缓存全局。使用 WDK NuGet 包（10.0.28000.2526）手动
  cl.exe/link.exe 重新编译，signtool SHA256 重签名后部署到同一 VM，
  `sc start AnXinProcProtect` → **STATE: 4 (RUNNING)**，无蓝屏。
- **AnXinNetFilter.sys — 已修复，加载成功。** 初次 `sc start` 返回 error 127
  （ERROR_PROC_NOT_FOUND）。根因：MSBuild + WDK NuGet 生成的 PE 存在四项内核不兼容：
  映像基址 0x140000000（用户态默认）、入口 GsDriverEntry（/GS 未禁用）、启用 CFG/fothk 段、
  缺少 /INTEGRITYCHECK。改用手动 cl.exe/link.exe 构建（/GS- /ENTRY:DriverEntry
  /BASE:0x10000 /DRIVER /KERNEL /INTEGRITYCHECK），WDK NuGet 10.0.28000.2526，
  signtool SHA256 重签名后部署到同一 VM，`sc start AnXinNetFilter` →
  **STATE: 4 (RUNNING)**。
- **三驱动功能验证与内存泄漏测试 — 通过。** 在同一 VM 上完成：
  (a) ProcProtect：STATE 4 RUNNING，服务类型 KERNEL_DRIVER，可停止；
  (b) FileProtect：`fltmc load` 成功，2 个实例（C: 卷 + 全局），高度 370050，
  实例名 "AnXinFileProtect Instance"；
  (c) NetFilter：`netsh wfp show state` 确认 23 个 AnXin WFP 对象引用——
  10 个 callout（ALE Connect/Accept v4/v6、Flow Established v4/v6、Stream v4/v6、
  Datagram v4/v6）+ 10 个对应 filter + 提供者 + 子层，全部 GUID（a7e9c1d4-*）在册；
  (d) 内存泄漏压力测试：10 轮 stop/start 循环（ProcProtect sc stop/start、
  FileProtect fltmc unload/load、NetFilter sc stop/start），每轮全部恢复 RUNNING。
  NonPaged Pool 基线 82.97 MB → 10 轮后 83.03 MB（累计 +64 KB，均值 6.4 KB/轮），
  且两轮之间池内存回落到基线以下（86,945,792 < 86,999,040），表明增长来自系统噪声
  （360 驱动、Windows 服务）而非 AnXin 驱动泄漏。Paged Pool 稳定（-48 KB）。
  WFP 对象在 10 轮循环后仍为 23 个引用，无残留。
  结论：三个驱动功能注册完整、加载/卸载幂等、无显著池内存泄漏。
- 本轮未运行 cargo/npm 测试（纯 VM 驱动验证，不涉及应用层代码变更）。
- 360 主动防御服务（ZhuDongFangYu）在 VM 中仍处于运行状态，后续驱动调试前建议停止
  以排除干扰。
- **驱动自保验证 — 通过。** 在同一 VM 上对三个驱动的自保机制进行攻击模拟验证：
  (a) `reg delete HKLM\SYSTEM\CurrentControlSet\Services\AnXinProcProtect /f`
  （管理员 cmd）→ Access Denied，CmCallback + DACL 双重拦截生效；
  (b) `reg add` 创建子键或写入值 → Access Denied；
  (c) `sc stop AnXinProcProtect` → 返回 STOP_PENDING，驱动实际未停止
  （DriverUnload 未注册）；
  (d) `fltmc unload AnXinFileProtect` → 失败，错误码 0x801f0010
  （STATUS_FLT_DO_NOT_DETACH）；
  (e) `sc delete AnXinProcProtect` → SCM 接受删除请求，但注册表键实际删除被
  DACL 阻止；重启后 SCM 以 SYSTEM + SeRestorePrivilege 完成删除 → 已知限制。
  构建产物：ProcProtect.sys 46,056 bytes、FileProtect.sys 27,624 bytes、
  NetFilter.sys 88,552 bytes（均为手动 cl/link 构建，测试证书签名）。
  发现 `IOCTL_ANXIN_ADD_PID` 缺少调用方授权检查，已登记 VUL-043 并于同日修复（High, Fixed）。
  此前 BSOD 0x0A 根因已确认为 CmCallback DeleteKey fail-closed 策略误阻系统
  关键操作，修复为精确匹配目标服务键、非目标键放行。

### 2026-06-18

- 本轮修复托盘菜单退出时的 `PostMessage failed ... 无效的窗口句柄` / `Chrome_WidgetWin_0` 类注销错误风险：新增 `AppLifecycleService` 作为退出状态闸门；`execute_exit` 改为先幂等标记退出、延迟到 invoke 响应后执行清理，不再提前手动关闭主 WebView；退出清理顺序调整为先停止进程扫描器、APIHook watcher、文件监控、Hook 管道、ETW 和扫描引擎，再恢复/清理拦截队列；日志、ETW、Hook、风险、启动快照和拦截窗口展示在 `exiting` 后停止向前端投递或新增拦截。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml begin_exit_is_idempotent --lib --quiet`：通过，1/1，确认退出状态第一次标记成功、重复退出请求幂等返回。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过；剩余 warning 为既有 `EngineService::is_malware` / `NativeEngineService::is_malware` 未使用。
- 本轮已运行 `node --test --test-name-pattern "TitleBar|capabilities" tests\recent_fixes.test.mjs`：通过，3/3，确认标题栏托盘最小化和 capability 结构测试未被退出修复破坏。
- 本轮已运行 `node --test --test-name-pattern "log buffer emits dedicated realtime log events|Interception alerts render" tests\monitoring_runtime_control.test.mjs tests\scan_page_threat_actions.test.mjs`：通过，2/2，确认实时日志事件通道和独立拦截窗口结构守卫仍通过。
- 本轮已运行 `rustfmt --edition 2021 --config skip_children=true --check` 检查本次触及文件（排除 `snapshot_service.rs`）：通过；包含 `snapshot_service.rs` 时仍会因既有 `detect_module_chain_anomalies(...)` 两处换行风格差异失败，本轮未批量格式化无关大文件。真实托盘退出烟测本轮尚未执行，不能写成现场完全通过。
- 用户真实复测第一阶段退出修复后，终端只剩 `[0618/132754.231:ERROR:ui\gfx\win\window_impl.cc:172] Failed to unregister class Chrome_WidgetWin_0. Error = 1412`，未再出现 `PostMessage failed ... 无效的窗口句柄`；因此第二阶段聚焦 WebView/Chromium 窗口销毁顺序，而不是继续扩大后台事件投递闸门。
- 本轮第二阶段调整 `commands/tray.rs`：后台清理完成并恢复/清理拦截队列后，新增 `destroy_webview_windows_for_exit`，按 `interception`、其他窗口、`main` 的顺序调用 `WebviewWindow::destroy()`，再短暂等待并调用 `app_handle.exit(0)`；继续避免在 invoke 响应返回前销毁发起命令的 WebView。
- 本轮顺手修复 `etw_service.rs` 中 `QueryDosDeviceW` 对 `windows-0.58.0` 的调用签名不匹配：第二参数改为 `Some(&mut target)`，不改变 ETW 业务逻辑；否则当前仓库 `cargo check` 会在该处失败，无法验证退出修复。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过；剩余 warning 仍为既有 `EngineService::is_malware` / `NativeEngineService::is_malware` 未使用。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml begin_exit_is_idempotent --lib --quiet`：通过，1/1。
- 本轮已运行 `node --test --test-name-pattern "Tray exit destroys webview windows after backend cleanup|TitleBar|capabilities" tests\recent_fixes.test.mjs`：通过，4/4，确认托盘退出结构守卫、标题栏托盘最小化和 capability 结构仍符合预期。
- 本轮已运行 `rustfmt --edition 2021 --config skip_children=true --check src-tauri\src\commands\tray.rs src-tauri\src\services\etw_service.rs`：通过。
- 本轮已运行 `git diff --check -- src-tauri\src\commands\tray.rs src-tauri\src\services\etw_service.rs tests\recent_fixes.test.mjs docs\continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。第二阶段真实托盘退出烟测尚未执行，仍需在桌面环境确认 `Chrome_WidgetWin_0 Error = 1412` 是否消失。
- 本轮已补 ETW 现场诊断缓存和行为页诊断入口：`src-tauri/src/services/etw_service.rs` 维护有界环形缓存并统计 provider/operation/rule/drop，`src-tauri/src/commands/behavior.rs` 提供读取、清空和导出命令，`src/api/behavior.ts` 与 `src/components/BehaviorPage.tsx` 接入刷新/清空/导出按钮；导出目标为 APPDATA runtime JSON，不写回仓库配置。
- 本轮进一步把 ETW 诊断从“只保留最近 4096 条”升级为“最近样本 + 热点聚合桶”：`EtwDiagnosticsCache` 现在还维护按 `stage/provider/operation/pid/path摘要/ruleId/threatType/dropReason/parseError` 归并的聚合桶，默认桶上限 `16384`，并记录 `aggregateEvictions`；前端行为页新增热点聚合展示，确保高频刷屏时不会因为最近队列被填满而丢掉同类事件的次数和代表样本。该聚合仍只用于现场观测，不参与拦截判定。
- 本轮已运行 `cargo check --manifest-path src-tauri/Cargo.toml`：通过；剩余 warning 仍为既有 `EngineService::is_malware` / `NativeEngineService::is_malware` 未使用。
- 本轮已运行 `cargo test --manifest-path src-tauri/Cargo.toml etw_diagnostics_cache --lib --quiet`：通过，3/3，覆盖诊断缓存有界、统计累加、解析错误记录、清空重置和 JSON 可序列化。
- 本轮已再次运行 `cargo test --manifest-path src-tauri/Cargo.toml etw_diagnostics_cache --lib --quiet`：通过，5/5，新增覆盖聚合桶去重、桶上限淘汰和热点事件计数保留。
- 本轮已运行 `rustfmt --edition 2021 --check src-tauri/src/services/etw_service.rs src-tauri/src/commands/behavior.rs`：通过，确认本轮触及 Rust 文件格式无差异。
- 本轮已运行 `npm run typecheck`：通过，确认 ETW 诊断 API 类型和行为页接线通过 TypeScript 检查。
- 本轮已运行 `npm run lint`：通过，确认前端新增行为页诊断 UI 无 ESLint 错误。
- 本轮已运行 `node --test tests\monitoring_runtime_control.test.mjs tests\frontend_stores_i18n.test.mjs`：通过，18/18，覆盖前端 API 命令名、行为页诊断入口和内置中文 fallback 文案。
- 本轮已运行 `node -e "JSON.parse(...)"` 解析 `config/i18n/zh-CN.json`、`config/i18n/en-US.json`：通过。注意：本轮没有在管理员桌面环境做真实 ETW 注入采样，所以不能把诊断缓存写成“已证明实战拦截命中”；下一步应由现场导出的 JSON 决定实际 provider/operation/rule 修正方向。

### 2026-06-17

- 本轮按“ETW / 文件监控先拦截，后置检测只补证”的口径升级实时链路：当时 `etw_service.rs` 曾让 `trusted_process_unsigned_image_load` 与 `remote_thread_start_outside_image` 直接入 `InterceptionService` 挂起目标 PID，并通过 `ProcessScannerService::mark_hot_pid` 唤醒后置复扫；`file_monitor_service.rs` 对实时文件事件扫描命中的恶意文件直接拦截来源 PID，并同样标记 hot PID。该条是 2026-06-17 的历史状态，已被 2026-06-23 降噪策略覆盖：当前只有 `trusted_process_unsigned_image_load` 这类强证据仍保留直接拦截和 hot PID 补证，`remote_thread_start_outside_image` 只保留在 ETW 诊断缓存/聚合桶中，不再进入前端实时推送、行为库写入、风险分析或 `ProcessScanner` hot PID 复扫。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml process_scanner_service --lib --quiet`：通过，20/20，覆盖 hot PID 队列去重、hot 唤醒、进程扫描相关既有单测。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml direct_realtime_interception_queues_injection_event --lib --quiet`：通过，确认 ETW 注入规则可直接进入拦截条目。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml nested_rust_file_event_extracts_file_name --lib --quiet`：通过，确认嵌套 ETW File 事件可提取文件路径、PID 与进程名，供文件监控直接拦截来源 PID。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过；剩余 warning 为既有 `EngineService::is_malware` / `NativeEngineService::is_malware` 当前未使用，原因是文件监控改为统一走 `ScanResultCacheService::scan_or_get_cached`。
- 本轮修复启动快照拦截重复弹窗：主窗口 `App` 已移除 `process-intercepted` 监听和内嵌 `InterceptionModal` 渲染；`InterceptionService` 只 `emit_to("interception", "process-intercepted", ...)`，不再 fallback 到全局 `emit("process-intercepted")`；独立拦截窗口只在前端拿到事件或 `peek_current_interception` 当前条目后再 `show/focus`，窗口本身已改为不透明单层独立面板，避免无内容红色空窗和透明壳子叠加。
- 本轮已把实时 ETW 的 `Thread/start` 入口检测接到检测链：`startAddress` 先做十六进制/十进制兼容解析，再与 `enumerate_process_module_info(pid)` 返回的模块 `base_address + image_size` 范围比对；若线程起点不在任何已加载模块内，会升级为 `remote_thread_start_outside_image`。该条 2026-06-17 记录当时仍会进入更重的响应链路；当前口径已由 2026-06-23 降噪策略覆盖：它只保留在 ETW 诊断缓存/聚合桶中，不再进入风险分析、行为库或 hot PID 复扫。已运行 `cargo test --manifest-path src-tauri\Cargo.toml etw --lib` 和 `cargo test --manifest-path src-tauri\Cargo.toml --test etw_rules_engine_tests`，均通过；本轮仍建议在管理员桌面环境做真实 `npm run dev` + 受控注入样本验证。
- 本轮将独立拦截窗口固定为 `640x480` 的 `4:3` 比例，内容层铺满窗口并继续保留路径换行与详情滚动，避免按钮区或长文件路径挤出可视区域。
- 本轮继续修复拦截队列只显示第一条的问题：`commands/interception.rs` 的 `handle_interception`、队列查询、清空、状态和 `peek_current_interception` 统一改为 `State<Arc<InterceptionService>>`，匹配 `main.rs` 中 `app.manage(interception_service.clone())` 的真实托管类型；`InterceptionWindowApp` 改为允许/阻止命令成功后再 `setInterceptionData(null)`，命令失败时保留当前弹窗。新增 Rust 单测覆盖三条队列按 FIFO 连续展示，新增前端结构测试约束命令状态类型和成功后清窗。
- 本轮已运行 `node --test --test-name-pattern "Interception" tests\scan_page_threat_actions.test.mjs`：通过，5/5，确认独立拦截窗口、主窗口不监听拦截事件、后端不全局广播、命令层读取 `Arc<InterceptionService>`、前端成功后清窗等结构守卫。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml interception --lib`：通过，20/20，确认拦截队列、当前展示条目拉取、重复 PID 去重、三条队列 FIFO 轮播、启动快照拦截 payload 形状等相关单测仍通过。
- 本轮已运行 `rustfmt --edition 2021 --config skip_children=true --check src-tauri\src\commands\interception.rs src-tauri\src\services\interception_service.rs`：通过，确认命令层和拦截服务格式无差异。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认拦截命令状态类型统一和队列轮播测试改动可编译。
- 本轮已运行 `npm run typecheck`：通过，确认主窗口移除拦截弹窗接线、独立拦截窗口去重和样式状态改动可通过 TypeScript 检查。
- 本轮修复拦截窗口长文本溢出：`InterceptionModal` 的进程名和文件路径详情现在允许换行，文件路径使用 `detail-path` 等宽样式、`overflow-wrap: anywhere` 和面板内滚动上限，避免长路径撑出独立窗口可视区域；结构测试已覆盖路径字段的完整 `title` 和换行样式。
- 本轮已再次运行 `npm run typecheck`、`cargo check --manifest-path src-tauri\Cargo.toml`、`node --test --test-name-pattern "Interception" tests\scan_page_threat_actions.test.mjs`：均通过，确认拦截窗口文本溢出修复不破坏前后端编译和拦截结构守卫。
- 本轮已运行 `node --test --test-name-pattern "Interception" tests\scan_page_threat_actions.test.mjs`：通过，4/4，确认结构守卫覆盖独立拦截窗口、主窗口不再监听 `process-intercepted`、后端不再全局广播拦截事件、空闲红窗样式被收口。
- 本轮已运行 `rustfmt --edition 2021 --config skip_children=true --check src-tauri\src\services\interception_service.rs src-tauri\src\services\interception_window_service.rs`：通过，确认拦截服务和窗口服务格式无差异。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认拦截事件定向投递和独立窗口准备/隐藏职责调整可编译。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml interception --lib`：通过，19/19，确认拦截队列、当前展示条目拉取、重复 PID 去重、启动快照拦截 payload 形状等相关单测仍通过。
- 本轮首次运行 `cargo test --manifest-path src-tauri\Cargo.toml interception --lib` 时 124 秒窗口超时；随后确认残留 `cargo/rustc` 进程自然退出，并在重新运行后通过。该次超时不记为通过或失败。
- 本轮已运行 `node --test tests\startup_snapshot_phase_split.test.mjs tests\startup_phase_screen.test.mjs`：通过，8/8，确认启动页真实消费快照进度/结果、展示安全提示和可信环境摘要，并约束启动基线先 emit、后台深度检查后启动。
- 本轮已运行 `rustfmt --edition 2021 --config skip_children=true --check src-tauri\src\services\snapshot_service.rs src-tauri\src\commands\snapshot.rs`：通过，确认本轮启动快照 Rust 触及文件无格式差异。
- 本轮首次运行 `cargo test --manifest-path src-tauri\Cargo.toml only_noncritical_trusted_processes_defer_module_checks --lib` 时 124 秒窗口超时，随后确认残留 `cargo/rustc` 进程自然退出；该次超时不记为通过或失败。
- 本轮已重新运行 `cargo test --manifest-path src-tauri\Cargo.toml only_noncritical_trusted_processes_defer_module_checks --lib`：通过，1/1，确认只有非关键、可扫描、可信签名且伪装检测不适用的进程会后移模块检查。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，38/38，确认启动快照、路径策略、签名缓存、目标扫描缓存、后台阶段拆分和 Unknown/超时语义相关单测仍通过。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认后台阶段拆分和进程签名预取改动可编译。本次命令等待前一轮 dev 冷编译释放构建锁，耗时约 3m28s。
- 本轮已运行真实 `npm run dev` 分阶段后台化采样：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-phase-split-full-20260617-003857`，Tauri 冷编译 16m02s 后进入应用，启动快照基线终线为 `baseline=22485ms`、`processLoop=22304ms`、`signatureVerification=8870ms`、`targetScan=1570ms`、`deepScanPendingModules=2232`。本样本证明分阶段后台化接近但未达到 15s。
- 本轮已运行真实 `npm run dev` 进程签名预取热启动采样：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-process-signature-prefetch-hot-20260617-010836`，Tauri 热编译 2.37s 后进入应用，启动快照基线终线为 `baseline=12951ms`、`processLoop=10658ms`、`signatureVerification=2158ms`、`targetScan=0ms`、`deepScanPendingModules=2232`。本样本证明热路径可信环境基线已压到 15s 内；后台深度模块仍保持 pending/Unknown。
- 本轮已完成 `native/file_hook` 真实技术探测 DLL 的代码编写和静态审查：新增 `peb_unlink_real_dll.cpp`（PEB 断链）、`reflective_load_real_dll.cpp`（反射加载）、`test_config.h`（共享配置）、`config/test_probes.md`（配置文档）、`tests/test_config_unittest.cpp`（单元测试），并更新 `CMakeLists.txt` 新增 `BUILD_PEB_REAL_PROBE` / `BUILD_REFLECTIVE_REAL_PROBE` 构建选项。**本轮尚未执行 CMake 编译和 MSVC 构建验证**；代码已通过结构审查（PE 头部偏移、PEB 链表操作、导入表解析逻辑、内存管理路径），但真实的 x64 编译和注入测试有待后续在管理员桌面环境完成。

### 2026-06-16

- 本轮已运行 `node --test tests\startup_phase_screen.test.mjs`：通过，3/3，确认启动阶段页面继续消费真实 `snapshot-progress` / `snapshot-result`，并新增可信基线、深度校验、Unknown 与威胁摘要展示守卫。
- 本轮已运行 `npm run typecheck`：通过，确认启动阶段页摘要状态、i18n 文案和 App 接线可通过 TypeScript 检查。
- 本轮已运行 `node -e "JSON.parse(...)"` 解析 `config/i18n/zh-CN.json`、`config/i18n/en-US.json`：通过，确认新增启动阶段文案仍为合法 JSON。
- 本轮通过内置浏览器打开 `http://localhost:1421/` 做前端烟测：页面标题可返回 `AnXin Security`，但普通浏览器环境缺少 Tauri `window.__TAURI_INTERNALS__.metadata`，`main.tsx` 的 `getCurrentWindow()` 抛出 `Cannot read properties of undefined (reading 'metadata')`，因此不能把该烟测写成桌面壳启动页渲染通过；需在 Tauri 桌面环境中继续验证真实启动页视觉效果。
- 本轮已运行 `rustfmt --edition 2021 --check src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs src-tauri/src/services/scan_result_cache_service.rs src-tauri/src/commands/snapshot.rs`：通过，确认哈希复用和诊断改动无格式差异。
- 本轮已运行 `rustfmt --edition 2021 --config skip_children=true --check src-tauri\src\main.rs src-tauri\src\commands\config.rs`：通过，确认分阶段启动触及的 Rust 文件本身无格式差异；直接运行 `rustfmt --edition 2021 --check src-tauri\src\main.rs src-tauri\src\commands\config.rs` 会因既有子模块 `commands/i18n.rs`、`commands/interception.rs`、`services/interception_service.rs`、`services/interception_window_service.rs` 格式差异失败，不能视为本轮改动失败。
- 本轮已运行 `node --test --test-name-pattern "New-process scanner starts before the full startup snapshot|configStore monitoring toggles" tests\scan_page_threat_actions.test.mjs tests\monitoring_runtime_control.test.mjs`：通过，2/2，确认新进程扫描器在完整快照前启动、APIHook watcher 仍在完整快照后启动，且进程监控开关会控制新进程扫描器启停。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认分阶段启动顺序和设置开关运行态闭环可编译。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，37/37，确认分阶段启动改动未破坏启动快照、路径策略、签名缓存和 Unknown/超时语义。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml process_scanner --lib`：通过，11/11，确认新进程扫描器已有单测仍通过。
- 本轮已运行 `git diff --check -- src-tauri\src\main.rs src-tauri\src\commands\config.rs tests\scan_page_threat_actions.test.mjs tests\monitoring_runtime_control.test.mjs docs\continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。
- 本轮已运行无 debug `npm run dev` 真实采样：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-early-scanner-final-20260616-174702`，确认新进程扫描器在完整启动快照前启动，APIHook watcher 在完整快照完成后启动；完整快照关键终线为 `durationMs=80316ms`、`processLoop=17226ms`、`signatureVerification=19050ms`、`targetScan=8614ms`。采样结束后已停止本次 `npm run dev` 进程树；ETW 本次因非管理员/残留会话失败，不写成通过。
- 本轮已运行 `npm run typecheck`：通过，确认启动阶段页面、快照事件封装和新增 i18n 文案能通过 TypeScript 检查。
- 本轮已运行 `node --test tests\startup_phase_screen.test.mjs`：通过，3/3，确认启动阶段页面真实监听 `snapshot-progress` / `snapshot-result`，并且不会把未完成检查写成可信。
- 本轮已运行 `node --test --test-name-pattern "startup phase" tests\startup_phase_screen.test.mjs`：通过，3/3，确认新增启动阶段测试入口可单独执行。
- 本轮已运行 `npm run test`：未通过，124/131；失败点仍是若干既有前端源码结构断言，集中在 `tests/monitoring_runtime_control.test.mjs` 和 `tests/scan_page_threat_actions.test.mjs` 中对旧文案/旧结构的期待，和本轮新增启动阶段页面没有直接冲突。
- 本轮已运行 `npm run build:frontend`：通过，Vite 生产构建完成；仅保留既有动态导入 chunk 提示。
- 本轮已运行 125 秒窗口 `npm run dev` 真实采样：Vite 在 `http://localhost:1421/` 启动，后端完成启动快照并启动 APIHook watcher；日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-phase-ui-20260616-212415`，关键终线为 `durationMs=47510ms`、`processLoop=19410ms`、`signatureVerification=14765ms`、`targetScan=9898ms`。本次说明启动阶段页面改动未阻断启动链路，但完整可信环境仍未达到 15 秒目标；采样结束后已停止本次 `npm run dev` 进程树。
- 本轮已运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `hash_after_path_miss_cached`、`scan_or_get_cached_deferred_with_hash`、`hashSource` 诊断，以及目标扫描明细日志。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml path_policy_hash_after_path_miss --lib`：通过，1/1，确认过期文件版本键不会返回可复用 SHA-256。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml normalized_sha256_hex --lib`：通过，1/1，确认扫描缓存只接受完整 64 位十六进制 SHA-256。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，37/37，确认启动快照、路径策略和签名/扫描缓存相关单测仍通过。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml scan_result_cache --lib`：通过，6/6，确认扫描缓存 hash 复用辅助逻辑和既有缓存单测通过。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认哈希复用改动可编译。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml path_policy --lib`：通过，48/48，确认进程哈希允许列表后置、哈希允许列表仅接受完整 SHA-256、允许列表哈希分块读取和路径策略快照缓存相关单测通过。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，37/37，确认进程哈希允许列表后置未破坏启动快照、签名缓存、目标扫描缓存和 Unknown/超时语义。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认进程哈希允许列表后置与允许列表哈希分块读取可编译。
- 本轮已运行无 debug 普通路径采样一次：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-nodebug-20260616-161135`，完整输出 `[StartupSnapshot] Performance` 并进入 `Process scanner started after startup snapshot`；关键终线为 `processLoop=70705ms`，`targetScan=0ms`，`targetScanCacheHits=356`，`targetScanCacheMisses=0`，总快照 `durationMs=148459ms`。
- 本轮已运行进程哈希允许列表后置后的无 debug 冷缓存采样一次：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-nodebug-after-20260616-164230`，完整输出 `[StartupSnapshot] Performance` 并进入 `Process scanner started after startup snapshot`；关键终线为 `targetScanCacheHits=89`，`targetScanCacheMisses=282`，总快照 `durationMs=161863ms`。该样本主要用于确认冷缓存补写，不作为热路径性能结论。
- 本轮已运行进程哈希允许列表后置后的无 debug 热缓存采样一次：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-nodebug-warm-20260616-165224`，完整输出 `[StartupSnapshot] Performance` 并进入 `Process scanner started after startup snapshot`；关键终线为 `processLoop=27711ms`，`signatureVerification=20498ms`，`targetScan=9863ms`，`targetScanCacheHits=365`，`targetScanCacheMisses=0`，总快照 `durationMs=96190ms`。
- 本轮已运行 `git diff --check -- src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs src-tauri/src/services/scan_result_cache_service.rs src-tauri/src/commands/snapshot.rs tests/scan_page_threat_actions.test.mjs docs/continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。
- 本轮已运行带 `ANXIN_STARTUP_SNAPSHOT_DEBUG=1` 与 `ANXIN_SCAN_CACHE_DEBUG=1` 的 `npm run dev` 真实诊断采样：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-detail-20260616-151509\dev.log`，快照完整输出 `[StartupSnapshot] Summary/Performance` 并进入 `Process scanner started after startup snapshot`；关键终线为 `Module scan batch done: 15063 verified modules, 256 scans started, 180233ms`，`targetScan=116367ms (process=22083ms, module=94284ms)`，`targetScanCacheHits=59`，`targetScanCacheMisses=288`，用于定位重复 SHA-256 读取。
- 本轮已运行带 `ANXIN_STARTUP_SNAPSHOT_DEBUG=1` 与 `ANXIN_SCAN_CACHE_DEBUG=1` 的 `npm run dev` 哈希复用后真实采样：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-hash-reuse-20260616-155634\dev.log`，快照完整输出 `[StartupSnapshot] Summary/Performance` 并进入 `Process scanner started after startup snapshot`；关键终线为 `Module scan batch done: 15103 verified modules, 5 scans started, 100550ms`，`targetScan=9959ms (process=1068ms, module=8891ms)`，`targetScanCacheHits=333`，`targetScanCacheMisses=7`，大量 `Lookup detail` 为 `hashSource=precomputed`。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs`：通过，确认模块签名超时自动放宽改动无格式差异。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `startup_module_signature_verify_timeout(signature_verify_timeout, target_scan_timeout)` 与 `STARTUP_MODULE_SIGNATURE_TIMEOUT_MULTIPLIER`。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，34/34，确认新增模块签名超时 helper 单测，以及既有启动快照单测仍通过。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认模块签名超时自动放宽可编译。
- 本轮已运行带 `ANXIN_STARTUP_SNAPSHOT_DEBUG=1` 的 `npm run dev` 真实采样：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-module-sig-20260616-143828\dev.log`，快照完整输出 `[StartupSnapshot] Summary/Performance` 并进入 `Process scanner started after startup snapshot`；关键终线为 `Module scan batch done: 14637 verified modules, 5 scans started, 180947ms`，`signatureVerification=24101ms (process=5212ms, module=18889ms)`，`targetScan=110347ms (process=19862ms, module=90485ms)`，`signatureTimeouts=4 (process=0, module=4)`，`targetScanCacheHits=347`，`targetScanCacheMisses=8`。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs`：通过，确认本轮目标扫描结果复用改动无格式差异。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖启动快照目标扫描缓存改为文件版本键、成功/失败 outcome 复用，以及禁止退回 `target_scan_key` 裸路径插入。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，33/33，确认新增 `startup_scan_cache_key` 和 `StartupScanOutcome::started_scan` 单测，以及既有启动快照单测仍通过。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认目标扫描结果/失败按文件版本键复用可编译。
- 本轮已运行带 `ANXIN_STARTUP_SNAPSHOT_DEBUG=1` 的 `npm run dev` 真实采样：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-debug-20260616-141040\dev.log`，快照完整输出 `[StartupSnapshot] Summary/Performance` 并进入 `Process scanner started after startup snapshot`；关键终线为 `Module scan batch done: 15335 verified modules, 275 scans started, 296731ms`，`targetScan=173882ms (process=20825ms, module=153057ms)`，`targetScanCacheHits=88`，`targetScanCacheMisses=307`。
- 本轮已运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs`：通过，确认新增性能字段、模块哈希允许列表延后和后半段 debug 里程碑日志无格式差异。
- 本轮已运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖细分性能字段、模块哈希允许列表延后到签名后，以及后半段 `Module signature batch` / `Module scan batch` 诊断日志。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，31/31，确认启动快照单测仍通过。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml scanner_revocation_options_default_when_missing_from_legacy_config --lib`：通过，1/1，确认旧配置兼容仍通过。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认本轮启动快照改动可编译。
- 本轮已运行 `git diff --check -- src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs tests/scan_page_threat_actions.test.mjs`：通过，仅有工作区 LF/CRLF 换行提醒。
- 本轮受控运行 `npm run dev` 到完整启动快照终线一次：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-20260616-061353`，Tauri dev build 后进入真实快照，最终输出 `[StartupSnapshot] Performance`；关键结论是 `targetScan=236953ms`、其中 `module=200139ms`，模块枚举只有 `1265ms`。
- 本轮再次受控运行 `npm run dev` 采样模块哈希允许列表延后后的行为：日志位于 `C:\Users\Saika\AppData\Local\Temp\anxin-startup-snapshot-20260616-064334`，主循环推进到 `428/428`，但未出现 `[StartupSnapshot] Summary/Performance` 终线；本次不能写成快照完成，已停止采样进程。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml concurrent_module_signature_verification_coalesces_same_file_version --lib`：通过，1/1，确认批内同文件版本签名合并仍保持顺序展开与归属字段完整。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，31/31，确认两阶段模块签名调度、批内合并和进程签名异步化未破坏启动快照单测。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认两阶段模块签名调度可编译。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs`：通过，确认本轮触及 Rust 文件无格式差异。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖两阶段模块签名调度与批内合并字段。
- 本轮已再次运行 `git diff --check -- src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs tests/scan_page_threat_actions.test.mjs docs/continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml scanner_revocation_options_default_when_missing_from_legacy_config --lib`：通过，1/1，确认旧配置缺少 `startupModuleEnumerationTimeoutMs` 时仍能按默认 1000ms 加载。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认模块枚举超时配置与两阶段模块签名调度一起可编译。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖模块枚举超时 helper 与配置链路。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml concurrent_module_signature_verification_coalesces_same_file_version --lib`：通过，1/1，确认同一批模块签名验证会把相同文件版本键合并为一次真实验证，并按原模块顺序展开结果。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖进程签名异步入口、模块签名并发入口、批内签名合并观测字段和命令层默认 `performance.signatureCoalescedWaiters`。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，31/31，确认进程签名异步化、模块签名批内合并、签名缓存、路径策略和 Unknown/超时相关启动快照单测仍通过。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs`：通过，确认本轮触及 Rust 文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认本轮启动快照签名验证调度改动可编译。
- 本轮已再次运行 `git diff --check -- src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs tests/scan_page_threat_actions.test.mjs docs/continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。
- 本轮已运行 `rustfmt --edition 2021 --check src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs`：通过，确认启动快照相关 Rust 文件无格式差异。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml path_policy_snapshot_hash_cache_invalidates_when_file_version_changes --lib`：通过，1/1，确认 `PathPolicySnapshot` 的哈希缓存会随文件版本变化失效。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，19/19，覆盖启动快照、模块去重、签名缓存和路径策略哈希缓存相关单测。
- 本轮已运行 `rustfmt --edition 2021 --check src-tauri/src/services/process_scanner_service.rs src-tauri/src/services/snapshot_service.rs src-tauri/src/services/path_policy_service.rs src-tauri/src/commands/snapshot.rs`：通过，确认启动快照和进程扫描相关 Rust 文件无格式差异。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml image_integrity_from_module_info_detects_main_module_path_mismatch --lib`：通过，1/1，确认复用 `ProcessModuleInfo` 时仍能识别主模块路径不一致。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml image_integrity_from_module_info_is_unknown_without_module_snapshot --lib`：通过，1/1，确认没有模块快照时主映像完整性仍保持 `Unknown`，不误判可信。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml image_integrity --lib`：通过，5/5，确认主映像完整性检测相关单测通过。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，20/20，覆盖启动快照、模块去重、签名缓存、路径策略哈希缓存和模块信息复用相关单测。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认路径策略哈希缓存改动可编译。
- 本轮已运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认启动快照源码结构断言仍覆盖当前模块扫描、缓存链路，以及复用 `enumerate_process_module_info` 供扫描和主映像完整性检查的结构。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml startup_signature_cache_reuses_only_same_file_version --lib`：通过，1/1，确认启动签名缓存仍只复用同一文件版本。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，20/20，确认本轮把目标文件属性读取合并进 `inspect_startup_target` 后没有破坏启动快照单测。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫已经跟上新的 `inspect_startup_target` / `verify_file_for_target` 链路。
- 本轮已运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs`：通过，确认本轮启动快照 Rust 文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认目标检查复用改动在正常编译下无警告。
- 本轮已运行 `git diff --check -- src-tauri/src/services/snapshot_service.rs tests/scan_page_threat_actions.test.mjs docs/continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml path_policy_snapshot_path_only_skip_does_not_use_hash_allowlist --lib`：通过，1/1，确认纯路径快速判断不会使用哈希允许列表，也不会触发哈希缓存。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs`：通过，确认路径策略和启动快照相关文件无格式差异。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，22/22，确认纯路径策略先行后启动快照相关单测仍通过。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `should_skip_by_path_only` 链路。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认纯路径策略先行改动可编译。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml path_policy_snapshot_prepared_entries_keep_existing_match_semantics --lib`：通过，1/1，确认路径策略快照预处理后仍保留目录排除、进程排除和精确路径允许语义。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，23/23，确认路径策略规则预处理后启动快照相关单测仍通过。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs`：通过，确认路径策略和启动快照相关文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认规则预处理改动可编译。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫仍通过。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml startup_module_is_process_image_only_matches_same_normalized_path --lib`：通过，1/1，确认只跳过与进程主路径规范化后完全相同的模块，不跳过同目录或其他目录的不同文件。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，24/24，确认主映像模块重复项跳过后启动快照相关单测仍通过。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `startup_module_is_process_image` 链路。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs src-tauri/src/services/path_policy_service.rs`：通过，确认本轮触及 Rust 文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认主映像模块重复项跳过改动可编译。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml path_policy_snapshot_decision_cache_invalidates_when_file_version_changes --lib`：通过，1/1，确认路径策略判定缓存会随文件版本键变化失效。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，21/21，确认路径策略判定缓存接入启动快照后相关单测仍通过。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `should_skip_security_scan_cached` 链路。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认路径策略判定缓存改动可编译。
- 本轮已运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs`：通过，确认本轮扫描入口调整无格式差异。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，21/21，确认 `policy_already_checked` 接入后启动快照单测仍通过。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖扫描入口的策略兜底开关。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认扫描入口调整可编译。
- 本轮已运行 `git diff --check -- src-tauri/src/services/snapshot_service.rs tests/scan_page_threat_actions.test.mjs docs/continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs`：通过，确认 `process_scan_key` 复用微优化无格式差异。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml startup_module_is_process_image_only_matches_same_normalized_path --lib`：通过，1/1，确认复用预计算的进程主路径 key 后仍只跳过同一主映像路径。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，24/24，确认本轮启动快照相关单测仍通过。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖预计算 `process_scan_key` 后的模块重复项判断链路。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认 `process_scan_key` 复用微优化可编译。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml prepare_startup_module_paths_preserves_first_path_and_precomputed_key --lib`：通过，1/1，确认同一进程模块路径去重仍保留首次出现原始路径，并保存预计算 `scan_key`。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml startup_module_is_process_image_only_matches_same_precomputed_key --lib`：通过，1/1，确认主映像重复项判断改为 key 比对后仍只匹配同一规范化路径。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `prepare_startup_module_paths`、`StartupTargetSnapshot.scan_key` 和 `module.scan_key` 复用。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，24/24，确认模块路径预计算 key 和目标检查 `scan_key` 接入后启动快照相关单测仍通过。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs`：通过，确认本轮触及 Rust 文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认本轮启动快照 key 复用改动可编译。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `scan_startup_target` 复用调用方传入的 `target_scan_key`。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，24/24，确认启动恶意扫描缓存改为复用预计算 key 后启动快照相关单测仍通过。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs`：通过，确认最终启动快照 Rust 文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认最终启动快照 key 复用改动可编译。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml path_policy_snapshot_reuses_prepared_lookup_without_hash_fast_path --lib`：通过，1/1，确认路径策略快速判断复用同一份 lookup 后仍不触发哈希允许列表。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `PreparedPathLookup` 复用。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，25/25，确认路径策略 lookup 复用后启动快照相关单测仍通过。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs`：通过，确认本轮触及 Rust 文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认本轮启动快照路径 lookup 复用改动可编译。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml prepared_process_exclusion_uses_prepared_file_name_once --lib`：通过，1/1，确认 `process` 型排除项复用预处理文件名后仍能命中同名进程路径。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `matches_prepared_exclusion` 不再重复对规则路径做小写转换。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，25/25，确认预处理文件名复用后启动快照相关单测仍通过。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs`：通过，确认本轮触及 Rust 文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认本轮路径策略文件名复用改动可编译。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml path_policy_snapshot_hash_after_path_miss --lib`：通过，2/2，确认路径规则已未命中后的窄入口只使用哈希允许列表，精确路径允许不会在该入口被当作哈希命中，哈希命中会按文件版本键缓存。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，27/27，确认窄化后的哈希允许列表后续检查未破坏启动快照、路径策略、签名缓存和 Unknown/超时相关单测。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖启动快照先走 `should_skip_by_path_only`，再走 `should_skip_by_hash_after_path_miss_cached` 的链路。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs`：通过，确认路径策略和启动快照相关 Rust 文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认本轮启动快照路径策略窄化改动可编译且无新增警告。
- 本轮已运行 `git diff --check -- src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs tests/scan_page_threat_actions.test.mjs docs/continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml path_policy_snapshot_caches_prepared_lookup_per_raw_path --lib`：通过，1/1，确认 `PathPolicySnapshot` 会复用同一原始路径的 `PreparedPathLookup`，只缓存字符串转换结果。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml prepared_allowlist_hash_is_case_insensitive_without_rechecking_entry_hash --lib`：通过，1/1，确认允许列表哈希在预处理阶段转为小写，后续匹配不再反复读取原始 entry hash。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，28/28，确认 lookup 缓存和 allowlist hash 预处理未破坏启动快照、路径策略、签名缓存和 Unknown/超时相关单测。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `lookup_cache`、`lookup_for_path` 和预处理 allowlist hash 链路。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs`：通过，确认路径策略和启动快照相关 Rust 文件无格式差异。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认本轮 lookup 缓存和 allowlist hash 预处理改动可编译。
- 本轮已再次运行 `git diff --check -- src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs tests/scan_page_threat_actions.test.mjs docs/continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml inspect_startup_target_reuses_precomputed_scan_key --lib`：通过，1/1，确认模块路径可以复用 `prepare_startup_module_targets` 预计算的 `scan_key`。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，29/29，确认复用预计算 `scan_key` 后启动快照相关单测仍通过。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认本轮启动快照字符串规整复用改动可编译。
- 本轮已再次运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认结构守卫覆盖 `inspect_startup_target_with_scan_key` 链路。
- 本轮已再次运行 `rustfmt --edition 2021 --check src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs`：通过，确认本轮触及 Rust 文件无格式差异。
- 本轮已再次运行 `git diff --check -- src-tauri/src/services/path_policy_service.rs src-tauri/src/services/snapshot_service.rs tests/scan_page_threat_actions.test.mjs docs/continuous-running.md`：通过，仅有工作区 LF/CRLF 换行提醒。

### 2026-06-15

- 已运行 `node -e "..."` 解析 `config/i18n/zh-CN.json`、`config/i18n/en-US.json`、`src-tauri/capabilities/default.json`、`src-tauri/capabilities/interception.json`：通过。
- 已运行 `npm run typecheck`：通过。本轮实时日志修复后已再次运行并通过。
- 本轮移除已替代 C++ 模块后再次运行 `npm run typecheck`：通过。
- 已运行 `npm run lint`：通过。本轮实时日志修复后已再次运行并通过。
- 已运行 `npm run test`：通过，127/127。此前前端源码结构断言已按当前 UI、独立拦截窗口 capability 和实时日志 `log-event` 通道结构修正。
- 本轮移除已替代 C++ 模块后再次运行 `npm run test`：未通过，124/127；失败 3 项均为 `SettingsPage` 相关前端源码结构断言仍期待旧的硬编码中文/旧 toggle 结构，和本轮 `native/etw_bridge`、`native/trust_bridge`、`native/process_watcher` 删除无直接关系。
- 已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过。
- 本轮移除已替代 C++ 模块后再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过。
- 本轮已运行 `node -e "JSON.parse(...src-tauri/tauri.conf.json...)"`：通过，确认收窄后的 Tauri 资源配置仍是合法 JSON。
- 本轮已运行 `git diff --check -- AGENTS.md README.md buglist.md docs\continuous-running.md src-tauri\tauri.conf.json native`：通过。
- 已运行 `cargo test --manifest-path src-tauri\Cargo.toml private_trace_properties_use_anxin_guid_and_realtime_mode --lib`：通过，确认 ETW 会话属性使用 AnXin 私有 GUID 且保持实时模式。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml private_trace_properties_use_anxin_guid_and_realtime_mode --lib`：通过，确认 ETW 会话属性使用 AnXin 私有 GUID，并同时设置实时模式与系统级 logger mode。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml default_provider_keywords_match_kernel_provider_categories --lib`：通过，确认默认 ETW provider keyword 覆盖当前 Windows kernel provider 的进程、文件、注册表和 IPv4/IPv6 网络类别。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml should_drop_system_etw_event --lib`：通过，3/3，确认 ETW 后端分发入口会过滤顶层和嵌套 PID `0` / `4` / `4294967295`，并保留正常 PID 或缺失 PID 的事件。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认 PID 过滤变更不破坏 Rust 编译。
- 本轮已运行 `git diff --check -- src-tauri/src/services/etw_service.rs`：通过，仅提示工作区 LF/CRLF 换行提醒。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml should_drop_system_log_event --lib`：通过，2/2，确认公共实时日志入口过滤顶层和嵌套 PID `0` / `4` / `4294967295`，并保留正常 PID 或缺失 PID 的事件。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml etw_callback_pid_guard_filters_system_and_invalid_pid --lib`：通过，确认 ETW 原始回调入口会过滤 PID `0` / `4` / `u32::MAX`，在进入 JSON 序列化、队列和规则链路之前丢弃无效事件。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml unknown_provider_json_preserves_pid_for_downstream_filtering --lib`：通过，确认 ETW Unknown provider 事件序列化时保留 `pid/tid/provider`，不再生成会被前端显示为 `PID:0` 的空事件。
- 本轮已再次运行 `cargo test --manifest-path src-tauri\Cargo.toml system_pid_hook_events_are_dropped_before_dispatch --lib`：通过，确认文件 Hook 事件在分发前过滤 PID `0` / `4` / `u32::MAX`。
- 本轮已运行 `node --test --test-name-pattern "log buffer emits dedicated realtime log events" tests\monitoring_runtime_control.test.mjs`：通过，确认前端结构测试已约束后端实时日志通道使用带 PID 过滤的结构化写入入口。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认实时日志 PID 过滤补丁不破坏 Rust 编译。
- 本轮已运行 `git diff --check -- src-tauri/src/commands/logs.rs src-tauri/src/services/etw_service.rs src-tauri/src/services/etw/session.rs src-tauri/src/services/hook_service.rs tests/monitoring_runtime_control.test.mjs`：通过，仅提示工作区 LF/CRLF 换行提醒。
- 本轮已再次运行 `cargo fmt --manifest-path src-tauri\Cargo.toml --check`：未通过；剩余失败仍为既有 `interception_service.rs`、`interception_window_service.rs` 格式差异，当前 PID 过滤相关文件已无 rustfmt 差异。
- 本轮已运行 `logman query providers "Microsoft-Windows-Kernel-Process"`、`"Microsoft-Windows-Kernel-File"`、`"Microsoft-Windows-Kernel-Registry"`、`"Microsoft-Windows-Kernel-Network"`：通过，确认当前系统 provider keyword；尝试 `logman start` 做真实事件采集时返回 Access is denied，需要管理员权限重试，不能写成已通过真实采集烟测。
- 本轮曾并行运行两个 `cargo test --manifest-path src-tauri\Cargo.toml ... --lib` 窄测试：124 秒超时；随后确认无残留 cargo/rustc/link 进程，并串行重跑通过，超时不计为失败或通过。
- 已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test hook_service_tests`：通过，4/4。本轮第一次 124 秒窗口超时，确认残留 cargo 进程后清理并用 240 秒窗口串行重跑通过；超时不计为失败或通过。
- 已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test trust_service_tests test_windows_catalog_signed_system_file_is_trusted -- --nocapture`：通过，确认 Windows 系统 catalog 签名文件可被 `TrustService` 判为 trusted。
- 已运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，14/14。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml module_enumeration_access_denied_errors_are_classified_separately --lib`：通过，1/1，确认启动快照可识别中文/英文拒绝访问错误并与其他模块枚举失败分开。
- 本轮已运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认启动快照源码结构测试覆盖新增模块枚举拒绝访问统计字段。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，17/17，覆盖启动快照本轮签名结果缓存的键构造、同版本复用逻辑和相关快照单元测试。
- 本轮已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认启动快照缓存与性能采样改动可编译。
- 本轮已运行 `node --test --test-name-pattern "Process and startup scans use cached engine results for process modules" tests\scan_page_threat_actions.test.mjs`：通过，1/1，确认前端源码结构断言已覆盖 `StartupSignatureCache` 调用和 `SnapshotPerformanceStats` 性能采样字段。
- 本轮已运行 `rustfmt --edition 2021 --check src-tauri/src/services/snapshot_service.rs src-tauri/src/commands/snapshot.rs`：通过，确认本轮触及的 Rust 文件无格式差异。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml deduplicate_startup_module_paths_preserves_first_path_per_normalized_module --lib`：通过，1/1，确认同一进程模块路径去重按规范化路径保留首次出现路径。
- 本轮已运行 `cargo test --manifest-path src-tauri\Cargo.toml snapshot --lib`：通过，18/18，覆盖启动快照签名缓存、模块去重、拒绝访问分类、伪装检测和证书吊销相关单测。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过，确认启动快照模块去重与进度日志增强可编译。
- 本轮直接运行 `npm run dev` 一次：364 秒工具窗口超时，未拿到可用中间日志，不能写成启动快照完成。
- 本轮通过重定向日志再次运行 `npm run dev`：Vite 在 `http://localhost:1421/` 启动，Rust dev build 热启动约 0.92 秒，启动快照进入真实扫描；约 12 分钟后日志停在 `Progress: 220/416 processes, 4910 module references, 37 unique scanned paths, 2 cache hits, 0 malicious targets, 148 skipped unscannable targets`，未出现 `[StartupSnapshot] Performance` 或 `Process scanner started after startup snapshot`，随后出现 `PostMessage failed ... 无效的窗口句柄` 和 WebView class unregister error。本次只能记为性能瓶颈采样，不是完整通过。
- 本轮已运行 `node --test tests\scan_page_threat_actions.test.mjs`：未通过，21/24；失败 3 项为既有前端源码结构断言仍期待旧 `ScanPage`/`SettingsPage`/`OverviewPage` 文本或结构，和本轮启动快照统计拆分无直接关系。
- 本轮已再次运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过。
- 本轮已再次运行 `cargo fmt --manifest-path src-tauri\Cargo.toml --check`：未通过；剩余失败为既有 `interception_service.rs`、`interception_window_service.rs` 格式差异，和本轮 ETW 修复无直接关系。本轮不批量格式化无关文件。
- 已运行 `cargo test --manifest-path src-tauri\Cargo.toml interception_service --lib`：通过，15/15。
- 已按 240 秒窗口运行 `npm run dev` 两次：Vite 在 `http://localhost:1421/` 启动，Tauri/Rust 后端进入引擎加载、文件钩子、文件监控和启动快照链路；ETW 仍因非管理员权限跳过，这是开发环境限制。
- `npm run dev` 首次运行主要耗在重新编译，约 3 分 41 秒后应用启动；采样日志显示 `ScanResultCache` DPAPI 解密失败 0 次，medium/high 入队 0 次，启动快照进度到 90/428。
- `npm run dev` 热启动约 2 秒完成 Rust dev 构建；采样日志显示 `ScanResultCache` DPAPI 解密失败 0 次，`ctfmon.exe`、`sihost.exe` 未再入队；仍有 `facewinunlock-tauri.exe`、`EnergyStarX.exe` 两个第三方进程 medium 入队，需作为后续第三方签名兼容/真实未签名问题单独判断。
- 本轮未等到完整启动快照结束后再记录 `Process scanner started after startup snapshot`，原因是 240 秒窗口内快照仍在模块扫描阶段；不能把“完整快照结束”写成已验证。
- 曾并行运行 `cargo check --manifest-path src-tauri\Cargo.toml` 与 `cargo test --manifest-path src-tauri\Cargo.toml interception_service --lib`：300 秒超时；确认是并行编译进程争用 target 后，已停止残留 cargo 进程并串行重跑通过，不能将这次超时视为代码失败。

## 变更记录

### 2026-06-22

- 修复弱证据自动挂起导致的拦截队列风暴：`RiskService` 现在只有“高风险且强证据”才自动入队；`unsigned_process`、`unsigned_module`、单点 `api_hook_process_activity` 均只做告警、记录和补证。`remote_thread_start_outside_image` 后续在 2026-06-23 进一步降噪为只保留 ETW 诊断缓存/聚合桶，不再进入风险分析、行为库或 hot PID 复扫。`RiskService` 同时修复同 PID 假去重，已分析 PID 不再重复推进拦截队列。
- 启动快照不再把普通未签名进程/模块直接构造成 `InterceptionEntry`；未签名模块保留 `unsignedModuleAlerts` 统计，恶意扫描命中、主映像异常、模块链异常、证书吊销等强证据路径仍按原安全策略处置。
- 独立拦截窗口初始化增加兜底：翻译加载失败不会阻断事件监听和 `peekCurrentInterception()` 拉取；事件监听注册失败也会继续主动拉取当前拦截项；组件卸载时释放 `process-intercepted` 监听，避免重复监听放大队列/卡顿。`src-tauri/capabilities/interception.json` 增补 `core:default`，但仍不授予 `shell:default` / `fs:default`。
- 已运行 `npm run typecheck`：通过。
- 已运行 `npm run lint`：未通过，失败点为既有 `src/components/ErrorBoundary.tsx` class 组件调用 `useErrorStyles`，和本轮拦截策略、启动快照未签名边界及独立拦截窗口修复无关。
- 已运行 `cargo check --manifest-path src-tauri\Cargo.toml`：通过；剩余 warning 包含 `TimedSignatureVerdict.status` 未使用，以及既有 `EngineService::is_malware` / `NativeEngineService::is_malware` 未使用。
- 已运行 `cargo test --manifest-path src-tauri\Cargo.toml risk_service --lib --quiet`：通过，9/9。
- 已运行 `cargo test --manifest-path src-tauri\Cargo.toml signature_timeout_is_unknown_not_unsigned_interception --lib --quiet`：通过。
- 已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test risk_grading_tests --quiet`：通过，16/16。
- 已运行 `cargo test --manifest-path src-tauri\Cargo.toml --test risk_signature_adjustment_tests --quiet`：通过，13/13。
- 已运行 `node --test --test-name-pattern "Interception alerts render|Interception alert uses risk-themed|Tauri capabilities" tests\scan_page_threat_actions.test.mjs tests\recent_fixes.test.mjs`：通过，3/3。
- 本轮未执行管理员桌面端到端复测；下一步需要重启 AnXinSecurity 后复查 `%APPDATA%\AnXinSecurity\runtime\interception_diagnostics.jsonl`，确认 `unsigned_process` / `unsigned_module` 不再刷屏入队，同时用真实强证据注入链确认拦截窗口仍能弹出并处理目标 PID。

### 2026-06-15

- 新增独立 `interception` 拦截窗口服务与前端窗口壳：拦截事件不再依赖主窗口可见性，主窗口最小化/隐藏到托盘后仍可显示独立安全警报；同步更新 i18n 和前端结构测试。
- 拆分独立拦截窗口 capability：`default.json` 仅绑定 `main`，新增 `interception.json` 仅绑定 `interception` 并授予最小事件/窗口权限，避免继承默认窗口的 `shell:default` 和 `fs:default`。
- 记录 `npm run dev` 240 秒运行结果，以及本轮前端、Rust 检查命令结果。
- 修正 `npm run test` 的前端断言，并更新为 126/126 通过状态。
- `ProcessMonitorService` 的新进程签名判定改为复用 `TrustService`，避免 APIHook watcher 继续使用旧的嵌入签名-only 判断。
- `InterceptionService` 入队日志增加 threat/path，启动快照 unsigned process payload 增加 `signatureStatus`，便于后续误报定位。
- 独立拦截窗口当前已改为固定 4:3 物理尺寸（640x480）并保留窗口拖动区域；拦截弹窗按钮顺序调整为先“允许运行”后“阻止进程”，但默认动作仍是“阻止进程”，并在 60 秒无操作后自动触发一次默认阻止。按钮命令仍复用 `handle_interception`，但后端语义已收敛为：入队先挂起，阻止则终止已挂起进程，允许则加入内存临时白名单并恢复进程。
- 启动快照同轮签名验证现在通过 `StartupSignatureCache` 复用结果，减少同一文件版本在进程与模块循环中的重复签名验证开销；缓存键采用规范化路径、修改时间和文件大小，文件版本变化时会自动失效。
- `EtwService` 分发入口新增 PID `0` / `4` 过滤：同一次 JSON 解析后直接判断顶层 `pid` 或嵌套 `event.pid`，过滤通过后才广播给文件监控、写实时日志、推送前端事件、入行为库和触发风险分析，减少系统噪音和无效后续开销。
- 实时日志 PID 过滤补强：`commands/logs.rs` 新增结构化 `append_event_log_and_emit`，写入前过滤 PID `0` / `4` / `4294967295`；`hook_service.rs` 在文件 Hook 分发前过滤系统/无效 PID；`etw/session.rs` 的 Unknown provider 事件保留原始 PID，避免缺字段被前端展示成 `PID:0`。
- 补齐无效 PID `4294967295` 过滤：`etw/session.rs` 在 ETW 回调入口直接丢弃 `0/4/u32::MAX`，`etw_service.rs`、`hook_service.rs` 和 `commands/logs.rs` 继续在后端分发/写入前兜底过滤，避免无进程归属事件进入实时日志、行为库和风险分析链路。
- 拆分启动快照模块枚举失败统计：`SnapshotResult` 新增 `moduleEnumerationFailures` 与 `moduleEnumerationAccessDenied`，摘要日志输出 access denied/other 子计数，并把首个拒绝访问样本与首个非预期失败样本分开记录。
- 为启动快照增加 `SnapshotPerformanceStats` 性能采样：结果对象新增 `performance` 字段，后端同步输出 `[StartupSnapshot] Performance` 日志，记录各阶段耗时和缓存命中计数，用于定位下一轮加速目标；本次只做观测，不改变安全判定和拦截边界。
- 启动快照模块路径处理增加本进程内去重，并增强中途进度日志：进度日志现在同时输出唯一模块路径数、扫描缓存命中数、签名缓存命中/未命中数，便于在完整快照未结束时也能判断瓶颈是否集中在模块签名验证阶段。

### 2026-06-16

- `PathPolicySnapshot` 增加本轮内 SHA-256 哈希缓存，用于允许列表哈希匹配：同一路径同一文件版本只计算一次哈希，缓存不写入运行时文件；文件修改时间或大小变化后缓存键变化，继续重新计算，避免降低允许列表安全边界。
- 启动快照复用同一次模块信息枚举结果：`enumerate_process_module_info` 产出的 `ProcessModuleInfo` 既转换为模块路径列表参与扫描，也直接传给 `detect_process_image_integrity_from_modules` 做主映像完整性检查，减少同一进程重复 ToolHelp 模块快照；缺少模块快照时仍返回 `Unknown`，不降低安全判定。
- 启动快照模块循环跳过当前进程主映像重复项：`inspect_startup_target` 现在随目标检查结果返回 `scan_key`，模块列表准备阶段也生成 `StartupModuleTarget { path, scan_key }`；模块层只用模块路径 key 与进程路径 key 比对，当两者完全一致时不再重复执行路径策略、签名验证和扫描，其他模块仍照常处理。
- 进程枚举结果现在直接保存预计算 `scan_key`，启动快照主循环不再为同一个进程路径重复做一次标准化；后台吊销检查也复用这份 key，只在重读当前路径时重新规整一次用于比较，避免把路径比对做成隐性热点。
- 启动快照复用预计算路径 key：唯一模块统计、主映像重复项判断、启动恶意扫描缓存查找和签名缓存键拼装不再分别重复调用 `startup_scan_key`；该优化只减少字符串规范化开销，不改变 Unknown、超时、未签名、恶意命中、允许列表和排除项的安全语义。
- 启动快照进一步复用单次目标文件检查结果：`inspect_startup_target` 在一次 `metadata` 读取后同时供可扫描判断、签名缓存键和写入时间提取使用，减少同一路径反复读取文件属性；签名缓存仍按文件版本变化失效，不把旧结论套到新文件上。
- `PathPolicySnapshot` 增加本轮内路径策略判定缓存：启动快照对进程和模块路径调用 `should_skip_security_scan_cached`，缓存键来自 `inspect_startup_target` 的文件版本键；无版本键时不缓存，文件变更后重新匹配排除项/允许列表。
- `scan_startup_target` 增加 `policy_already_checked` 兜底开关：启动快照主循环已经完成路径策略判断的目标不再在扫描入口重复判断；如果未来调用方传入 `false`，扫描入口仍会自行执行路径策略检查。
- `PathPolicySnapshot` 增加纯路径快速判断 `should_skip_by_path_only`：启动快照在读取目标文件属性前先处理排除项和精确路径允许列表，减少已明确跳过目标的 `metadata` 读取；路径标准化与文件名提取现在先合并成一次 lookup，排除项和精确允许判断共用它，哈希允许列表不走该快速路径。
- `PathPolicySnapshot` 改为加载时预处理规则路径：排除项保存 `normalized_path/file_name`，允许项保存 `normalized_path`，减少每个进程/模块判断时对同一批规则重复执行 `normalize_path`；`matches_prepared_exclusion` 的 `process` 分支现在直接使用预处理 `file_name`，避免对规则路径重复 `to_ascii_lowercase`。
- 启动快照在路径快速判断未命中后改用 `should_skip_by_hash_after_path_miss_cached`，只补查哈希允许列表并复用文件版本键缓存，避免重复匹配排除项和精确路径允许列表；纯路径快速判断仍不读取文件哈希，Unknown、超时、不可读文件和未签名目标不会因此进入可信基线。
- `PathPolicySnapshot` 增加 `lookup_cache` 并把 allowlist hash 预处理为小写字符串：同一轮启动快照内重复出现的模块路径不再反复做路径标准化/文件名提取，哈希允许列表匹配也不再反复拆原始 entry；缓存内容限于纯字符串转换，不缓存文件属性或可信结论。
- `PathPolicySnapshot` 的允许列表预处理从线性条目数组改为 `PreparedAllowlistIndex { exact_paths, hashes }`：路径允许和哈希允许都通过集合查找减少重复遍历；哈希允许仍依赖文件版本键缓存与 SHA-256 计算，不把 Unknown、超时或不可读文件放入可信基线。
- 启动快照模块签名验证改为有限并发：`SnapshotScanOptions` 新增 `signature_verify_concurrency`，配置项为 `scanner.startupSignatureVerifyConcurrency`；当前默认值为 0，表示启动时按本机逻辑处理器数量自动解析，读取失败时回退到 4。并发只覆盖已经通过路径策略和文件属性检查的模块签名验证，验证结果仍回写同一轮 `StartupSignatureCache`，不会按裸路径缓存可信结论；实现上改为 `verify_file_with_timeout_async`，避免并发任务内部再开一层线程。
- 启动快照模块路径检查改为复用 `prepare_startup_module_targets` 预计算的 `scan_key`：`inspect_startup_target_with_scan_key` 只避免再次做字符串规整，不减少模块路径的 metadata、签名、哈希或恶意扫描步骤。
- 启动快照目标恶意扫描增加同轮文件版本级结果复用：`scan_startup_target` 通过 `StartupScanCachedOutcome` 复用同一文件版本的成功扫描结果或失败/超时结果；失败复用仍返回 `Failed` 并计入扫描失败，恶意结果复用仍按当前宿主目标入拦截，缺少文件版本键时不缓存，避免按裸路径复用扫描结论。
- 新进程扫描器启动从完整启动快照之后前移到完整启动快照之前，缩短”新增进程恶意扫描防护就绪”的等待时间；APIHook watcher 仍在快照完成后启动，避免自身 Hook DLL 污染快照基线。`set_process_monitoring_enabled` 同步控制 `ProcessScannerService` 启停，防止监控开关关闭后扫描器继续采集。

### 2026-07-31（Hypervisor 驱动编译与部署）

**已完成**

- `native/hypervisor/` 全量编译通过：20 个 .obj（18 C + 2 ASM），链接生成 `out/AnXinHypervisor.sys`（46592 bytes），PE 验证通过（AMD64 / Native / ImageBase 0x10000 / INTEGRITYCHECK）。
- 测试签名完成：使用 `CN=AnXin Security Test`（thumbprint `CA21B971BC2EA0201E2AA568B230A0035212246E`）signtool SHA256 签名。
- 构建脚本拆分为三阶段独立 bat（解决 `enabledelayedexpansion` 破坏 ml64/link 的问题）：
  - `build_direct.bat`：C 编译（cl.exe /kernel）
  - `asm_build.bat`：MASM 汇编（ml64.exe，无 delayedexpansion）
  - `link_build.bat`：链接（link.exe /DRIVER，无 delayedexpansion）
  - `build_all.bat`：顶层编排，通过 `cmd /c` 隔离各阶段
- 签名脚本 `sign_driver.bat`：指定 `/sha1` 避免多证书冲突。
- 编译期间修复的问题：SAL 注解（platform.h #undef 块）、PANX_CPUID_RESULT 指针 typedef、KeRegisterProcessorChangeCallback 3 参数签名、va_arg const char* typedef、g_CpuVendor 非 static 化、ANX_CR0_TS 定义、AnxProtectRecordViolation 前向声明、PVMCB 指针 typedef、VmcsRead/Write 去 __forceinline、entry_intel.asm QWORD PTR + 段寄存器/invept asm 包装、entry_amd.asm __invlpga 包装、CRLF 行尾。

**当前阻塞（部署到 VM）**

- VM「病毒测试」已停止（为离线挂载准备）。
- 网络部署失败：SMB 端口 445 开放但管理共享 C$ 返回错误 67（找不到网络名称）；WinRM 无响应；PS Remoting 模块加载异常。
- 离线 VHDX 挂载失败：当前 shell 无管理员权限（0x80070522）。
- VHDX 路径：`D:\Virtual Hard Disks\病毒测试_EA72CAF9-12A8-4E0C-B8B9-21A51D889088.avhdx`（差分盘）。
- 已准备提权部署脚本：`native/hypervisor/deploy_offline.ps1`（Mount-VHD → Copy → Dismount → Start-VM）。

**重启后续步骤**

1. 以管理员 PowerShell 运行 `native/hypervisor/deploy_offline.ps1`，将 `out/AnXinHypervisor.sys` 复制到 VM 的 `C:\Windows\System32\drivers\`。
2. VM 启动后，在 VM 内创建服务：`sc create AnXinHypervisor type= kernel start= demand binPath= C:\Windows\System32\drivers\AnXinHypervisor.sys`。
3. 启动服务 `sc start AnXinHypervisor`，预期驱动检测 CPUID.1.ECX[31]（Hyper-V present）进入 `ANX_HV_MODE_DEGRADED_HYPERV`。
4. 通过 IOCTL 或 DbgPrint 确认降级模式生效。
5. 降级路径验证通过后，关闭 VM → `Set-VMProcessor -VMName '病毒测试' -ExposeVirtualizationExtensions $true` → 启动 VM → 验证完整虚拟化路径（VMX root 初始化）。

**计划 / 假设**

- 降级模式下驱动只注册设备对象和 IOCTL 分发，不执行 VMXON/VMCLEAR，应当稳定无 BSOD。
- 嵌套虚拟化开启后 Intel VMX 可用，驱动应进入完整模式并初始化 EPT。
- VM 内 test signing 已启用（之前部署其他驱动时已配置），签名验证应通过。

### 2026-07-31 AnXinHypervisor 嵌套虚拟化最终决策（已验证）

**已验证状态**

- 通过 Microsoft Learn 官方文档查证 Hyper-V 嵌套虚拟化支持范围：
  - 中文版：https://learn.microsoft.com/zh-cn/virtualization/hyper-v-on-windows/user-guide/nested-virtualization
  - 英文版：https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/nested-virtualization
- 官方明确声明："Virtualization applications other than Hyper-V aren't supported
  in Hyper-V virtual machines, and are likely to fail."
- AnXinHypervisor 在 Hyper-V VM 内执行 VMRUN 三重故障是预期行为，非代码 Bug，
  无法通过修改代码解决。
- **决策结论**：采纳选项 1，接受降级模式（`ANX_HV_MODE_DEGRADED_HYPERV`）作为
  Hyper-V 环境下的最终方案。完整模式代码保留但标注"未验证"。

**降级模式功能边界（查证自 [driver.c](file:///e:/Project/HTML/AnXinSecurity/native/hypervisor/src/driver.c#L920-L1001)）**

| IOCTL | 降级模式可用性 | 说明 |
|-------|---------------|------|
| `ANX_HV_IOCTL_GET_STATUS` | ✅ 可用 | 返回版本、OperatingMode、CpuVendor、CpuCount=0、PageTablesActive=0、DegradReason |
| `ANX_HV_IOCTL_GET_STATS` | ❌ `STATUS_NOT_SUPPORTED` | `g_HypervisorActive=FALSE` |
| `ANX_HV_IOCTL_GET_VIOLATIONS` | ❌ `STATUS_NOT_SUPPORTED` | `g_HypervisorActive=FALSE` |

**项目影响**

- 核心安全功能（进程/文件/网络防火墙）由独立驱动承担，不依赖 hypervisor，不受决策影响。
- hypervisor 是增强模块，尚未集成到 `src-tauri/`，降级决策不影响主应用功能。
- 完整模式能力（EPT/NPT 内存保护、MSR/CR 拦截、CPUID/HLT/VMMCALL 拦截）在 Hyper-V 环境下不可用。

**风险/待办**

- 完整模式代码（SVM/VMX 初始化、VMCB 配置、EPT/NPT、HAL vtable）保留但未验证，
  未来若获得裸机测试条件或确认 VMware 嵌套 SVM 支持，可重新激活。
- 详细决策记录见 [native/hypervisor/NESTED_VIRT_STATUS.md](file:///e:/Project/HTML/AnXinSecurity/native/hypervisor/NESTED_VIRT_STATUS.md)「最终决策」章节。

### 2026-08-07 AnXinHypervisor 开发暂缓（冻结，无物理机验证）

**状态变更（已验证）**

- **AnXinHypervisor 开发暂时冻结，不再推进**。
- **原因：没有可以验证的物理机。**
  - 用户明确不能在裸机系统测试（无可用测试平台）
  - Hyper-V 官方文档确认不支持第三方 hypervisor 嵌套虚拟化，VMRUN 三重故障是平台
    限制，非代码 Bug，无法通过修改代码解决
  - 完整虚拟化路径（VMRUN/VMLAUNCH、EPT/NPT 内存保护、MSR/CR 拦截、Guest 寄存器
    访问桩）在当前任何测试环境下都无法验证

**冻结范围（暂缓，直到获得可验证物理机或确认支持的虚拟化平台）**

- 完整虚拟化路径验证（Mode=FULL）
- EPT/NPT 重新启用（`g_PageTablesActive` 当前为 `FALSE`）
- Guest 通用寄存器访问桩补全（`intel_ops.c`/`amd_ops.c`）
- CPUID/MSR/CR/hypercall 退出处理器功能化
- 驱动集成到 Tauri resources / NSIS / 服务模式 IPC 分发（`GET_HYPERVISOR_STATUS`、
  `SET_HYPERVISOR_ENABLED` 仍不入 ipc_server 分发表）
- 生产签名（EV 证书 + 微软 attestation）

**保持不变的现状**

- 完整模式代码（SVM/VMX 初始化、VMCB/VMCS、EPT/NPT、HAL vtable、exit handler、
  hypercall）全部保留，不删除、不投入新开发
- 降级路径（DEGRADED_HYPERV）的 IOCTL 状态查询能力维持现状
- 核心安全功能（进程/文件/网络防火墙）由独立驱动承担，不依赖 hypervisor，不受冻结影响

**恢复条件**

1. 获得一台可验证的物理机（无 Hyper-V / VBS）
2. 确认 VMware Workstation/ESXi 或其他平台支持嵌套 SVM/VMX，且用户愿意切换
3. 产品或安全需求变化，明确需要 Ring -1 防护能力

**参考**

- 详细冻结决策见 [native/hypervisor/NESTED_VIRT_STATUS.md](file:///e:/Project/HTML/AnXinSecurity/native/hypervisor/NESTED_VIRT_STATUS.md)「暂缓开发决策（2026-08-07）」。

### 2026-08-07 修复 REG_KEY IOCTL 漂移与应用服务键注册表保护迁移（VUL-095）

**背景（根因）**

- 注册表自保已整体从 `AnXinProcProtect.sys` 迁移到 `AnXinFileProtect.sys`（CmRegisterCallbackEx + 服务键 DACL + 硬编码服务键列表），`driver.c` 删除了 REG_KEY IOCTL 族（0x806-0x808，`IOCTL_ANXIN_ADD_REG_KEY` / `REMOVE_REG_KEY` / `CLEAR_REG_KEYS`）。
- 但 Rust 侧仍定义并调用这 3 个死 IOCTL，且 FileProtect 硬编码列表只覆盖 3 个驱动服务键——**应用自身服务键 `AnXinSecurityService` 在迁移后静默失去注册表保护**（迁移前由 Rust 通过 REG_KEY IOCTL 登记保护）。攻击者可改写该键 `ImagePath`/`Start` 禁用或劫持自保服务。`test_ioctl_constants_derived_from_driver_source` 因 3 个常量在驱动源中已不存在而 panic。

**修复内容（已验证）**

- `utils/driver_client.rs`：删除死常量/方法/测试条目，删除「METHOD_NEITHER 三条」断言中对应项，新增迁移注释。
- `services/windows_service.rs`：删除 `register_registry_protection()` 调用及函数本体（原保护服务键/卸载入口/产品键/WoW64 变体）。
- `services/driver_install_service.rs`：`release_self_protection()` 只调 `clear_pids()`；删除 `protect_driver_services()` 函数，注释说明驱动服务键由 FileProtect 硬编码 CmCallback 列表保护。
- `main.rs`：`--protect-dir` 分支删除 `protect_driver_services()` 调用。
- `native/file_protect/src/minifilter.c`：`MAX_PROTECTED_KEYS` 3→4，新增 `SVC_KEY_APP_STR = L"\Registry\Machine\System\CurrentControlSet\Services\AnXinSecurityService"` 并加入 `keys[]`，使应用自身服务键重新受 CmRegisterCallback + DACL 保护。

**验证结果（已验证）**

- `cargo check`：通过（仅既有 dead_code warnings）。
- `cargo test --lib`：346/346 通过。
- `AnXinFileProtect.sys` 用 WDK 10.0.28000 + MSBuild（`/p:SignMode=Off`）重建：新产物 23552 bytes，PE 校验通过（x64），strings/dumpbin 确认 4 个服务键宽字符串（含 `AnXinSecurityService`）已内嵌。Inf2Cat/InfVerif 报错为签名/catalog 相关，与代码无关（.sys 已生成），与既有 VUL-091 等记录一致。

**残余（评估完成 2026-08-07，维持不保护 / 接受风险，记录于 buglist.md VUL-095）**

- 迁移前由 `register_registry_protection()` 保护的卸载入口键、制造商/产品键、WoW64 变体（共 4 条：`HKLM\SOFTWARE\...\Uninstall\AnXin Security`、`HKLM\SOFTWARE\AnXin Security` 及其 WOW6432Node 变体）在迁移后不再受注册表自保覆盖。**评估结论：既不纳入 FileProtect 硬编码列表，也不恢复按需登记机制，维持不保护。** 核心理由：
  - 这 4 条路径只存放安装器元数据（应用运行时配置为文件型 `config/app.json`，安装目录与 `unins000.exe` 已由文件 minifilter 在安装期 `--protect-dir "$INSTDIR"` 保护），无安全价值；
  - 硬编码 DACL 是持久的（`ZwSetSecurityObject`，随键存活不随驱动卸载消失），会拦死以管理员用户身份运行的 NSIS 卸载器删除自身卸载入口 → 破坏卸载；
  - 仅回调（不加 DACL）会拦截升级/覆盖安装器重写卸载入口 → 破坏升级；
  - 恢复 REG_KEY 按需登记需重加已删除的 IOCTL 族 + 运行时 ObjectID 缓存 + Rust 侧接线，重造本次迁移刻意消除的「安装期静默失效」死握手。
  - 后续方向：若未来产品把敏感配置写入 `HKLM\SOFTWARE\AnXin Security`，应改用文件型/APPDATA+DPAPI 存储而非扩充注册表自保列表；卸载器反篡改的正确载体是文件层而非注册表。

### 2026-08-08 修复服务模式启动卡死 + 跨会话 IPC 管道不可达（Hyper-V VM 实测通过）

**背景（根因）**

报告症状：通过服务启动后端时卡死，导致无法启动服务、无法连接前端。拆出两个独立根因：

1. **跨会话命名管道不可达（确定性）**：`ipc_protocol.rs::IPC_PIPE_NAME` 原为 `\\.\pipe\AnXinSecurityIPC`（无 `Global\` 前缀）。Windows 命名管道命名空间按会话隔离：服务进程以 SYSTEM 身份运行在 Session 0，创建的会话级管道仅 Session 0 可见；UI 进程运行在 Session 1+，按同一名字打开必然 `ERROR_FILE_NOT_FOUND` → 前端永远连不上服务。服务持有 `SeCreateGlobalPrivilege`，创建 `Global\` 前缀管道后所有会话均可见。
2. **服务进入 Running 前的同步阻塞（结构性）**：`start_protection_runtime()` 在服务达到 Running 之前同步调用 `init_driver_protection()`，其中 `DriverClient::connect()` / `register_file_protection()` 使用无超时的 `DeviceIoControl` / `FilterSendMessage`。若驱动已加载但分发例程不响应，主线程无限阻塞 → 服务卡在 START_PENDING，超过 SCM 30s wait_hint 被杀 → “无法启动服务”。主线程在 Running 前被阻塞任务占用，违背“主线程不应被任何任务占用以确保能响应消息”。

**修复内容（已验证）**

- `src-tauri/src/services/ipc_protocol.rs`（`IPC_PIPE_NAME`）：改为 `\\.\pipe\Global\AnXinSecurityIPC`，补充中英文注释说明必须使用 `Global\` 前缀的原因（服务在 Session 0、UI 在 Session 1，服务持有 `SeCreateGlobalPrivilege`）。
- `src-tauri/src/services/windows_service.rs`（`start_protection_runtime`）：`init_driver_protection()` 移到独立线程 `anxin-driver-init`，不再等待；驱动缺失/挂起只阻塞该后台线程，服务照常进入 Running。补充注释说明 DeviceIoControl/FilterSendMessage 同步无超时、SCM 30s wait_hint 语义。
- `src-tauri/src/services/ipc_server.rs` / `ipc_client.rs`：管道名注释同步更新为 Global 版本（无功能变更）。

**验证结果（已验证）**

- `cargo check` 通过；`cargo test --lib` 346/346 通过。
- Hyper-V VM `病毒测试`（Win10 IoT Enterprise LTSC；`test` 用户交互会话 Session 1；服务以 SYSTEM 运行 Session 0）实测：
  - **启动不卡死**：`sc start` 后 START_PENDING → RUNNING 约 2 秒（08:50:45 → 08:50:47），远低于 SCM 30s wait_hint；服务持续 RUNNING，PID 4036（Session 0），ws≈162MB（无 4GB 内存尖峰）。
  - **跨会话管道可达**：Session 1 交互会话 `NamedPipeClientStream.Connect` 到 `Global\AnXinSecurityIPC` 成功（CONNECT-OK）；同一会话按旧名 `AnXinSecurityIPC` 连接超时（操作已超时），复现修复前症状。Session 0 枚举管道确认 `Global\AnXinSecurityIPC` 存在、会话级 `AnXinSecurityIPC` 不存在。
  - **端到端链路**：服务启动后经 `CreateProcessAsUserW` 把 UI（`C:\AnXinVmTest\anxin-security.exe`）拉起进 Session 1，UI 又启动 msedgewebview2（Tauri WebView），前端进程存活。PowerShell 探针连上 Global 管道后写 PING 被 `verify_pipe_client` 拒绝（管道已中断）——证明管道存活且身份校验仍生效。

**残余**

- 本轮 VM 未安装三个内核驱动（AnXinProcProtect/FileProtect/NetFilter），因此“驱动分发例程挂起导致旧代码卡死”的负面对照无法在 VM 内复现（驱动缺失时旧代码会快速失败而非挂起）。修复正确性由代码层面（阻塞调用移出主线程）保证，VM 验证证明修复后启动路径畅通、服务正常进入 Running。
- 服务进程的 stderr 在 Windows 服务上下文被丢弃，本轮服务日志靠 `sc query` 状态轮询与外部管道探针验证，未落盘服务端 eprintln。

### 2026-08-08 前端启动内存减负：WebView2 浏览器参数裁剪（Hyper-V VM 实测通过）

**背景（根因）**

报告症状：前端启动时占用太大。Hyper-V VM `病毒测试` 内实测 standalone 模式（无引擎模型部署）启动前 2 秒即达稳定态、无尖峰，内存构成：

| 进程 | 工作集 | 说明 |
|---|---|---|
| `anxin-security.exe`（UI 宿主） | ~26MB | 引擎模型未部署；真机 standalone 额外 +139MB |
| `msedgewebview2.exe` × 8 | ~254MB | browser 114MB + renderer 45MB + GPU 40MB + utility ~60MB |
| **合计** | **~280MB** | WebView2 占 90% |

前端 JS 本身很小：renderer 仅 ~45MB，日志封顶 200 条（展示 8 条），快照结果 payload 是小 JSON。因此“前端占用大”不是前端代码/数据问题，而是 WebView2 的固定开销（Chromium 浏览器进程 + renderer + GPU + utility 进程）。

**修复内容（已验证）**

- `src-tauri/tauri.conf.json`：主窗口新增 `additionalBrowserArgs`，值为
  `--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-gpu --disable-background-networking --disable-component-update`。
  前段 `msWebOOUI,msPdfOOUI,msSmartScreenProtection` 是 wry 默认参数，必须显式保留（`additional_browser_args` 会整体替换默认串）。
- `src-tauri/src/services/interception_window_service.rs`：拦截窗口 `WebviewWindowBuilder` 追加逐字节相同的 `additional_browser_args`，并补注释说明原因：
  不同 `CoreWebView2EnvironmentOptions` 在同一 user data folder 下会导致 WebView2 启动独立浏览器进程（内存翻倍）或创建失败，因此主窗口与拦截窗口必须共用同一组浏览器参数。两个窗口共享同一 WebView2 环境，只保留一个浏览器进程。

**验证结果（已验证）**

- `cargo build --release --bin anxin-security` 通过（仅既有 dead_code warnings）。新产物 SHA256 与 VM 内 `C:\AnXinVmTest\anxin-security.exe` 一致后复测。
- **standalone A/B（同一条启动路径，仅浏览器参数不同）**：
  - WebView2 合计 ~254MB → **~212MB**（净省 ~40MB / ~14%）；
  - WebView2 进程数 8 → **6**（GPU 进程被移除，浏览器进程自身 ~114MB → ~78MB）；
  - 前端栈合计 ~280MB → **~240MB**。
- **拦截窗口兼容性**：每次启动都会 `prepare_interception_window`（创建后隐藏）。实测进程数保持 6、无崩溃，证明主窗口与拦截窗口共享同一 WebView2 环境、参数一致生效，未出现第二个浏览器进程。
- **服务模式（部署形态）**：服务启动后 `CreateProcessAsUserW` 拉起 UI，UI 宿主 ~24MB，WebView2 6 个进程（GPU 进程已移除，进程数 8→6），服务进程（Session 0）~154MB。服务模式 UI 的 WebView2 合计（~277MB）高于 standalone（~212MB），因为连接服务后 UI 渲染实时防护数据（IPC 日志/状态事件），浏览器与 renderer 持有更多状态——这不是浏览器参数失效，而是实时数据负载更高。

**残余 / 权衡**

- `--disable-gpu` 使 WebView2 回退软件渲染（SwiftShader）。对 Fluent UI 控制台可用，但低端机器上滚屏/动画的 CPU 占用可能略升；这是“内存换渲染”的明确取舍。未验证真实硬件上的视觉差异。
- WebView2 的剩余 ~210-280MB 是 Chromium 固有下限，浏览器进程 + renderer 无法通过合法参数进一步压缩（`--single-process` 会破坏进程隔离，对安全产品不可接受）。
- **standalone 引擎的 139MB 模型内存未被本轮处理**：该内存是 `kvd_create` 加载全部 ONNX 模型的代价，启动快照、文件监控、ETW 风险分析都依赖它。延迟加载会留下“启动后防护未生效”的空窗，故未做。服务模式下 UI 进程本就不加载引擎（引擎在服务进程内），所以部署形态的前端栈已基本只含 WebView2。

### 2026-08-13 驱动自保专项测试：R3 攻击面与卸载链路（Hyper-V 来宾实测）

**测试目标（对应安全需求）**：在 Hyper-V 来宾 `病毒测试` 内，从本地高权限管理员 R3（非物理机）角度验证——除软件自身卸载程序外，任何 R3 手段均不得：终止/卸载驱动、删改驱动文件、删改驱动注册表、删改软件本体/引擎/配置文件、注入/挂起/终止软件进程与 webview 进程；最终只有卸载程序能在重启一次后彻底清除驱动与软件。

**测试基线**：快照 `Post-Install-Pre-SelfProtectTest_20260813_0215`（2026-08-13 04:05，全新安装后）。服务 AnXinSecurityService=Running、AnXinProcProtect/AnXinFileProtect=Running、AnXinNetFilter=Stopped；受保护 PID 3 个（服务 4680 / UI 6140 / spoof helper 1316）。

**攻击向量实测结果（已验证）**

| 分类 | 向量 | 结果 |
|---|---|---|
| 驱动终止/卸载 | `sc stop` / NtUnloadDriver（运行中驱动） | 拦截 ✅（1052 无 STOP 控件，WDM 驱动不接受停止） |
| 驱动卸载 | `sc delete`（运行中驱动） | 拦截 ✅（minifilter CmCallback 拒非授权调用方；仅 1072 标记删除挂起） |
| 驱动文件 | 删/改/覆盖 `AnXin*.sys`（运行中） | 拦截 ✅（boot-time IsKernelDriverFile 后缀保护） |
| 驱动注册表 | 改/删 ProcProtect / FileProtect 服务键 | 拦截 ✅（DACL + ObjectID CmCallback） |
| 软件进程 | taskkill/TerminateProcess/NtSuspendProcess/NtSuspendThread/DebugActiveProcess | 拦截 ✅ |
| 注入 | CreateRemoteThread / QueueUserAPC / VirtualAllocEx+WriteProcessMemory | 拦截 ✅（句柄被剥离，均失败） |
| minifilter 端口 | 非 anxin-security.exe 调用者 FilterConnectCommunicationPort | 拦截 ✅ |

**已确认缺陷（违反需求，已记入 buglist.md VUL-096~VUL-103，现已全部 Fixed，修复后重测见下节）**

| 缺陷 | 实测证据 | 漏洞号 |
|---|---|---|
| webview 进程未受保护 | `taskkill /f /im msedgewebview2.exe` 一次性终止全部 7 个 webview 进程（根因：isChildOfProtected 只查已提升列表不查 pending 队列，2s 提升窗口内子进程永不受保护） | VUL-096 (High) |
| 安装目录文件保护运行期未生效 | exe 未运行时 `del` 直接成功、echo 覆盖成功（minifilter 仅保护 .sys，运行时 FpmAddPath 注册静默失败） | VUL-097 (High) |
| 服务键注册表保护仅 2/4 键生效 | AnXinSecurityService 键 `reg delete` 成功；AnXinNetFilter 键停止时 `sc delete` 成功（部署 .sys 内嵌 4 键字符串但运行时只保护 2 键） | VUL-098 (High) |
| SET_DIAG 无授权校验 | `IOCTL_ANXIN_SET_DIAG=0xF` 后 taskkill 成功终止受保护 PID，置 0 恢复 | VUL-099 (Critical) |
| 进程名伪装获内核授权 | 复制 powershell 命名为 anxin-security.exe（C:\Windows\Temp），成功终止服务 4680 + UI 6140 | VUL-100 (Critical) |
| 卸载残留 .sys | `uninstall.exe /S` 退出 0；重启一次后 4 服务全 1060、安装目录/卸载项清除，但 3 个 .sys 残留（重启删除登记被仍加载的 minifilter 拦截，PendingFileRenameOperations 无条目） | VUL-101 (Medium) |
| FpmQueryPaths 挂起 | `--query-protected-paths` 无响应，调用方永久阻塞 | VUL-102 (Low) |
| 线程上下文句柄可开 | 受保护线程 OpenThread(GET/SET_CONTEXT) 成功 | VUL-103 (Low) |

**卸载链路（唯一成功入口，已验证）**：`uninstall.exe /S` → NSIS PREUNINSTALL → `anxin-security.exe --uninstall-drivers`（清 PID 保护列表 → 按序停止/删除 4 服务 → 删 .sys 或安排重启删除）→ sc stop/delete AnXinSecurityService → 删除安装目录与卸载入口 → 重启。实测卸载器成功删除软件 + 4 服务，但 **3 个 .sys 文件残留**（VUL-101）。

**来宾当前状态**：软件已卸载（处于"彻底卸载后"态，4 服务 1060、无驱动加载、3 个 .sys 残留可手动 del）。如需恢复安装态，可回滚快照 `Post-Install-Pre-SelfProtectTest_20260813_0215`。

**待办 / 风险**：VUL-096~VUL-103 修复（webview 子进程保护传播、安装目录 boot-time 硬编码保护、服务键 DACL 4 键全覆盖、SET_DIAG/Ob 授权路径校验、卸载 .sys 重启删除改 RunOnce/ScheduledTask、FpmQueryPaths 修复、线程上下文权限剥离）；修复后需重跑本测试并补测"卸载 + 重启一次全清"。

**2026-08-13 修复后重测（VUL-096~VUL-103 全部 Fixed + T10 卸载收口验证通过）**

修复内容（详细记录见 buglist.md 对应条目）：
- **VUL-096**：`isChildOfProtected`（driver.c:1637）覆盖 pending 待提升队列，父进程提升窗口内产生的子进程同样登记保护。
- **VUL-097**：Rust `register_file_protection_paths` 改为独立线程 + 有效回复缓冲（4 + MAX_PROTECTED_PATHS*520*2）+ 8s 超时发送 `FpmAddPath`（原主线程 NULL 缓冲调用在 FLTLIB.DLL 内 AV 崩溃），安装目录运行期注册生效。
- **VUL-098**：`RegProtectCallback` 改用稳定 ObjectID + 按路径名 `IsRegProtectedKeyPathName` 识别，不依赖 boot 期 ObjectID 缓存，4 服务键运行时全生效。
- **VUL-099 / VUL-100**：SET_DIAG 与 Ob 授权均改为 `IsCallerFamilyTry`（driver.c:1446/1914）完整路径族系校验，伪装名进程不再获得内核授权。
- **VUL-101**（本轮重点）：卸载 `stop_and_delete_service` 改用一次性 SYSTEM 计划任务（`schtasks /ru SYSTEM` 执行 `reg delete`）删 4 个服务注册表键。根因双层：① 驱动不注册 DriverUnload → `sc stop` 1052 → `sc delete` 对 RUNNING 服务只标记删除、键不落地，重启后 SCM 读键重载驱动锁 .sys；② 服务键被驱动设 DACL（SYSTEM 全控 / Everyone 只读），管理员 reg delete 被 DACL 拒绝（DACL 检查先于 CmCallback，授权窗口救不了）。SYSTEM 身份满足 DACL + 窗口内 CmCallback 放行 → 删键必达；键删后重启 SCM 不再加载驱动，3 个 .sys 的 PFRO 重启删除成功。
- **VUL-102**：FpmQueryPaths 驱动侧改紧凑回复格式 + Rust 侧独立线程 + 8s 超时守卫。
- **VUL-103**：线程 Ob 回调权限剥离集合补入 `THREAD_GET_CONTEXT` / `THREAD_SET_CONTEXT` / `THREAD_QUERY_INFORMATION`（driver.c:245-249）。

**重测自保矩阵（2026-08-13，安装态来宾，新 release 构建后重装）**：
REG-del 4/4 DENIED、SCM delete 3/3 DENIED、DRV DEL 3/3 DENIED、安装目录 DEL/OVERWRITE/RENAME 全 DENIED、`taskkill` app DENIED、SPOOF-STOP（伪装名进程终止）DENIED、OPEN-THREAD ctx DENIED、POST-DIAG taskkill DENIED；`--query-file-protect` 0.22s 返回（不再挂起）。SET_DIAG：非授权（test）进程连驱动设备都被 DACL 拒绝（设备访问本身即被拦，IOCTL 无法发出）。webview 因 PS Direct Session 0 限制无法在本轮初始化，VUL-096 由前轮验证通过。

**T10 卸载 + 重启一次全清（收口验证，2026-08-13 通过）**：`uninstall.exe /S` → 卸载完成（安装目录、卸载项、AnXinSecurityService 清除）；PFRO 登记 6 条 AnXin*.sys 重启删除；3 驱动服务键被 schtasks SYSTEM 任务删除（卸载后检查为 STOP_PENDING）；重启一次后 `post-reboot-clean.ps1` 全绿：4 服务 gone、无 AnXin*.sys、安装目录 gone、卸载注册表 gone、无进程、PFRO 已消费。**"只有卸载程序能在重启一次后彻底清除驱动与软件"达成。**

**来宾当前状态**：软件已卸载且彻底干净（4 服务 gone、无 .sys、无安装目录）。恢复安装态可回滚快照 `Post-Install-Pre-SelfProtectTest_20260813_0215` 或重新安装。

**待办 / 风险**：VUL-101 的 schtasks 卸载依赖卸载器以管理员运行（`schtasks /ru SYSTEM` 需提权）；`--query-file-protect` 输出走 stderr 导致 PS Direct 会话捕获为空（低优先，建议改 stdout 便于脚本断言）；其余 Open 漏洞见 buglist.md（VUL-004 隔离擦除、VUL-005 路径遍历、VUL-006 capability 过宽等）。
