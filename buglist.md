# AnXinSecurity 安全漏洞清单

> 本文件记录项目中已发现的安全漏洞，需持续更新。
> 最后更新：2026-08-13

---

## 漏洞索引

| 编号 | 严重等级 | 漏洞类型 | 影响模块 | 状态 |
|------|---------|---------|---------|------|
| VUL-001 | Critical | DLL 注入路径未校验 | process_monitor_service | Fixed |
| VUL-002 | Critical | 命名管道无安全描述符 | hook_service | Fixed |
| VUL-003 | High | 签名验证跳过证书吊销检查 | trust_service / snapshot_service | Fixed |
| VUL-004 | High | 隔离区原文件简单删除未安全擦除 | quarantine_service | Open |
| VUL-005 | High | 路径遍历：normalize_path 保留 `..` | path_policy_service | Open |
| VUL-006 | High | Tauri capability 权限过宽 | capabilities/default.json | Open |
| VUL-008 | Medium | 环境变量泄露加密密钥 | quarantine_service | Open |
| VUL-009 | Medium | NativeEngineService 手动实现 Send/Sync | native_engine_service | Open |
| VUL-010 | Medium | 签名缓存可被时间回拨欺骗 | trust_service | Open |
| VUL-011 | Medium | 拦截决策无审计日志 | interception_service | Open |
| VUL-013 | Medium | 错误信息泄露内部路径 | 多个模块 | Open |
| VUL-014 | Low | 进程监控 eprintln 输出路径信息 | process_monitor_service | Open |
| VUL-015 | High | config 中残留测试规则（可被本地滥用冻结任意进程） | config/etw_match_rules.json | Fixed |
| VUL-016 | High | ETW EVENT_RECORD 本地结构体布局错误导致实时注入检测失效 | etw/session / etw_service | Fixed |

| VUL-017 | High | 远程线程入口孤立信号误入自动挂起导致 cmd 控制链假死 | etw_service / risk_service / interception_service | Fixed |
| VUL-018 | High | ETW Image/load 设备路径验签失败导致系统 DLL 被误判为未签名注入模块 | etw_service / trust_service | Fixed |
| VUL-019 | High | ETW Image/load 事后挂起存在短时间执行窗口 | etw_service / interception_service / file_hook / native/driver | Fixed |
| VUL-020 | High | 弱证据自动挂起导致拦截队列风暴和主页卡死 | snapshot_service / risk_service / interception_window | Fixed |
| VUL-021 | High | dev 运行态导致 VM 控制面失效并曾触发 CRITICAL_PROCESS_DIED 蓝屏 | startup / ETW / interception / VM runtime | Fixed |
| VUL-022 | High | ETW 命中事件重复入库导致行为数据库写放大 | etw_service / risk_service / behavior_service | Fixed |
| VUL-023 | High | ETW 重复实时响应和 FileMonitor 同路径重复扫描导致任务/扫描放大 | etw_service / file_monitor_service / risk_service / process_scanner_service | Fixed |
| VUL-024 | Critical | 内核驱动 IOCTL 码与驱动定义完全不符导致驱动防护全链路静默失效 | utils/driver_client / native/driver | Fixed |
| VUL-025 | High | 驱动镜像缺少 FORCE_INTEGRITY 导致 ObRegisterCallbacks 注册被拒 | native/driver/AnXinProcProtect.vcxproj | Fixed |
| VUL-026 | High | 风险研判事件名与转发白名单不符导致服务模式下告警全丢 | windows_service / ipc_bridge_service / risk_service | Fixed |
| VUL-027 | High | 行为监控开关在服务模式下不生效，关闭后仍持续采集 | commands/config / ipc_protocol / windows_service | Fixed |
| VUL-028 | Medium | ETW 运行状态上报恒为真且 IPC 查询分支为死代码 | ipc_server / commands/behavior | Fixed |
| VUL-029 | Medium | 服务进程在无 UI 连接时挂起进程且无人可询问，形成永久冻结 | service_context / interception_service | Fixed |
| VUL-030 | Medium | ETW 时间窗口规则恒不命中，行为链关联为死特性 | etw/rules | Fixed |
| VUL-031 | Critical | 内核驱动把 PCHAR 强转为 PUNICODE_STRING，进程名可控的野指针解引用 | native/driver / native/file_protect | Fixed |
| VUL-032 | High | 微过滤器授权校验在取不到进程路径时 fail-open，任意进程可获授权 | native/file_protect | Fixed |
| VUL-033 | High | 进程保护驱动设备无显式 DACL，任意非特权进程可下发 IOCTL 关闭自保护 | native/driver | Fixed |
| VUL-034 | High | 服务模式下拦截决策全部静默失败，放行的进程永久挂起、阻止的进程仍存活 | ipc_server / ipc_protocol | Fixed |
| VUL-035 | Medium | IPC 控制管道对 Everyone 授予 GENERIC_ALL | ipc_server | Fixed |
| VUL-036 | Low | 服务模式拦截队列除 PID 外字段全为空串 | ipc_server | Fixed |
| VUL-037 | High | Ob 回调对象类型指针层级错误导致句柄保护构建或运行失效 | native/driver | Fixed |
| VUL-038 | High | 仅按可伪造的进程文件名授予内核驱动信任 | native/driver / native/file_protect | Fixed |
| VUL-039 | High | 微过滤器端口消息路径未限定 NUL 导致内核越界访问 | native/file_protect | Fixed |
| VUL-040 | Medium | 防火墙首次启用顺序死锁并产生持久化状态漂移 | firewallStore / firewall command / ipc_server | Fixed |
| VUL-041 | Medium | 进程驱动失败会连带跳过文件保护路径登记 | windows_service | Open |
| VUL-042 | Medium | 手工安装写入旧 minifilter Instances 路径 | driver_install_service | Fixed |
| VUL-043 | High | IOCTL_ANXIN_ADD_PID 缺少调用方授权校验 | native/driver/src/driver.c | Fixed |
| VUL-044 | High | 注册表保护用对象指针比较导致 sc delete 绕过 | native/file_protect/src/minifilter.c | Fixed |
| VUL-045 | Critical | IsPathProtected 前缀匹配与 PortMessage 尾部反斜杠矛盾导致目录下文件保护全失效 | native/file_protect/src/minifilter.c | Fixed |
| VUL-046 | High | 可信目录子串匹配 `\anxinsecurity\` 可被路径构造绕过（VUL-038 修复不完整） | native/driver/src/driver.c / native/file_protect/src/minifilter.c | Fixed |
| VUL-047 | High | RemoveProtectedPath 缺少路径长度校验导致栈缓冲区溢出 | native/file_protect/src/minifilter.c | Fixed |
| VUL-048 | High | 注册表保护未拦截 RegRestoreKey/RegReplaceKey 可整体覆盖服务键 | native/file_protect/src/minifilter.c | Fixed |
| VUL-049 | High | NetFilter 非接管者关闭句柄时清空全部 IRP 队列导致 DoS | native/net_filter/src/driver.c | Fixed |
| VUL-050 | High | file_hook 句柄表全表清空（非 LRU）导致注入链检测绕过 | native/file_hook/src/file_hook_dll.cpp | Fixed |
| VUL-051 | High | file_hook 管道名来自环境变量可被重定向至攻击者管道 | native/file_hook/src/file_hook_dll.cpp | Fixed |
| VUL-052 | High | file_hook 阻断后目标进程可能永久冻结（恢复失败无兜底） | native/file_hook/src/file_hook_dll.cpp | Fixed |
| VUL-053 | Medium | IOCTL_ANXIN_ADD_WINSTA 未调用授权检查 | native/driver/src/driver.c | Open |
| VUL-054 | Medium | AddProtectedPid 缺少 PID 存在性/归属验证，可被 PID 重用利用 | native/driver/src/driver.c | Open |
| VUL-055 | Medium | IMAGE_EVENT_PATH_CHARS=260 截断长路径导致信任决策错误 | native/driver/src/driver.c | Open |
| VUL-056 | Medium | driver.inf 缺少服务注册表键 DACL 保护 | native/driver/driver.inf | Open |
| VUL-057 | Medium | 注册表保护 60 秒宽限期 fail-open | native/file_protect/src/minifilter.c | Open |
| VUL-058 | Medium | FileRenameInformation 仅检查源路径未检查目标路径 | native/file_protect/src/minifilter.c | Open |
| VUL-059 | Medium | FSCTL 拦截列表不全，FSCTL_FILE_LEVEL_TRIM 等可清零文件数据 | native/file_protect/src/minifilter.c | Open |
| VUL-060 | Medium | NetFilter IOCTL 操作未校验调用方是否为接管进程 | native/net_filter/src/driver.c | Open |
| VUL-061 | Medium | NetFilter 进程统计节点无上限可导致非分页池耗尽 | native/net_filter/src/rules.c | Open |
| VUL-062 | Medium | NetFilter SelfPid 可被任意管理员设置为豁免任意进程 | native/net_filter/src/driver.c | Open |
| VUL-063 | Medium | NetFilter DecisionId 顺序递增且无调用方校验可伪造裁决 | native/net_filter/src/pending.c | Open |
| VUL-064 | Medium | file_hook 心跳 ACK 用 "ok" 子串匹配可被误判 | native/file_hook/src/file_hook_dll.cpp | Open |
| VUL-065 | Medium | file_hook 诊断文件无安全描述符且允许并发写入（日志投毒） | native/file_hook/src/file_hook_dll.cpp | Open |
| VUL-066 | Medium | file_hook isProtectedProcessNameW 仅按文件名匹配不验证路径 | native/file_hook/src/file_hook_dll.cpp | Open |
| VUL-067 | Medium | file_hook normalizePathW 对盘符路径不解析 `..` | native/file_hook/src/file_hook_dll.cpp | Open |
| VUL-068 | Medium | file_hook 注入器不验证 DLL 路径合法性（相对路径劫持） | native/file_hook/src/file_hook_injector.cpp | Open |
| VUL-069 | Medium | file_hook 注入器 OpenProcess 不校验目标是否为受保护进程 | native/file_hook/src/file_hook_injector.cpp | Open |
| VUL-070 | Medium | file_hook gInjectionChains O(n²) 剪枝导致 CPU 耗尽 + 刷量驱逐 | native/file_hook/src/file_hook_dll.cpp | Open |
| VUL-071 | Low | IOCTL_ANXIN_QUERY_PIDS 缺少授权校验泄露受保护 PID | native/driver/src/driver.c | Open |
| VUL-072 | Low | DriverEntry 错误清理路径未清理 Thread 通知和 Ob callbacks | native/driver/src/driver.c | Open |
| VUL-073 | Low | ObRegisterCallbacks(Thread) 失败静默继续，线程保护缺失无感知 | native/driver/src/driver.c | Open |
| VUL-074 | Low | Thread 与 WinSta ObCallback 共用 Altitude "325801" 导致冲突 | native/driver/src/driver.c | Open |
| VUL-075 | Low | Debug 构建中 DbgPrint 泄露内核地址和受保护对象指针 | native/driver/src/driver.c / native/file_protect/src/minifilter.c | Open |
| VUL-076 | Low | build_driver.bat 缺少驱动签名步骤 | native/driver/build_driver.bat | Open |
| VUL-077 | Low | IsAnxinProcess 路径分隔符访问潜在越界读（tailChars 下溢） | native/driver/src/driver.c | Open |
| VUL-078 | Low | IsKernelDriverFile 后缀匹配可被误触发保护任意目录同名文件 | native/file_protect/src/minifilter.c | Open |
| VUL-079 | Low | PortConnect 中 g_ClientPort 检查与赋值无锁存在竞态 | native/file_protect/src/minifilter.c | Open |
| VUL-080 | Low | RegProtectCallback IRQL 检查阈值错误（APC_LEVEL 下调用 CmCallbackGetKeyObjectIDEx） | native/file_protect/src/minifilter.c | Open |
| VUL-081 | Low | FpmRemovePath 不加尾部反斜杠与 FpmAddPath 不对称导致路径无法删除 | native/file_protect/src/minifilter.c | Open |
| VUL-082 | Low | NetFilter g_ObjectsAdded 非原子检查存在竞态 | native/net_filter/src/wfp.c | Open |
| VUL-083 | Low | NetFilter IPv6 地址字段未做 NULL 检查可导致蓝屏 | native/net_filter/src/callouts.c | Open |
| VUL-084 | Low | NetFilter PendingCount 检查存在 TOCTOU 竞态 | native/net_filter/src/pending.c | Open |
| VUL-085 | Low | NetFilter 限速路径 BLOCK+DEFER 语义矛盾可能导致数据丢失 | native/net_filter/src/callouts.c | Open |
| VUL-086 | Low | NetFilter 令牌桶补充值在极端配置下可能溢出 | native/net_filter/src/rules.c | Open |
| VUL-087 | Low | file_hook DllMain CreateThread 失败不处理，心跳不启动则 Hook 永久驻留 | native/file_hook/src/file_hook_dll.cpp | Open |
| VUL-088 | Low | file_hook CMakeLists.txt 未启用 CFG 等安全编译选项 | native/file_hook/CMakeLists.txt | Open |
| VUL-089 | Low | reflective_load_real_dll PE 解析无边界检查 | native/file_hook/src/reflective_load_real_dll.cpp | Open |
| VUL-090 | Low | peb_unlink_real_dll PEB 链表操作无并发保护 | native/file_hook/src/peb_unlink_real_dll.cpp | Open |
| VUL-091 | Critical | FileProtect PreWrite 路径在 DISPATCH_LEVEL 调用 ExAcquireFastMutex 导致蓝屏 | native/file_protect/src/minifilter.c | Fixed |
| VUL-092 | High | FileProtect PreWrite 路径在 DISPATCH_LEVEL 调用 SeLocateProcessImageName 导致蓝屏 | native/file_protect/src/minifilter.c | Fixed |
| VUL-093 | Low | NetFilter FwpsPendClassify0 失败后对未挂起分类调用 FwpsCompleteClassify0 | native/net_filter/src/callouts.c | Fixed |
| VUL-094 | Medium | NetFilter 状态修改类 IOCTL 未校验调用方为已接管客户端（BYOVD） | native/net_filter/src/driver.c | Fixed |
| VUL-095 | High | 注册表保护迁移后应用自身服务键静默失去保护，且 Rust 仍调用已删除的 REG_KEY 死 IOCTL | native/file_protect/src/minifilter.c / utils/driver_client.rs / services/windows_service.rs | Fixed |
| VUL-096 | High | WebView2 前端进程未受进程保护（isChildOfProtected 遗漏 pending 队列，2s 提升窗口内子进程永不受保护） | native/driver/src/driver.c | Fixed |
| VUL-097 | High | 安装目录文件保护运行期注册未生效，exe 未运行时可直接删除/覆盖安装目录文件 | native/file_protect/src/minifilter.c / services/windows_service.rs / utils/driver_client.rs | Fixed |
| VUL-098 | High | 驱动服务键注册表保护运行时仅 2/4 键生效，AnXinSecurityService 与 AnXinNetFilter 键可被管理员删除（VUL-095 修复在运行时未生效） | native/file_protect/src/minifilter.c | Fixed |
| VUL-099 | Critical | IOCTL_ANXIN_SET_DIAG 无调用方授权校验，任意管理员可置 DIAG_DISABLE_* 关闭 Ob 进程/线程自保护 | native/driver/src/driver.c | Fixed |
| VUL-100 | Critical | Ob 进程授权仅按 14 字节 ANSI 文件名前缀匹配（无路径校验），名称伪装进程可终止受保护服务与 UI 进程 | native/driver/src/driver.c | Fixed |
| VUL-101 | Medium | 卸载程序重启一次后残留 3 个驱动 .sys 文件（重启删除登记被仍在加载的 minifilter 拦截） | build/nsis-hooks.nsh / services/driver_install_service.rs | Fixed |
| VUL-102 | Low | FpmQueryPaths 诊断查询挂起（FilterSendMessage 无响应），`--query-protected-paths` 死锁 | native/file_protect/src/minifilter.c | Fixed |
| VUL-103 | Low | 受保护进程线程的 OpenThread(THREAD_GET/SET_CONTEXT) 句柄可打开，存在线程劫持面 | native/driver/src/driver.c | Fixed |
| VUL-104 | High | AnXinProcMon 构建缺 /INTEGRITYCHECK，进程/线程回调注册被 CI 拒绝（0xC0000022） | native/proc_monitor/AnXinProcMon.vcxproj | Fixed |
| VUL-105 | Medium | 服务模式 IPC 唯一处理线程被批量扫描阻塞，状态刷新 broken-pipe、开关卡死、扫描无法取消 | services/ipc_server.rs | Fixed |
| VUL-106 | Medium | IPC 客户端身份校验仅按镜像文件名白名单（无安装目录/签名比对），同名伪装进程可通过校验并驱动拦截决策/停服通道；三进程拆分白名单扩至 anxin-tray.exe 后伪装面增大 | services/identity_verification_service.rs | Open |

| VUL-107 | Low | Rust 依赖审计（cargo-audit 2026-08-23）：sqlx 0.7.4 RUSTSEC-2024-0363 为唯一 Windows 可达条目且仅用 SQLite 嵌入式驱动（wire-protocol 误读不可达）；quick-xml×2 与 rsa 经产物符号抽查确认不在 Windows 构建内 | src-tauri/Cargo.lock（crates/anxin-core） | Accepted |
---

## 漏洞详情

### VUL-001: DLL 注入路径未校验

- **严重等级**: Critical
- **漏洞类型**: DLL 注入 / 路径注入
- **影响模块**: `src-tauri/src/services/process_monitor_service.rs`
- **状态**: Fixed
- **位置**: L84-L109 (`start_with_resource_dir`)
- **描述**: `start_with_resource_dir` 接受前端传入的 `injector_x64/x86` 和 `dll_x64/x86` 路径参数。当传入非空路径时，`resolve_process_hook_file` 仅检查文件是否存在（`is_file()`），不验证路径是否在预期目录内。恶意前端或被篡改的 Tauri 事件可指定任意可执行文件作为注入器或 DLL，导致任意代码以应用权限执行。
- **代码片段**:
  ```rust
  // L474-L479: 仅检查文件存在，不校验路径合法性
  fn resolve_process_hook_file(explicit_path: &str, ...) -> Result<PathBuf, String> {
      let trimmed_path = explicit_path.trim();
      if !trimmed_path.is_empty() {
          let explicit = PathBuf::from(trimmed_path);
          if explicit.is_file() {
              return Ok(explicit);  // 直接返回任意路径
          }
      }
  ```
- **攻击向量**: 恶意前端调用 `start_process_watcher` 命令时传入指向恶意 DLL 的路径
- **修复日期**: 2026-06-25
- **修复方式**: `resolve_process_hook_file` 不再接受任意存在的显式路径；非空路径必须与默认可信候选（开发目录 `native/bin/<arch>` 或 Tauri resource 目录内的 `native/bin/<arch>` / `<arch>`）经 `canonicalize` 后完全一致，且文件名必须匹配 `file_hook_injector.exe` 或 `file_hook_detours.dll`。新增 `process_monitor_service_tests` 覆盖可信资源显式路径可用、可信资源缺失时报错、任意外部显式路径被拒绝。

---

### VUL-002: 命名管道无安全描述符

- **严重等级**: Critical
- **漏洞类型**: 未授权访问 / 提权
- **影响模块**: `src-tauri/src/services/hook_service.rs`
- **状态**: Fixed
- **位置**: L488-L499 (`serve_pipe_connection`)
- **描述**: 创建命名管道时传入 `std::ptr::null()` 作为安全属性（`security_attrs`），使用默认 DACL。这意味着同一台机器上的任何进程都可以连接到此命名管道，发送伪造的文件操作事件。攻击者可通过向管道注入恶意 JSON 事件来触发虚假告警、绕过拦截或注入恶意数据到行为分析链路。
- **代码片段**:
  ```rust
  // L488-L499: security_attrs 传入 null
  let pipe_handle = unsafe {
      create_pipe(
          pipe_name_c.as_ptr() as *const u8,
          PIPE_ACCESS_DUPLEX,
          PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT,
          1,
          65536,
          65536,
          0,
          std::ptr::null(),  // 无安全描述符！
      )
  };
  ```
- **修复日期**: 2026-06-25
- **修复方式**: Hook 管道创建时改为显式安全描述符，只授予 `SYSTEM`、`BUILTIN\Administrators` 和当前用户 SID 访问，并在 `CreateNamedPipe` pipe mode 中加入 `PIPE_REJECT_REMOTE_CLIENTS`。连接建立后通过 `GetNamedPipeClientProcessId` 获取真实客户端 PID，事件 payload 中的 `pid` 必须与客户端 PID 一致才会进入日志、行为库、风险分析和拦截链路；不一致或无法确认客户端 PID 的事件会写入 `interception_diagnostics.jsonl` 后丢弃。新增 `hook_service_tests` 覆盖 PID 防伪判断。

---

### VUL-003: 签名验证跳过证书吊销检查

- **严重等级**: High
- **漏洞类型**: 证书验证绕过
- **影响模块**: `src-tauri/src/services/trust_service.rs`, `src-tauri/src/services/process_monitor_service.rs`
- **位置**: trust_service.rs L514-L519; process_monitor_service.rs L737
- **描述**: 默认签名验证使用 `WTD_REVOKE_NONE`（不检查证书吊销），且 `WTD_CACHE_ONLY_URL_RETRIEVAL` 标志阻止网络查询。这意味着已吊销的代码签名证书签发的恶意文件仍会通过签名验证，被标记为"已签名"并跳过安全扫描。进程监控的 `verify_file_signed` 同样使用 `WTD_REVOKE_NONE`。
- **代码片段**:
  ```rust
  // trust_service.rs L514-L519
  revocation_checks: if check_revocation {
      WTD_REVOKE_WHOLECHAIN
  } else {
      WTD_REVOKE_NONE  // 默认不检查吊销
  },
  // ...
  prov_flags: if check_revocation {
      WTD_REVOCATION_CHECK_CHAIN
  } else {
      WTD_CACHE_ONLY_URL_RETRIEVAL  // 仅缓存，不联网
  },

  // process_monitor_service.rs L737
  revocation_checks: WTD_REVOKE_NONE,  // 进程监控也不检查吊销
  ```
- **修复日期**: 2026-07
- **修复方式**: `trust_service.rs` 新增 `verify_file_with_revocation()` 公开方法，启用 `WTD_REVOKE_WHOLECHAIN` + `WTD_REVOCATION_CHECK_CHAIN` 进行完整链吊销检查；`snapshot_service.rs` 在启动快照深度检查阶段调用该方法；缓存键通过 `|revocation=chain` / `|revocation=none` 后缀隔离，防止吊销结果污染快速路径；单元测试 `verify_file_with_revocation_entrypoint_exists_and_isolated_from_default` 锁定隔离行为。进程监控保留快速路径（`verify_file()`）是性能设计决策，深度吊销检查由后台快照承担。

---

### VUL-004: 隔离区原文件简单删除未安全擦除

- **严重等级**: High
- **漏洞类型**: 数据残留 / 不安全删除
- **影响模块**: `src-tauri/src/services/quarantine_service.rs`
- **位置**: L249-L251 (`isolate_file`)
- **描述**: 隔离文件时，原文件仅使用 `fs::remove_file` 简单删除，未执行安全擦除（覆写后删除）。恶意文件内容仍可通过磁盘恢复工具恢复。而 `delete_quarantine` 方法对隔离区文件执行了三遍覆写，但 `isolate_file` 对原文件的处理与此安全标准不一致。
- **代码片段**:
  ```rust
  // L249-L251: 仅简单删除，注释也承认了这个问题
  // 安全删除原文件（简单删除，生产环境应多次覆写）
  fs::remove_file(&original_path)
      .map_err(|e| format!("Failed to remove original file: {}", e))?;
  ```

---

### VUL-005: 路径遍历：normalize_path 保留 `..`

- **严重等级**: High
- **漏洞类型**: 路径遍历
- **影响模块**: `src-tauri/src/services/path_policy_service.rs`
- **位置**: L303-L325 (`normalize_path`)
- **描述**: `normalize_path` 函数仅做大小写转换和斜杠统一，不解析 `..` 路径组件。测试用例也明确保留了 `..\..\test.exe` 这样的相对路径。攻击者可通过构造包含 `..` 的路径绕过排除项和允许列表的匹配逻辑。例如，排除 `C:\Safe\Folder` 时，路径 `C:\Safe\Folder\..\..\Windows\System32\evil.exe` 规范化后仍包含 `..`，不会匹配排除项前缀。
- **代码片段**:
  ```rust
  // L303-L325: 不解析 .. 路径组件
  fn normalize_path(path: &str) -> String {
      let mut normalized: String = path.trim().chars().map(|ch| {
          if ch == '/' { '\\' } else { ch.to_ascii_lowercase() }
      }).collect();
      // ... 仅去除前缀和尾部斜杠，不解析 ..
  }

  // 测试用例明确保留 .. 路径
  // L571: assert_eq!(normalize_path(r"..\..\test.exe"), r"..\..\test.exe");
  ```

---

### VUL-006: Tauri capability 权限过宽

- **严重等级**: High
- **漏洞类型**: 过度权限授予
- **影响模块**: `src-tauri/capabilities/default.json`
- **位置**: L13-L16
- **描述**: 默认 capability 配置授予了 `shell:default` 和 `fs:default` 权限。`shell:default` 允许前端执行 shell 命令，`fs:default` 允许前端访问文件系统。对于安全防护应用，这些权限过于宽泛。如果前端存在 XSS 漏洞或被恶意代码注入，攻击者可直接执行系统命令或读写任意文件。
- **代码片段**:
  ```json
  {
    "permissions": [
      "core:default",
      "core:window:default",
      "core:window:allow-minimize",
      "core:window:allow-toggle-maximize",
      "core:window:allow-hide",
      "core:window:allow-show",
      "core:window:allow-is-maximized",
      "dialog:default",
      "shell:default",   // 过宽：允许 shell 命令执行
      "fs:default"       // 过宽：允许文件系统访问
    ]
  }
  ```

---

### VUL-008: 环境变量泄露加密密钥

- **严重等级**: Medium
- **漏洞类型**: 密钥泄露
- **影响模块**: `src-tauri/src/services/quarantine_service.rs`
- **位置**: L146-L163 (`get_encryption_key`)
- **描述**: 隔离区加密密钥可通过环境变量 `ANXIN_SECURITY_QUARANTINE_KEY` 传入。环境变量对同一用户会话中的所有进程可见，且可能被日志系统、崩溃报告或子进程继承泄露。此外，环境变量中的密钥以明文 hex 字符串形式存在，不提供 DPAPI 保护。
- **代码片段**:
  ```rust
  // L147: 从环境变量读取明文密钥
  if let Ok(hex_key) = std::env::var("ANXIN_SECURITY_QUARANTINE_KEY") {
      if hex_key.len() == 32 {
          // 直接解析为密钥，无额外保护
      }
  }
  ```

---

### VUL-009: NativeEngineService 手动实现 Send/Sync

- **严重等级**: Medium
- **漏洞类型**: 数据竞争 / 未定义行为
- **影响模块**: `src-tauri/src/services/native_engine_service.rs`
- **位置**: L70-L71
- **描述**: `NativeEngineService` 包含原始指针 `Mutex<*mut KvdHandle>` 并手动 `unsafe impl Send for NativeEngineService` 和 `unsafe impl Sync for NativeEngineService`。虽然 `Mutex` 提供了外层同步，但 `kvd_scan_path` 和 `kvd_scan_bytes` 通过 FFI 传递原始指针给 C DLL，如果 C DLL 内部不保证线程安全，多个并发扫描请求可能导致数据竞争。
- **代码片段**:
  ```rust
  // L70-L71
  unsafe impl Send for NativeEngineService {}
  unsafe impl Sync for NativeEngineService {}
  ```

---

### VUL-010: 签名缓存可被时间回拨欺骗

- **严重等级**: Medium
- **漏洞类型**: 缓存投毒
- **影响模块**: `src-tauri/src/services/trust_service.rs`
- **位置**: L234-L252 (`verify_file_with_revocation_mode`)
- **描述**: 签名验证缓存使用 `monotonic_ms()`（基于 `Instant::now().elapsed()`）计算 TTL。但 `Instant` 在某些系统上可能不是真正的单调时钟（如虚拟化环境），且缓存键仅包含路径和写入时间。如果攻击者能修改文件写入时间（通过 SetFileTime API）并回拨系统时间，可使缓存条目被认为仍然有效，从而跳过对已篡改文件的重新验证。
- **代码片段**:
  ```rust
  // L239-L241: 缓存新鲜度判断
  let fresh = entry.write_time == write_time
      && now_ms >= entry.cached_at_ms
      && (now_ms - entry.cached_at_ms) <= cache.ttl_ms;
  ```

---

### VUL-011: 拦截决策无审计日志

- **严重等级**: Medium
- **漏洞类型**: 审计缺失
- **影响模块**: `src-tauri/src/services/interception_service.rs`
- **位置**: L160-L172 (`mark_decision`)
- **描述**: 拦截决策（放行/阻止）仅使用 `eprintln!` 输出到 stderr，不写入持久化审计日志。`clear_all` 方法可一次性清除所有决策记录，且无审计追踪。在安全事件回溯时，无法确认哪个用户在何时对哪个进程做了什么决策。
- **代码片段**:
  ```rust
  // L161-L163: 仅 eprintln，无持久化审计
  pub fn mark_decision(&self, pid: u32, decision: InterceptionDecision) {
      let mut decisions = self.decisions.lock().unwrap_or_else(|e| e.into_inner());
      decisions.insert(pid, decision);
      eprintln!("[InterceptionService] PID {} decision: {:?}", pid, decision);
  }
  ```

---

### VUL-013: 错误信息泄露内部路径

- **严重等级**: Medium
- **漏洞类型**: 信息泄露
- **影响模块**: 多个模块
- **位置**: `process_monitor_service.rs` L563-L566; `quarantine_service.rs` 多处; `native_engine_service.rs` L91-L94
- **描述**: 多个错误消息直接包含完整文件路径、候选路径列表和内部目录结构。例如 `format_missing_process_hook_file_error` 会暴露 APIHook 注入器和 DLL 的所有候选路径，`NativeEngineService::new` 的错误消息暴露 DLL 路径和模型文件路径。这些信息可帮助攻击者了解应用内部结构和文件布局。
- **代码片段**:
  ```rust
  // process_monitor_service.rs L563-L566
  format!(
      "Missing APIHook {} file '{}'. Checked paths: {}",
      role, file_name, checked_paths  // 泄露所有候选路径
  )

  // native_engine_service.rs L91
  Err(format!("DLL path does not exist: {:?}", dll_path))  // 泄露 DLL 路径
  ```

---

### VUL-014: 进程监控 eprintln 输出路径信息

- **严重等级**: Low
- **漏洞类型**: 信息泄露
- **影响模块**: `src-tauri/src/services/process_monitor_service.rs`
- **位置**: L168-L170
- **描述**: 进程监控的 watcher 线程使用 `eprintln!` 输出被跳过的进程路径信息。在调试构建中，这些输出可能被其他进程捕获。虽然仅影响 stderr，但在安全产品中应避免将用户文件路径写入标准错误流。
- **代码片段**:
  ```rust
  // L168-L170
  eprintln!(
      "[ProcessMonitor] Skipped by exclusions or allowlist: {}",
      image_path  // 输出完整路径到 stderr
  );
  ```

---

### VUL-015: config 中残留测试规则

- **严重等级**: Low → **High**（2026-07-26 重新定级）
- **漏洞类型**: 配置安全 / 本地拒绝服务
- **影响模块**: `config/etw_match_rules.json`
- **位置**: L23-L35（旧版本）
- **状态**: Fixed
- **描述**: ETW 匹配规则配置文件中包含测试规则，这些规则可能在生产环境中被意外启用，导致误报或规则引擎性能下降。测试规则应与生产规则分离，或通过明确的启用/禁用标志控制。
- **重新定级理由**: 原定级 Low 低估了实际影响。`test_rule_trigger` 的 `severity: 5` 经 `normalize_rule_severity` ×20 得 100 分，在 `risk_service.rs` 中判为 `high` 并触发 `InterceptionService::enqueue`，而 enqueue 会先 `NtSuspendProcess` 挂起目标进程。其匹配条件是**公开可知的固定文件名** `anxin_rule_test_trigger.bin`，等于给本机任意低权限程序留下一个可控的"冻结任意进程"开关。`calc_probe_payload_image_load` 同理：虽写 `recommendAction: alert`，但当时该字段完全不参与决策，severity 4（80 分）一样会挂起宿主进程。
- **攻击向量**: 本地任意程序重命名一个名为 `anxin_rule_test_trigger.bin` 的文件，即可让自身或诱导的目标进程被安全软件挂起，形成本地 DoS。
- **修复日期**: 2026-07-26
- **修复方式**:
  1. 生产配置 `config/etw_match_rules.json` 删除 `calc_probe_payload_image_load` 与 `test_rule_trigger`，两条规则迁至 `config/etw_match_rules.test.json`；后者不在 `tauri.conf.json` 的 `bundle.resources` 中，不会随安装包分发。
  2. 新增 `production_config_contains_no_test_rules` 与 `production_rules_do_not_recommend_blocking` 两个测试（`src-tauri/tests/etw_rules_engine_tests.rs`），前者禁止测试规则回流生产配置，后者禁止任何生产规则的 `recommendAction=block` 或 `severity > 3`。
  3. 配套修复 `should_auto_intercept_event`（`src-tauri/src/services/risk_service.rs`），要求 `recommendAction == "block"` 才允许自动挂起，切断"severity 隐式驱动拦截"这条根因路径。

---

---

### VUL-016: ETW 字段解析不完整导致实时注入检测失效

- **严重等级**: High
- **漏洞类型**: 安全检测绕过 / 实时拦截失效
- **影响模块**: `src-tauri/src/services/etw/session.rs`, `src-tauri/src/services/etw/parser.rs`, `src-tauri/src/services/etw_service.rs`
- **位置**: `EventRecord` 本地 FFI 镜像、`etw_event_record_callback_inner`, `parse_event_record`, `apply_image_load_injection_detection`, `apply_remote_thread_start_detection`
- **状态**: Fixed
- **描述**: 2026-06-18 先后读取 `%APPDATA%\AnXinSecurity\runtime\etw_diagnostics_dump_20260617_180506_230.json` 和附件新 schema JSON 后确认，ETW 实时链路能收到 `Image/load`、`Image/unload`、`Thread/start`、`Process/start` 和 `Network` 事件，但关键字段为空，且新诊断字段显示所有事件 `rawUserDataLength=0`。进一步核对 Windows `EVENT_RECORD` 绑定发现，本地 `EventRecord` 把 `BufferContext` 错写成 `[u32; 4]`，而真实 `ETW_BUFFER_CONTEXT` 只有 4 字节，导致后续 `UserDataLength/UserData` 读取偏移错误。
- **攻击向量**: 注入链路触发短生命周期线程或镜像加载事件时，ETW 只产生 provider/id/opcode/PID/TID 而关键 payload 字段被错误读成空，规则无法命中，后续只能依赖较慢的事后巡检。
- **修复日期**: 2026-06-18
- **修复方式**: 将本地 `EventRecord.buffer_context` 改为 4 字节 `EtwBufferContext`，并新增 `local_event_record_layout_matches_windows_binding` 单测，断言本地 `EtwBufferContext/EventHeader/EventRecord` 的 size/alignment 与 `windows` crate 绑定一致；保留 `rawUserDataLength/rawUserDataPreview` 现场诊断字段用于后续实采验证。




---

### VUL-017: 远程线程入口孤立信号误入自动挂起导致 cmd 控制链假死

- **严重等级**: High
- **漏洞类型**: 误伤 / 自动挂起策略过强
- **影响模块**: `src-tauri/src/services/etw_service.rs`, `src-tauri/src/services/risk_service.rs`, `src-tauri/src/services/interception_service.rs`, `src-tauri/src/services/process_control_service.rs`
- **位置**: `remote_thread_start_outside_image` 规则分发、`RiskService::analyze_event` 的自动拦截判断、`InterceptionService::enqueue` 的挂起入口
- **状态**: Fixed
- **描述**: 远程线程入口不在已加载镜像内只是“高敏感度异常信号”，不应单独作为自动挂起依据。现场已经观察到当目标是 `cmd.exe` 或其承载的控制链时，自动挂起会把 AnXinSecurity 自己的启动/控制链一起冻结，造成系统假死。后续 VM 日志又确认，即使不打印该信号，它如果仍唤醒 hot PID 复扫、行为库写入和风险分析，也会造成进程扫描与 SQLite 写入风暴。
- **攻击向量**: 线程入口地址暂时解析到镜像外或解析不到时，被误当作可自动拦截证据，导致 shell / 控制台 / 启动链误挂起。
- **修复日期**: 2026-06-23
- **修复方式**: 已将 `remote_thread_start_outside_image` 从直接挂起和 hot PID 补证规则中移除；它仍保留在 ETW 诊断缓存/聚合桶中用于现场取证，但不再进入前端实时推送、行为库写入、风险分析或 `ProcessScanner` 热复扫。`trusted_process_unsigned_image_load` 仍保留为强证据直接拦截和后置补证。
- **验证**: 已通过 `cargo test --manifest-path src-tauri\Cargo.toml fanout --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml realtime_rule_policy --lib --quiet` 和本地 `cargo check`。2026-06-23 的 VM 运行样本 `logs/vm-direct/responses/0008-wait-dev-etw-summary.json` 显示 ETW 仍能采集事件，且日志尾部未再出现 `remote_thread_start_outside_image` hot PID、FileMonitor lag、行为库写入错误、内存分配失败或 `STATUS_STACK_BUFFER_OVERRUN`；后续 `0009` 复采卡在 PowerShell Direct，因此该验证只能说明本轮样本未复现风暴，不能替代长时间稳定性测试。

---

### VUL-018: ETW Image/load 设备路径验签失败导致系统 DLL 被误判为未签名注入模块

- **严重等级**: High
- **漏洞类型**: 误报 / 自动拦截策略误判
- **影响模块**: `src-tauri/src/services/etw_service.rs`, `src-tauri/src/services/trust_service.rs`
- **位置**: `apply_image_load_injection_detection`, `TrustService::verify_file`
- **状态**: Fixed
- **描述**: 2026-06-18 读取 `%APPDATA%\AnXinSecurity\runtime\etw_diagnostics_dump_20260618_052717_844.json` 后确认，`trusted_process_unsigned_image_load` 的 36 次命中主要来自 `svchost.exe` 加载 `\Device\HarddiskVolume4\Windows\System32\dsreg.dll`、`netapi32.dll`、`DiagnosticDataSettings.dll` 等正常系统 DLL。ETW `Image/load` 事件给出的是内核设备路径，未先转换为 `C:\...` 形式时，签名验证无法稳定打开目标文件；旧逻辑又把验签失败等同于“未签名”，导致启动任意系统进程都可能被误报为注入。
- **攻击向量**: 正常系统进程加载系统 DLL 时触发 `Image/load`，路径不可验证被当作不可信模块，进而把可信宿主进程推入高风险拦截队列，造成误拦截和用户判断偏移。
- **修复日期**: 2026-06-18
- **修复方式**: 在 ETW 镜像加载检测前新增 `\Device\HarddiskVolume...` 到盘符路径的转换；路径不可验证、目标不是实际文件或签名检查失败时只保守跳过，不再升级成 `trusted_process_unsigned_image_load`。新增 `etw_image_path_*` 单测，并通过 `cargo check --manifest-path src-tauri\Cargo.toml`、`cargo test --manifest-path src-tauri\Cargo.toml etw_image_path --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml etw --lib --quiet`。

---

### VUL-019: ETW Image/load 事后挂起存在短时间执行窗口

- **严重等级**: High
- **漏洞类型**: 实时拦截时间窗 / 防护绕过
- **影响模块**: `src-tauri/src/services/etw_service.rs`, `src-tauri/src/services/interception_service.rs`, `native/file_hook`
- **位置**: `apply_image_load_injection_detection`, `direct_intercept_realtime_injection_event`, `InterceptionService::enqueue`
- **状态**: Fixed
- **描述**: `Image/load` ETW 事件属于镜像已经加载后的通知。即使 `trusted_process_unsigned_image_load` 能够正确命中，目标 DLL 的 `DllMain` 或远程线程入口仍可能在 AnXinSecurity 完成验签、风险升级和 `NtSuspendProcess` 前已经执行。现场表现为”能告警/能挂起，但短生命周期 payload 有概率已经完成动作”。
- **攻击向量**: 注入载荷在 DLL attach 或远程线程入口中执行极短动作，然后迅速返回或自卸载；ETW 事件到达后再挂起宿主进程时，关键行为已经发生。
- **修复日期**: 2026-07-28（内核层）；2026-06-19 / 2026-06-25（用户态层）
- **修复方式**: 用户态层：2026-06-19 优化 `InterceptionService::enqueue` 先挂起再查询；2026-06-25 APIHook 源头链路检测/阻断（`OpenProcess/VirtualAllocEx/WriteProcessMemory/CreateRemoteThread` 强链路先挂起目标再阻断），Hook 管道安全描述符收紧，`NtCreateThreadEx` Hook。内核层（2026-07-28）：`native/driver/src/driver.c` 新增 `PsSetLoadImageNotifyRoutine(LoadImageNotifyCallback)` 回调，在映像映射到受保护进程地址空间时（代码执行前）触发，检查映像路径是否包含受信任安装目录（`\anxinsecurity\`），不受信任的加载事件写入 32 槽环形缓冲区，用户态服务通过 `IOCTL_ANXIN_QUERY_IMAGE_EVENTS`（0x809）查询并排空。此回调是通知型的（notify-only），阻止能力由用户态服务决定。该回调比 ETW `Image/load` 更早触发，关闭了”加载后、ETW 上报前”的执行窗口。
- **验证**: 2026-07-28 VM 部署验证：ProcProtect.sys 46056 bytes（含 VUL-019 代码），三个驱动全部 RUNNING。

---

### VUL-020: 弱证据自动挂起导致拦截队列风暴和主页卡死

- **严重等级**: High
- **漏洞类型**: 误伤 / 拒绝服务 / 自动挂起策略过强
- **影响模块**: `src-tauri/src/services/snapshot_service.rs`, `src-tauri/src/services/risk_service.rs`, `src/components/InterceptionWindowApp.tsx`, `src-tauri/capabilities/interception.json`
- **位置**: 启动快照未签名进程/模块入队、`RiskService::analyze_event` 的自动拦截判断、独立拦截窗口初始化链路
- **状态**: Fixed
- **描述**: 现场 `%APPDATA%\AnXinSecurity\runtime\interception_diagnostics.jsonl` 显示，普通未签名进程和模块（如开发工具、WebView、浏览器扩展宿主）会以 `unsigned_process` / `unsigned_module` 等弱证据进入自动挂起队列。队列被弱证据刷满后，独立拦截窗口长时间停在低优先级条目，主界面相关进程也可能被挂起，表现为“拦截窗口不显示、主页卡死不能动”。普通未签名只说明“身份还没确认”，不能单独等同于恶意行为。
- **攻击向量**: 本地正常软件或攻击者批量制造未签名/签名不可确认进程，使安全产品持续暂停正常进程和自身依赖链，形成可被本地触发的防护拒绝服务。
- **修复日期**: 2026-06-22
- **修复方式**: 将自动挂起收敛为“高风险且强证据”才触发：`unsigned_process`、`unsigned_module`、单点 `api_hook_process_activity` 和 `remote_thread_start_outside_image` 均改为记录/告警/补证，不再自动挂起；启动快照中的普通未签名进程和模块不再创建拦截项，模块只增加 `unsignedModuleAlerts`。`RiskService` 同时修复同 PID 假去重，已分析 PID 不再重复入队；独立拦截窗口翻译加载或事件监听失败时仍会拉取当前拦截项，并在卸载时释放监听；`interception` capability 增补 `core:default`，但仍不授予 `shell:default` / `fs:default`。
- **验证**: 已通过相关 Rust 单测、`cargo check`、`npm run typecheck` 和独立拦截窗口结构测试。2026-06-23 的 VM 运行样本 `logs/vm-direct/responses/0008-wait-dev-etw-summary.json` 未再观察到旧的 ETW hot PID / FileMonitor lag / 行为库写入风暴和崩溃信号；但尚未完成管理员桌面真实注入与弹窗端到端复测，后续仍需结合 `interception_diagnostics.jsonl` 复核队列是否不再被弱证据刷屏。

---

### VUL-021: dev 运行态导致 VM 控制面失效并曾触发 CRITICAL_PROCESS_DIED 蓝屏

- **严重等级**: High
- **漏洞类型**: 本地拒绝服务 / 系统稳定性风险
- **影响模块**: `scripts/vm-unattended-guest-startup.ps1`, `src-tauri/src/services/etw_service.rs`, `src-tauri/src/services/interception_service.rs`, ETW 运行态、进程控制与拦截链路、VM 测试运行环境
- **位置**: VM 启动 `npm run dev` 后的真实运行态；ETW `trusted_process_unsigned_image_load` 对 PowerShell Direct 相关 `powershell.exe` 的判定与自动拦截链路
- **状态**: Fixed
- **描述**: 2026-06-23 VM 在无人值守启动脚本拉起 `npm run dev` 后发生蓝屏并自动重启。来宾事件日志记录 `BugCheck 0x000000ef`，即 `CRITICAL_PROCESS_DIED`，时间为 2026-06-23 20:36:02；生成 `C:\Windows\Minidump\062326-5421-01.dmp`（约 690KB）和 `C:\Windows\MEMORY.DMP`（约 552MB）。2026-06-23 23:26 的受控 dev 烟测未拿到新的 BugCheck，但启动 `npm run dev` 后 PowerShell Direct / host poller 控制面连续超时。2026-06-24 01:59 在 VM 增配到 8 vCPU 后再次执行带 watchdog 的 bounded dev 烟测，仍复现控制面失效：`resume-start-bounded-dev-20260624-0200` 成功启动 `node/cargo` 和 `anxin-security.exe`，host poller 在 01:59 后停止取得新摘要，`poll-summary-20260624-015954-0008`、`0009`、`0010` 均因 guest script 超时失败，后续 `resume-heartbeat-after-dev-timeout-20260624-0212` 也 60 秒超时。宿主 Hyper-V 状态仍显示 VM `Running/正常运行` 且 IP 为 `172.28.88.10`，强制重启后 Direct 恢复，最近 3 小时没有新的 BugCheck，只有本轮强制重启造成的 Kernel-Power 41。dev 日志与 `interception_diagnostics.jsonl` 显示 AnXinSecurity 将多个 PowerShell Direct 相关 `powershell.exe` PID（如 1324、2960、7956）以 `trusted_process_unsigned_image_load`、`mode=suspend-before-enqueue` 推入拦截队列并展示拦截窗口，Direct 超时与该自动拦截高度相关。
- **攻击向量**: 本地触发安全产品运行态后，如果监控、拦截或进程控制链路影响关键系统进程，可能造成整机蓝屏级拒绝服务。当前仅在低资源 Hyper-V 测试 VM 中复现，不能外推为生产必现，但必须按高风险稳定性问题跟踪。
- **缓解状态**: 已将 `scripts/vm-unattended-guest-startup.ps1` 改为默认只启动 sampler，不再自动拉起 `npm run dev`；采样器默认 `-LocalOnly` 写入 VM 本地 `C:\ProgramData\AnXinSecurity\vm-unattended\latest-summary.json`，由宿主 `vm-unattended-host-poller.ps1` 通过提升 worker 拉取，避免 guest->host HTTP POST 超时阻塞。2026-06-24 已加入代码层缓解：`trusted_process_unsigned_image_load` 命中 Windows PowerShell / PowerShell Direct 控制链进程时，仍保留 ETW 诊断、前端风险事件和后置证据采集，但跳过 ETW 直拦截与 `RiskService` 自动入队挂起；控制链判定必须同时满足进程名和 Windows/PowerShell 可信安装路径，`C:\Temp\powershell.exe` 这类假冒路径不会被豁免。2026-06-28 VM 完整软件调试又发现两处残留控制面干扰：一是控制链事件虽跳过实时预拦截，但仍触发 `ProcessScanner` hot PID 后置复扫；二是启动快照对当前 AnXinSecurity dev 启动父链 `rustup.exe/cargo.exe` 的 image integrity alert 会进入拦截队列并尝试挂起，虽被 `process_control_service` 保护拒绝，但仍制造错误日志和误导性 `paused=1` 统计。当前已进一步收敛：Windows 控制链事件保留诊断但跳过 hot PID 复扫；`InterceptionService` 在调用挂起前直接拒绝当前进程父/祖先控制链入队；映像完整性拦截函数返回真实入队结果，启动快照只在实际入队时累加 `paused`。2026-06-29 进行 46 分钟长稳验收后，`npm.cmd run dev` 在 VM `病毒测试` 内持续运行至 `2026-06-29 00:11:18`，期间未再出现新的蓝屏、控制面失效、`Failed to suspend PID`、hot PID 误挂起或 panic，说明本轮误处置链路已收敛到可接受边界。
- **验证**: 代码层缓解已通过 `cargo test --manifest-path src-tauri\Cargo.toml risk --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml etw --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml process_control --lib --quiet`；新增回归覆盖真实 Windows PowerShell 路径不自动挂起、假冒 `powershell.exe` 路径仍自动拦截，以及共享控制链路径判断。2026-06-28 新增并通过 `cargo test --manifest-path src-tauri\Cargo.toml realtime_evidence_collection_skips_windows_control_chain --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml enqueue_rejects_current_process_control_chain_before_suspend --lib --quiet`、`rustfmt --edition 2021 --check src-tauri\src\services\etw_service.rs src-tauri\src\services\interception_service.rs src-tauri\src\services\process_scanner_service.rs src-tauri\src\services\snapshot_service.rs` 和 `cargo check --manifest-path src-tauri\Cargo.toml`。2026-06-28 23:24:48-2026-06-29 00:11:18 的长稳验收在 VM `病毒测试` 内持续运行 `npm.cmd run dev` 2790 秒，`summary.json` 记录 `sampleCount=9`、`failedSuspend=0`、`hotPid=0`、`panic=0`、`rustCompile=0`、`fileMonitorLag=0`、`systemCriticalEventCount=0`；运行结束后 `anxin-security`、`node`、`cargo`、`rustup`、`rustc` 均已退出，当前仅剩控制会话，没有新的系统崩溃或控制面失联迹象。该结果足以把本条收口为 Fixed。
- **后续观察**: 如后续再出现新的 BugCheck 或控制链失效，再重新打开新条目；本轮验收已闭环。

---

### VUL-022: ETW 命中事件重复入库导致行为数据库写放大

- **严重等级**: High
- **漏洞类型**: 本地拒绝服务 / 数据库写放大 / 运行态降级
- **影响模块**: `src-tauri/src/services/etw_service.rs`, `src-tauri/src/services/risk_service.rs`, `src-tauri/src/services/behavior_service.rs`
- **位置**: `EtwService::start` 的 ETW 事件分发循环、`RiskService::analyze_event` 的行为库写入路径
- **状态**: Fixed
- **描述**: ETW 高价值事件原先存在两条行为库写入路径：`etw_service` 在事件分发阶段直接调用 `BehaviorService::ingest_event()`，随后同一事件进入 `RiskService::analyze_event()` 后又会以 `risk_analysis` 形式再次写入行为库。遇到同一 PID、同一规则、同一路径的高频 ETW 命中时，SQLite 会被重复写入放大，表现为行为库增长过快、写入压力上升，并可能拖慢风险分析和前端查询。
- **攻击向量**: 本地进程持续制造能命中 ETW 规则的文件、注册表、镜像加载或测试规则事件，使安全产品把重复事件逐条写入 SQLite，造成资源消耗和安全功能降级。
- **修复日期**: 2026-06-24
- **修复方式**: 移除 `etw_service` 中 ETW 命中事件直接写行为库的分支，行为库写入统一由 `RiskService` 负责；在进入风险分析前新增 `EtwBehaviorDbGate`，按 `pid/provider/operation/ruleId 或 threatType/path` 生成去重键，同一信号在 10 秒窗口内只向行为库写入一条代表记录，重复样本继续保留在 ETW 诊断缓存和聚合桶中用于排查。
- **验证**: 已通过 `cargo test --manifest-path src-tauri\Cargo.toml etw --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml fanout --lib --quiet`、`rustfmt --edition 2021 --check src-tauri\src\services\etw_service.rs` 和 `cargo check --manifest-path src-tauri\Cargo.toml`。本轮未做管理员桌面/VM 长时间运行复测，仍需现场观察 SQLite 写入量和 ETW 诊断聚合是否符合预期。

---

### VUL-023: ETW 重复实时响应和 FileMonitor 同路径重复扫描导致任务/扫描放大

- **严重等级**: High
- **漏洞类型**: 本地拒绝服务 / 任务风暴 / 扫描放大 / 运行态降级
- **影响模块**: `src-tauri/src/services/etw_service.rs`, `src-tauri/src/services/file_monitor_service.rs`, `src-tauri/src/services/risk_service.rs`, `src-tauri/src/services/process_scanner_service.rs`
- **位置**: `EtwService::start` 的实时响应分发、`FileMonitorService::start` 的文件事件扫描入口
- **状态**: Fixed
- **描述**: 行为库双写修复后继续排查发现，同一 PID、同一规则、同一路径的高频 ETW 命中仍会重复触发前端事件、日志写入、直接拦截检查、`ProcessScanner` hot PID 唤醒以及 `RiskService::analyze_event()` 异步任务。File provider 事件虽然已收窄到 FileMonitor，但同一路径密集 `create/write/setinfo` 仍会反复读取路径策略、计算哈希并查扫描缓存。高频输入下这些出口会造成任务风暴、扫描放大和 UI/后台响应压力。
- **攻击向量**: 本地进程持续制造重复镜像加载、规则命中或同一路径文件写入事件，使安全产品反复调度响应链路和扫描链路，消耗 CPU、I/O、线程调度和前端事件处理资源。
- **修复日期**: 2026-06-24
- **修复方式**: 新增 `EtwResponseGate`，按 `pid/provider/operation/ruleId 或 threatType/path` 对高价值 ETW 实时响应做 2 秒短窗口合并；重复事件仍进入 ETW 诊断缓存和聚合桶，但不再重复触发前端推送、日志、直接拦截、hot PID 复扫或风险分析任务。新增 `FileScanDedupGate`，对同一路径 File 事件做 750ms 短窗口扫描去重，避免密集写入反复进入路径策略和扫描缓存入口；不同路径不会被合并。
- **验证**: 已通过 `cargo test --manifest-path src-tauri\Cargo.toml etw --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml file_monitor --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml fanout --lib --quiet`、`node --test tests\monitoring_runtime_control.test.mjs`、`rustfmt --edition 2021 --check src-tauri\src\services\etw_service.rs src-tauri\src\services\file_monitor_service.rs` 和 `cargo check --manifest-path src-tauri\Cargo.toml`。本轮未做管理员桌面/VM 长时间运行复测，仍需现场观察 ETW 响应任务数、FileMonitor 扫描量和 UI 实时事件量。

---

### VUL-024: 内核驱动 IOCTL 码与驱动定义完全不符导致驱动防护全链路静默失效

- **严重等级**: Critical
- **漏洞类型**: 防护失效 / 接口契约错误
- **影响模块**: `src-tauri/src/utils/driver_client.rs`, `native/driver/src/driver.c`
- **状态**: Fixed
- **位置**: `driver_client.rs` IOCTL 常量定义、`add_pid`/`remove_pid`、`query_pids`、`connect`
- **描述**: Rust 侧 9 个 IOCTL 常量全部被写成 `0x8000_00xx` 一族（等价于 DeviceType=0x8000、Function=9、Method=0、Access=0），而 `driver.c` 使用 `CTL_CODE(FILE_DEVICE_UNKNOWN=0x22, 0x800..0x808, …)`，真值为 `0x0022_A000` 一族，两者毫无关系。`DriverDeviceControl` 的 switch 因此全部落到 `default` 返回 `STATUS_INVALID_DEVICE_REQUEST`——**即使驱动成功加载，进程保护、WinSta 保护、注册表保护也 100% 静默失效**，且失败仅被 `eprintln` 吞掉，外部完全无感。伴随三处缓冲区契约错误：(1) `add_pid`/`remove_pid` 只发 4 字节，而驱动按 `InputBufferLength >= sizeof(HANDLE)`（x64=8）校验并以 `*(PHANDLE)` 读取；(2) `query_pids` 按 4 字节步长读 260 字节缓冲区，而驱动写 `ULONG count` + 8 字节 `HANDLE[]`，PID 超过 32 时驱动直接返回 `STATUS_BUFFER_OVERFLOW`，未超时读出的也全是错位值；(3) `connect()` 使用 `FILE_SHARE_NONE`，而 `init_driver_protection` 用 `std::mem::forget` 常驻持有第一个句柄，导致 `register_registry_protection` 的第二次 connect 必然 `ERROR_SHARING_VIOLATION`。
- **攻击向量**: 用户以为自我保护、注册表保护已启用，实际全部未生效。攻击者可正常终止安芯进程、读写其内存、篡改其注册表配置，防护形同虚设。
- **加重因素**: 原单元测试 `test_ioctl_constants_match_c_driver` 把同一批错误常量硬断言了一遍——常量与断言来自同一个错误来源，测试永远绿，把 bug 固化成了"已验证"。
- **修复日期**: 2026-07-26
- **修复方式**:
  1. 新增 `ctl_code()` const fn 按 WDK 公式 `(DeviceType << 16) | (Access << 14) | (Function << 2) | Method` 推导全部 9 个常量，不再硬编码字面量。
  2. `add_pid`/`remove_pid` 改发 `usize`（x64 = 8 字节）负载。
  3. `query_pids` 缓冲区改为 `4 + MAX_PROTECTED_PIDS * 8`、读取步长改为 8，并对驱动返回的 count 做容量夹取。
  4. `connect()` 改为 `FILE_SHARE_READ | FILE_SHARE_WRITE`。
  5. 测试重写为三层校验：与手工展开值比对、逐位校验 IOCTL 字段构成（设备类型/method/access）、**直接解析 `native/driver/src/driver.c` 的 CTL_CODE 实参重新推导每个值**，确保两侧不会再各自漂移。
- **验证**: `cargo test --lib utils::driver_client` 7 个测试全部通过。**注意：本机未安装 WDK 且驱动签名不满足内核加载要求，本修复尚未经过真机加载验证。**

---

### VUL-025: 驱动镜像缺少 FORCE_INTEGRITY 导致 ObRegisterCallbacks 注册被拒

- **严重等级**: High
- **漏洞类型**: 防护失效 / 构建配置缺失
- **影响模块**: `native/driver/AnXinProcProtect.vcxproj`
- **状态**: Fixed
- **描述**: `ObRegisterCallbacks` 硬性要求调用方镜像带 FORCE_INTEGRITY 标志（PE 可选头 `DllCharacteristics` 位 `0x0080`），否则直接返回 `STATUS_ACCESS_DENIED`。已编译的 `AnXinProcProtect.sys` 的 `DllCharacteristics` 为 `0x0160`，未置该位，因此 `driver.c` 中的进程句柄保护回调注册必然失败，句柄权限剥离完全不生效。
- **修复日期**: 2026-07-26
- **修复方式**: 在 vcxproj 的 Debug|x64 与 Release|x64 两个 `<Link>` 配置中加入 `<AdditionalOptions>/INTEGRITYCHECK %(AdditionalOptions)</AdditionalOptions>`。`native/file_protect` 是 minifilter、不调用 `ObRegisterCallbacks`，无需该选项。
- **验证**: 2026-07-27 使用官方 `Microsoft.Windows.WDK.x64 10.0.28000.2526` NuGet 包提供的 WDK 内容和本机 MSBuild 18.9 完成 `Release|x64` 干净重建；`dumpbin /headers` 显示新产物 `DllCharacteristics=0x41E0` 且包含 `Check integrity`。产物仍未签名，也未安装或真机加载，因此仅确认构建标志，未确认 `ObRegisterCallbacks` 现场注册成功。

---

### VUL-026: 风险研判事件名与转发白名单不符导致服务模式下告警全丢

- **严重等级**: High
- **漏洞类型**: 安全告警丢失
- **影响模块**: `src-tauri/src/services/windows_service.rs`, `src-tauri/src/services/ipc_bridge_service.rs`
- **状态**: Fixed
- **描述**: `RiskService` 发出的事件名是 `etw-risk-event`，前端 `src/api/risk.ts` 监听的也是 `etw-risk-event`，但服务进程的转发白名单与 UI 侧 IPC 桥接白名单里写的都是 `risk-event`——该名字在全仓**无人 emit**。事件总线与 IPC 客户端均按名字精确匹配，因此服务进程模式下每一次风险研判结果都发进无人订阅的通道，前端 `onRiskEvent` 永远为空，用户看不到任何 ETW 风险告警。
- **攻击向量**: 恶意行为被正确研判为高风险，但告警在传输层被静默丢弃，用户无从得知。
- **修复日期**: 2026-07-26
- **修复方式**: 两张白名单中的 `risk-event` 改为 `etw-risk-event`；新增 `forwardable_events_have_no_dead_entries` 测试，同时断言 `risk_service.rs` 确实发出该事件名、且白名单中不得残留死条目 `risk-event`。

---

### VUL-027: 行为监控开关在服务模式下不生效，关闭后仍持续采集

- **严重等级**: High
- **漏洞类型**: 安全开关失效 / 用户控制绕过
- **影响模块**: `src-tauri/src/commands/config.rs`, `src-tauri/src/services/ipc_protocol.rs`, `src-tauri/src/services/windows_service.rs`
- **状态**: Fixed
- **描述**: 违反 AGENTS.md「功能开关关闭时，对应监控与采集逻辑必须真正停止，不能只关界面不关后台」。双进程架构下 ETW 跑在 SYSTEM 服务进程里，而 `set_behavior_monitoring_enabled` 在 IPC 已连接时只调用 persist 写配置文件、完全跳过运行态控制，IPC 协议里也没有任何 ETW pause/resume 或配置下发方法。此外 `windows_service::start_protection_components` 启动 ETW 时根本不读 `behaviorMonitoring.enabled`，与 `main.rs` 独立模式的条件启动不一致——用户关掉开关后重启服务，服务照样采集。
- **攻击向量**: 用户认为已关闭行为监控（例如出于隐私或性能考虑），实际后台持续采集进程/文件/注册表/网络事件。
- **修复日期**: 2026-07-26
- **修复方式**:
  1. `ipc_protocol::methods` 新增 `SET_BEHAVIOR_MONITORING`，参数 `{ "enabled": bool }`。
  2. `ipc_server` 侧实现该方法，调用 `EtwService::resume/pause` 并回报 running/collecting。
  3. `commands/config.rs` 在 IPC 已连接时改走 IPC，且**运行态切换成功后才落盘**，避免"配置说关了但后台还在跑"的不一致状态。
  4. `windows_service` 启动 ETW 前读取 `AppConfig::load()?.behavior_monitoring.enabled`；读配置失败时默认开启（安全产品宁可多采集也不静默失防）。

---

### VUL-028: ETW 运行状态上报恒为真且 IPC 查询分支为死代码

- **严重等级**: Medium
- **漏洞类型**: 安全状态误报
- **影响模块**: `src-tauri/src/services/ipc_server.rs`, `src-tauri/src/commands/behavior.rs`
- **状态**: Fixed
- **描述**: 两个方向的状态都是错的。服务侧 `ipc_server` 的 `etw_running` 用 `ctx.get::<Mutex<EtwService>>().is_some()`，而 `build_service_context` 无条件注册 `EtwService`，该字段**恒为 true**，即使 ETW 因权限或会话创建失败根本没跑起来。UI 侧 `commands/behavior.rs::get_etw_status` 先查本地 state，而 UI 进程无条件 `app.manage(EtwService)`、服务模式下该实例从未启动，导致本地分支恒命中返回 `running=false`，把正在 SYSTEM 侧采集的服务显示成"ETW 已停止"，其后的 IPC 查询分支成为**死代码**。
- **攻击向量**: 用户依据界面判断防护状态，两种模式下都可能得到与实际相反的结论。
- **修复日期**: 2026-07-26
- **修复方式**: `ipc_server` 改为读真实的 `is_running()` / `is_collecting()`；`ProtectionStatus` 新增 `etw_collecting` 字段（带 `#[serde(default)]` 兼容旧版服务）；`get_etw_status` 改为 IPC 已连接时优先走 IPC，判据与 `commands/config.rs::is_service_connected` 保持一致。

---

### VUL-029: 服务进程在无 UI 连接时挂起进程且无人可询问，形成永久冻结

- **严重等级**: Medium
- **漏洞类型**: 拒绝服务 / 不可恢复状态
- **影响模块**: `src-tauri/src/services/service_context.rs`, `src-tauri/src/services/interception_service.rs`
- **状态**: Fixed
- **描述**: 服务进程的 `ServiceContext::show_interception_window` 在没有 UI 桥接时直接返回 `Ok(())`（假成功），而拦截流程在此之前已经通过 `NtSuspendProcess` 挂起了目标进程。当没有任何 UI 进程连接到 IPC 时，弹窗无处可推、用户无从得知、也没有任何恢复入口，被挂起的进程就此永久冻结。
- **攻击向量**: 在服务运行但 UI 未启动的时段触发一次高风险规则命中，即可让目标进程被无声冻结且无法恢复。
- **修复日期**: 2026-07-26
- **修复方式**: `IpcServer` 注册进 `ServiceContext`；`show_interception_window` 在没有 UI 桥接且 `client_count() == 0` 时返回 `Err`，从而走与建窗失败一致的回滚路径（恢复进程 + 保留告警与诊断记录）。取舍理由：**没人能回答的拦截等于永久冻结，"记录在案的放行"优于"用户永远无法被询问的冻结"**。副作用：headless 服务场景下自动挂起实际不生效，告警仍会记录。

---

### VUL-030: ETW 时间窗口规则恒不命中，行为链关联为死特性

- **严重等级**: Medium
- **漏洞类型**: 检测能力缺失
- **影响模块**: `src-tauri/src/services/etw/rules.rs`
- **状态**: Fixed
- **位置**: `match_window_rule`
- **描述**: `match_window_rule` 只向 `seen` 集合插入常量字符串 `"_event"`，而 `all_required` 判定查的是 `"{provider_char}:{op}"` 形式的键，因此 `requiredOps` 非空时判定恒为 `false`——**所有配置了 `windowMs` + `requiredOps` 的规则永远不可能命中**。`docs/etw_rules_guide.md` 中宣传的"高级时间窗口匹配"实际是死特性，这也意味着引擎缺少把孤立事件聚合成行为链的能力，只能对单个事件做强证据判定，是误报率高的根本原因之一。
- **修复日期**: 2026-07-26
- **修复方式**: 改为直接查询该 PID 的上下文环——该环由 `push_context` 对**每一个** ETW 事件写入（与规则是否命中无关），能真实反映窗口内发生过什么。新增 `ContextRing::contains_op_within(provider, op, start_ms, end_ms)`，直接扫描底层缓冲区而不做 snapshot 克隆（该函数在 ETW 回调线程上按「规则 × 先决条件」的次数调用，克隆 192 项上下文的代价不可接受）。删除已失效的 `window_states` 字段。同步修正 `docs/etw_rules_guide.md` 的判定语义说明。
- **验证**: 新增 4 个测试覆盖窗口内命中、无先决事件不命中、先决事件超窗不命中、跨 PID 不命中。

---

### VUL-031: 内核驱动把 PCHAR 强转为 PUNICODE_STRING，进程名可控的野指针解引用

- **严重等级**: Critical
- **漏洞类型**: 内核内存越界读 / 类型混淆
- **影响模块**: `native/driver/src/driver.c`、`native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: `IsAnxinProcess`（driver.c）、`IsCallerAuthorized`（minifilter.c）
- **描述**: 两处都写成 `PUNICODE_STRING name = (PUNICODE_STRING)PsGetProcessImageFileName(proc);`。`PsGetProcessImageFileName` 返回的是 `PCHAR`——指向 `EPROCESS` 内部一个 **15 字节 ANSI** 名字数组，不是 `UNICODE_STRING`。强转之后，结构体的 `Length` / `MaximumLength` / `Buffer` 三个字段实际是用**进程名自身的 ASCII 字节**拼出来的：对 `anxin-security.exe` 而言 `Length` 变成 `0x6E61`(28257)、`Buffer` 变成 `0x652E797469727563`。随后 `RtlCompareUnicodeString` 会去解引用这个完全由文件名决定的野指针，读取长达 28KB 的内存。
- **攻击向量**: 进程名由创建者完全控制，因此 `Buffer` 指针的每一个字节都可被攻击者选定——把"给进程改名"变成了一个内核任意地址读原语。最轻的后果是 `PAGE_FAULT_IN_NONPAGED_AREA` 蓝屏（`IsAnxinProcess` 在 `PsSetCreateProcessNotifyRoutineEx` 里对**每一次进程创建**都会被调用），最重可用于探测内核地址空间。
- **修复日期**: 2026-07-27
- **修复方式**: 改为两阶段判定。第一阶段按 `PCHAR` 的正确语义比较 15 字节 ANSI 名（截断长度内取 14 字符）做廉价预筛；第二阶段用 `SeLocateProcessImageName` 取完整 NT 路径，校验末段必须是 `\anxin-security.exe` 且前面紧邻路径分隔符，用完 `ExFreePool` 释放。`driver.c` 的头文件从 `ntddk.h` 换成 `ntifs.h`（`SeLocateProcessImageName` 只在后者声明），并补上 `PsGetProcessImageFileName` 的 extern 声明。
- **验证**: 2026-07-27 已用 WDK 10.0.28000.2526 完成进程与文件驱动的 `Release|x64` 干净重建，MSBuild 返回 0。产物未签名、未加载，仍需真机创建不同名称/同名进程验证授权行为。

---

### VUL-032: 微过滤器授权校验在取不到进程路径时 fail-open

- **严重等级**: High
- **漏洞类型**: 授权绕过
- **影响模块**: `native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: `IsCallerAuthorized`
- **描述**: `SeLocateProcessImageName` 失败时原代码直接 `return TRUE`，注释写的是"名字匹配、路径不可用 → 信任"。这是授权判定路径上的 fail-open：授权成功意味着调用方可以任意修改受保护文件与目录。
- **攻击向量**: 任何能让 `SeLocateProcessImageName` 失败的进程（例如在低内存压力下触发分页池分配失败，或利用映像节对象已被拆除的时机窗口）都可以直接获得完整授权，绕过文件保护。配合 VUL-031 的名字判定失效，这条路径的实际门槛更低。
- **修复日期**: 2026-07-27
- **修复方式**: 改为 fail-closed：取不到完整路径一律返回 `FALSE`，不授权。
- **验证**: 2026-07-27 已用 WDK 10.0.28000.2526 完成 `AnXinFileProtect.sys` 的 `Release|x64` 干净重建，MSBuild 返回 0。尚未真机制造 `SeLocateProcessImageName` 失败路径。

---

### VUL-033: 进程保护驱动设备无显式 DACL

- **严重等级**: High
- **漏洞类型**: 权限控制缺失
- **影响模块**: `native/driver/src/driver.c`
- **状态**: Fixed
- **位置**: `DriverEntry`
- **描述**: 设备用 `IoCreateDevice` 创建且未传安全描述符，继承的默认 DACL 允许普通用户打开。设备上暴露的 IOCTL 包含 `IOCTL_ANXIN_CLEAR_PIDS`、`IOCTL_ANXIN_ADD_PID`、`IOCTL_ANXIN_CLEAR_REG_KEYS` 等管理接口。
- **攻击向量**: 任意非特权进程 `CreateFile("\.\AnXinProcProtect")` 后下发一条 `IOCTL_ANXIN_CLEAR_PIDS`，即可清空受保护 PID 列表，整套进程自保护、窗口站保护与注册表保护随之失效——不需要任何提权。
- **修复日期**: 2026-07-27
- **修复方式**: 改用 `IoCreateDeviceSecure` 并显式指定 DACL `D:P(A;;GA;;;SY)(A;;GA;;;BA)`（仅 SYSTEM 与 Administrators），同时传入 `FILE_DEVICE_SECURE_OPEN` 让该 DACL 覆盖以设备名为前缀的相对打开路径。vcxproj 补上 `wdmsec.lib`。服务进程以 LocalSystem 运行，不受影响。
- **验证**: 2026-07-27 已用 WDK 10.0.28000.2526 完成 `AnXinProcProtect.sys` 的 `Release|x64` 干净重建，MSBuild 返回 0。新驱动 `AnXinNetFilter` 从一开始就用 `IoCreateDeviceSecure`；两者仍需加载后以普通用户/管理员句柄分别验证 DACL。

---

### VUL-034: 服务模式下拦截决策全部静默失败

- **严重等级**: High
- **漏洞类型**: 防护失效
- **影响模块**: `src-tauri/src/services/ipc_server.rs`、`src-tauri/src/services/ipc_protocol.rs`
- **状态**: Fixed
- **位置**: `handle_request` 的 `HANDLE_INTERCEPTION` 分支、`InterceptionDecisionParams`
- **描述**: 两个独立缺陷叠加。其一，UI 侧 `commands/interception.rs` 发出的报文是 `{"pid":..,"action":".."}`，而服务端反序列化的 `InterceptionDecisionParams` 只声明了 `decision` 字段，因此服务模式下每一次 Allow/Block 都以 ``Invalid params: missing field `decision``` 失败。其二，即便参数解析通过，该分支也只调用 `mark_decision_with_window`——该函数只做记账（清 showing、出队、删除恢复台账），既不调 `resume_process_by_pid` 也不调 `terminate_process_by_pid`。
- **攻击向量**: 用户点击"阻止"后恶意进程只是被挂起、仍然存活，且拦截窗口已关闭、恢复台账已删除，用户误以为威胁已处置；用户点击"允许"后合法进程被永久挂起，且台账已删，重启也无法恢复。
- **修复日期**: 2026-07-27
- **修复方式**: 给 `InterceptionDecisionParams::decision` 加 `#[serde(alias = "action")]`，让协议类型与线上实际报文一致并同时兼容两种键名；`HANDLE_INTERCEPTION` 分支改为完整复刻 `commands/interception.rs` 独立模式的流程——取 `entry_for_pid`、Allow 走 `mark_allowed_temporarily` + `resume_process_by_pid`（失败时撤销临时放行）、Block 走 `terminate_process_by_pid`，随后 `mark_decision_with_window` 并 `try_show_next` 轮播下一条。
- **验证**: 新增 2 个测试覆盖 `action` / `decision` 两种键名可解析、两者皆缺时报错。服务模式真机烟测**未运行**。

---

### VUL-035: IPC 控制管道对 Everyone 授予 GENERIC_ALL

- **严重等级**: Medium
- **漏洞类型**: 权限控制过宽
- **影响模块**: `src-tauri/src/services/ipc_server.rs`
- **状态**: Fixed
- **位置**: `start` 中的 SDDL 常量
- **描述**: 管道安全描述符为 `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;WD)`，其中 `WD` 即 Everyone，授予 `GENERIC_ALL`。该管道是 SYSTEM 托管的控制通道，上面挂着 `handle_interception`、`clear_interception_queue`、`start_engine`、`scan_file`，以及本轮新增的 `set_firewall_enabled` / `set_firewall_mode` / `handle_network_decision`。对比同仓的 `hook_service.rs` 用的是按用户 SID 收紧的 ACL。
- **攻击向量**: 任意本地账户（含各类服务账户、网络登录身份、计划任务身份）都能连上该管道，关闭防火墙、清空拦截队列、或替自己的连接下发放行裁决。
- **修复日期**: 2026-07-27
- **修复方式**: 把 `WD` 换成 `IU`（Interactive Users），保留 SYSTEM 与 Administrators。UI 进程在交互式会话中运行，不论登录用户是谁都能连上，而非交互式身份被排除。
- **遗留**: 这不足以挡住同一交互式会话内的恶意进程。真正的控制是 `identity_verification_service` 的调用方身份校验。
- **补充接线（2026-08-07）**: `identity_verification_service` 此前全部函数都是死代码。本轮新增 `verify_pipe_client` 整合入口（复用 `collect_evidence` 采集 PID/路径/启动时间/SID/会话/完整性，校验可执行文件路径、要求交互式会话 `session_id > 0`、拒绝 SYSTEM/服务账户 SID、拒绝低完整性），并在 `ipc_server.rs::handle_client` 创建连接前调用；校验失败 fail-closed（不注册客户端、不处理任何请求、关闭管道）。会话语义与 `verify_identity` 不同：服务进程在 Session 0，UI 在交互会话，故按「交互式会话」判定而非「等于服务进程会话」。

---

### VUL-036: 服务模式拦截队列除 PID 外字段全为空串

- **严重等级**: Low
- **漏洞类型**: 信息缺失
- **影响模块**: `src-tauri/src/services/ipc_server.rs`
- **状态**: Fixed
- **位置**: `handle_request` 的 `GET_INTERCEPTION_QUEUE` 分支
- **描述**: 该分支只从 `get_paused_pids()` 拿 PID，其余字段（进程名、路径、风险等级、威胁类型、原因、时间戳）一律填空串或 0。服务模式下 UI 拿到的拦截队列因此只有一列 PID，用户既看不出是哪个程序被拦，也看不出为什么被拦。
- **修复日期**: 2026-07-27
- **修复方式**: 改为对每个 PID 调 `entry_for_pid` 取回真实条目；条目恰好在两次调用之间被裁决掉时保留 PID，让调用方仍知道它曾在队列里。
- **验证**: 随 `cargo test --lib` 一起通过编译；服务模式真机烟测**未运行**。

---

### VUL-037: Ob 回调对象类型指针层级错误导致句柄保护构建或运行失效

- **严重等级**: High
- **漏洞类型**: 防护失效 / 内核 API 契约错误
- **影响模块**: `native/driver/src/driver.c`
- **状态**: Fixed
- **位置**: `ProcessPreOperation`、`ThreadPreOperation`、`DriverEntry` 中的 `OB_OPERATION_REGISTRATION`
- **描述**: `OB_OPERATION_REGISTRATION.ObjectType` 的类型是 `POBJECT_TYPE *`，应直接接收 WDK 导出的 `PsProcessType` / `PsThreadType`；回调中的 `Info->ObjectType` 才应与解引用后的 `*PsProcessType` / `*PsThreadType` 比较。原实现把两处指针层级写反，当前 WDK 下会产生不兼容指针错误；若通过强制转换或较宽松设置生成镜像，回调对象判断也可能恒不匹配，使进程和线程句柄权限剥离失效。
- **攻击向量**: 用户误以为驱动已阻止外部进程获取终止、内存读写、创建线程或挂起权限，实际构建无法完成或回调无法正确匹配对象类型。
- **修复日期**: 2026-07-27
- **修复方式**: 注册项改为 `ObjectType = PsProcessType/PsThreadType`，回调比较改为 `Info->ObjectType == *PsProcessType/*PsThreadType`，保持 WDK 契约两端一致。
- **验证**: `AnXinProcProtect.vcxproj` 已用 WDK 10.0.28000.2526 完成 `Release|x64` 干净重建，MSBuild 返回 0；产物未签名、未加载，尚未用真实句柄访问实验确认权限掩码。

---

### VUL-038: 仅按可伪造的进程文件名授予内核驱动信任

- **严重等级**: High
- **漏洞类型**: 身份验证绕过 / 防护绕过
- **影响模块**: `native/driver/src/driver.c`、`native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: `IsAnxinProcess`、`ProcessNotifyCallback`、`IsCallerAuthorized`
- **描述**: 两个驱动虽已从 15 字节进程短名升级为完整路径查询，但最终只检查路径是否以 `\anxin-security.exe` 结尾，没有绑定可信安装根、签名、文件标识或服务预登记 PID。任意目录中的同名程序都能通过身份判断；进程驱动还会在进程创建回调中自动把所有同名进程加入最多 64 项的受保护 PID 表。
- **攻击向量**: 本地攻击者运行自有 `anxin-security.exe`，可被驱动视作产品进程，绕过进程/线程/注册表访问限制和文件微过滤器写保护；批量创建同名进程还可占满受保护 PID 槽位。底层 Windows 文件 ACL 可能限制部分低权限写入，但不能替代驱动自身的身份边界。
- **修复日期**: 2026-07-28
- **修复方式**: 在 `driver.c` 的 `IsAnxinProcess` 和 `minifilter.c` 的 `IsCallerAuthorized` 中，文件名匹配成功后追加可信安装目录子串检查：路径必须包含 `\anxinsecurity\`（`TRUSTED_INSTALL_DIR` / `ANXIN_TRUSTED_DIR`），否则拒绝授权。两处使用相同的子串搜索逻辑（大小写不敏感），与 VUL-019 的 `IsTrustedImagePath` 保持一致。非受信路径的同名进程不再被自动加入受保护 PID 表，也不再获得微过滤器写保护豁免。
- **验证**: 2026-07-28 VM 部署验证：ProcProtect.sys 46056 bytes、FileProtect.sys 27624 bytes，三个驱动全部 RUNNING，自保测试通过。

---

### VUL-039: 微过滤器端口消息路径未限定 NUL 导致内核越界访问

- **严重等级**: High
- **漏洞类型**: 内核越界读写 / 输入校验缺失
- **影响模块**: `native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: `PortMessage` 的 `FpmAddPath` / `FpmRemovePath` 分支
- **描述**: 输入只验证 `InputBufferLength >= sizeof(FPM_MESSAGE)`，随后对固定 `WCHAR Path[520]` 使用无界 `wcslen` / `RtlInitUnicodeString`，并在添加末尾反斜杠时直接改写调用方消息。构造一个填满但无 NUL 的消息可越过结构体读取；删除路径随后会把不受上限约束的长度传入固定缓冲区处理，存在进一步内核栈破坏风险。利用前提是能通过通信端口连接和调用方身份检查，本轮没有把理论风险夸大为已证明的代码执行。
- **攻击向量**: 获得端口访问能力的本地进程发送无终止符路径，触发内核越界读取、崩溃或后续固定缓冲区越界。
- **修复日期**: 2026-07-27
- **修复方式**: 两个路径操作均在 `MAX_PATH_LENGTH` 内逐项查找 NUL；空路径或未终止路径立即拒绝。合法路径先复制到本地定长缓冲区，再构造显式 `Length/MaximumLength` 的 `UNICODE_STRING`；添加目录分隔符也只修改本地副本并预留终止符空间。
- **验证**: `AnXinFileProtect.vcxproj` 已用 WDK 10.0.28000.2526 完成 `Release|x64` 干净重建，MSBuild 返回 0。尚未加载驱动执行畸形消息回归，因此现场抗崩溃结论仍未验证。

---

### VUL-040: 防火墙首次启用顺序死锁并产生持久化状态漂移

- **严重等级**: Medium
- **漏洞类型**: 安全功能不可启用 / 状态事务不一致
- **影响模块**: `src/stores/firewallStore.ts`、`src-tauri/src/commands/firewall.rs`、`src-tauri/src/services/ipc_server.rs`、`src-tauri/src/services/firewall_service.rs`
- **状态**: Fixed
- **描述**: 前端首次开启时先调用 `setFirewallEnabled(true)`，成功后才调用 `startFirewall()`；后端设置命令却先把 `enabled=true` 保存到磁盘，再对尚未连接的驱动执行 `apply_config()`。未连接状态必然返回错误，前端因此不会继续启动，并只回滚界面状态，磁盘仍可能保留启用。服务模式下 `start_firewall` / `stop_firewall` 又在检测到 IPC 后直接返回成功，没有对应的服务端启动/停止方法。
- **攻击向量**: 防火墙默认关闭的安装无法通过正常 UI 首次启用，用户误以为开关已受控；持久化状态与当前运行态分离后，重启又可能在用户已看到回滚的情况下意外尝试启用。
- **修复日期**: 2026-08-07
- **修复方式**: 事务顺序改为「先运行态后落盘」。
  - 独立模式 `commands/firewall.rs::set_firewall_enabled`：开启时先 `apply_config`（驱动接受）成功后才 `save`；关闭时驱动在线先下发「恢复放行」再落盘，驱动未连仍如实落盘 false。
  - 服务端 `SET_FIREWALL_ENABLED`：开启时若防火墙未运行则调用 `firewall.start(ctx, config)` 完整启动（连接驱动→下发规则→下发配置→启动事件泵），已运行则 `apply_config`；任何失败 fail-closed 不落盘。关闭时驱动在线先下发放行再落盘，驱动未连直接落盘 false。
  - 服务模式 `start_firewall`/`stop_firewall` 的「返回成功」保留：生命周期归服务进程，但真正的开启启动已移到 `SET_FIREWALL_ENABLED`，覆盖「服务启动时驱动缺失降级、用户随后装好驱动再经 UI 开启」的路径。
- **验证**: 随 `cargo check` / `cargo test --lib` 通过；服务模式真机烟测**未运行**（无测试 VM 当前可用）。

---

### VUL-041: 进程驱动失败会连带跳过文件保护路径登记

- **严重等级**: Medium
- **漏洞类型**: 防护降级 / 错误隔离缺失
- **影响模块**: `src-tauri/src/services/windows_service.rs`
- **状态**: Open
- **位置**: `init_driver_protection`
- **描述**: 文件微过滤器的 `register_file_protection()` 被放在进程驱动连接、PID 登记、注册表登记之后。同一函数中的任一 `?` 提前返回都会跳过文件路径登记；即使 `AnXinFileProtect` 已正常加载，它也会因保护列表为空而不拦截安装目录修改。
- **攻击向量**: 删除、停止、签名阻断或破坏 `AnXinProcProtect` 即可连带关闭本应独立工作的文件保护，扩大单点故障影响面。
- **修复要求**: 将进程保护、注册表保护和文件保护初始化拆成独立的可观测步骤；每一路单独记录失败、继续启动其他链路，并保留幂等重试和明确清理路径。

---

### VUL-042: 手工安装写入旧 minifilter Instances 路径

- **严重等级**: Medium
- **漏洞类型**: 安全配置漂移 / 文件保护不可用
- **影响模块**: `src-tauri/src/services/driver_install_service.rs`、`native/file_protect/AnXinFileProtect.inf`
- **状态**: Fixed
- **描述**: INF 已按现代 minifilter 约定写入 `Services\AnXinFileProtect\Parameters\Instances`，但产品实际使用的 `--install-driver file` 手工安装路径仍写到旧的 `Services\AnXinFileProtect\Instances`。两种安装方式由此产生不同服务配置，现代 Filter Manager 可能找不到默认实例与 altitude，导致服务存在但过滤实例未挂载。
- **攻击向量**: 正常安装流程报告驱动服务创建成功，但文件保护实例未附加，安装目录处于无内核文件保护状态。
- **修复日期**: 2026-07-27
- **修复方式**: 手工安装统一改写 `Parameters\Instances`，并提取 `minifilter_instances_key` 作为唯一键路径生成入口；测试同时约束 Rust 生成路径与 INF 中的现代路径。
- **验证**: `driver_install_service` 相关单元测试通过，三个生成 INF 均通过 WDK `InfVerif /w`；当前终端非管理员，未执行注册表写入、服务安装或 `fltmc instances` 真机核验。

---

### VUL-043: IOCTL_ANXIN_ADD_PID 缺少调用方授权校验

- **严重等级**: High
- **漏洞类型**: 授权校验缺失 / 本地提权
- **影响模块**: `native/driver/src/driver.c`
- **状态**: Fixed
- **位置**: IOCTL 分发函数（`IOCTL_ANXIN_ADD_PID` 分支）
- **描述**: `IOCTL_ANXIN_REMOVE_PID` 和 `IOCTL_ANXIN_CLEAR_PIDS` 分支均已调用 `IsCallerAuthorizedForWinsta()` 进行调用方身份校验，但 `IOCTL_ANXIN_ADD_PID` 分支遗漏了该校验。任意用户态进程只需打开 `\\.\AnXinProcProtect` 设备并发送 `IOCTL_ANXIN_ADD_PID`，即可将任意 PID 加入受保护进程列表，使目标进程获得内核级终止保护（Ob 回调剥离 `PROCESS_TERMINATE` / `PROCESS_VM_WRITE` 等权限），变为不可终止进程。
- **攻击向量**: 本地任意进程打开设备句柄，以自身 PID 为参数发送 `IOCTL_ANXIN_ADD_PID`，即可使自身获得内核保护，任何用户态终止手段（`TerminateProcess`、任务管理器、安全软件）均无法将其杀死。也可将恶意 PID 批量注册以占满 64 项受保护槽位，挤占合法产品进程的注册空间。
- **修复日期**: 2026-07-28
- **修复方式**: 在 `IOCTL_ANXIN_ADD_PID` 分支入口处补充 `IsCallerAuthorizedForWinsta()` 校验，与 `REMOVE_PID` / `CLEAR_PIDS` 一致；校验失败返回 `STATUS_ACCESS_DENIED`。同时审计确认其余 IOCTL 分支（`QUERY_PIDS`、`ADD_WINSTA`、`REMOVE_WINSTA`、`ADD_REG_KEY`、`REMOVE_REG_KEY`、`CLEAR_REG_KEYS`、`QUERY_IMAGE_EVENTS`）均已有授权校验。设备本身通过 `IoCreateDeviceSecure` + SDDL 限定只有 SYSTEM 和 Administrators 能打开（VUL-033 修复），形成双层防护。
- **验证**: 2026-07-28 VM 部署验证：ProcProtect.sys 46056 bytes，三个驱动全部 RUNNING。

---

### VUL-044: 注册表保护用对象指针比较导致 sc delete 绕过

- **严重等级**: High
- **漏洞类型**: 注册表保护绕过 / 安全防护绕过
- **影响模块**: `native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: `IsRegProtectedKeyObject`、`RegProtectCallback`、`RegProtectServiceKeysDacl`
- **描述**: 注册表自保回调使用注册表键对象指针（`PVOID Object`）比较来识别受保护的三个服务键（AnXinProcProtect / AnXinFileProtect / AnXinNetFilter）。但 Windows 配置管理器为同一个注册表键的每次打开操作都创建不同的键对象，对象指针因打开路径不同而异。当 SCM（services.exe）在系统重启期间处理 `sc delete` 留下的 pending delete 标记并尝试删除服务键时，它使用的键对象指针与驱动初始化时缓存的指针不同，`IsRegProtectedKeyObject` 返回 FALSE，`RegProtectCallback` 放行删除操作。结果是三个驱动的服务注册表键在 VM 重启后被 SCM 删除，驱动在下次启动时无法加载，整个安全防护链路被绕过。
- **攻击向量**: 本地攻击者执行 `sc delete AnXinProcProtect` / `sc delete AnXinFileProtect` / `sc delete AnXinNetFilter`，SCM 的 `DeleteService()` API 返回成功并标记 pending delete。VM 重启时 SCM 处理 pending delete，由于对象指针不匹配，CmRegisterCallback 回调未阻止删除，三个服务键被清除，驱动无法加载。
- **修复日期**: 2026-07-29
- **修复方式**: 在 `IsRegProtectedKeyObject` 中使用 `CmCallbackGetKeyObjectIDEx` 获取稳定的 `ULONG_PTR ObjectID` 进行比较，替代对象指针比较。同一个注册表键无论通过什么 handle 打开，ObjectID 都相同，因此可以可靠地识别 SCM 对受保护键的操作。在 `RegProtectServiceKeysDacl` 中对每个服务键调用 `CmCallbackGetKeyObjectIDEx` 缓存 ObjectID 到 `g_RegProtectedKeyIDs` 数组。只请求 ObjectID（不请求 ObjectName），因此无需调用 `CmCallbackReleaseKeyObjectIDEx`。WDK 10.0.28000.0 签名要求第一个参数为 `PLARGE_INTEGER`，调用时传入 `&g_RegCookie`。
- **验证**: 2026-07-29 VM 部署验证：AnXinFileProtect.sys 23432 bytes，三个驱动全部 RUNNING（StartType=Boot）。直接注册表写/删操作被 CmRegisterCallback 阻止（Set-ItemProperty / Remove-ItemProperty 均返回"不允许所请求的注册表访问权"）。执行 sc delete 后重启 VM，三个服务键全部存活，驱动正常加载。

---

## 驱动安全审计发现（2026-07-29）

以下漏洞由 2026-07-29 对三个内核驱动（AnXinProcProtect / AnXinFileProtect / AnXinNetFilter）和用户态 file_hook DLL 的安全审计发现。审计由 4 个并行子智能体完成，覆盖输入验证、缓冲区安全、竞争条件、权限边界、注册表保护、WFP 引擎安全、注入安全等维度。

---

### VUL-045: IsPathProtected 前缀匹配与 PortMessage 尾部反斜杠矛盾导致目录下文件保护全失效

- **严重等级**: Critical
- **漏洞类型**: 防护失效 / 逻辑错误
- **影响模块**: `native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: `IsPathProtected` (L960-988)、`PortMessage` FpmAddPath (L1272-1278)
- **描述**: `PortMessage` 的 `FpmAddPath` 强制为路径添加尾部反斜杠（L1273-1278），导致所有受保护路径都以 `\\` 结尾存储（如 `\DEVICE\...\ANXINSECURITY\`）。但 `IsPathProtected` 的前缀匹配逻辑（L979-984）假设 `pp` 不以 `\\` 结尾：当 `sp.Length > pp->Length` 时检查 `sp.Buffer[pp->Length / sizeof(WCHAR)] == L'\\'`。当 `pp` 以 `\\` 结尾时，该位置是文件名首字符（如 `CONFIG.JSON` 的 `C`），而非路径分隔符，因此条件永远为 FALSE。结果是：**所有通过 PortMessage 添加的受保护目录，其下的文件全部不被保护**。仅 `IsKernelDriverFile` 的三个驱动文件（后缀匹配）仍受保护。
- **攻击向量**: 任意非授权进程可修改/删除受保护目录下的配置文件（如 `config/app.json`、`config/scan_rules.json`）、DLL、资源文件等，绕过文件保护。
- **修复建议**: 修正 `IsPathProtected` 前缀匹配逻辑：当 `pp` 以 `\\` 结尾时，前缀匹配成功即视为受保护（因为 `pp` 已包含分隔符）；或在 `FpmAddPath` 中不添加尾部反斜杠，改为在 `IsPathProtected` 中动态处理。
- **修复日期**: 2026-07-30
- **修复方式**: 在 `IsPathProtected` 前缀匹配中增加对 `pp` 以 `\\` 结尾的处理：当 `pp->Length >= sizeof(WCHAR)` 且 `pp->Buffer[lastCharOff] == L'\\'` 时直接判定前缀匹配成功（`pp` 已含分隔符，`sp` 以 `pp` 为前缀即位于受保护目录下）；同时保留原 `sp.Buffer[pp->Length / sizeof(WCHAR)] == L'\\'` 检查处理 `pp` 不以 `\\` 结尾的情况。
- **验证**: 2026-07-30 构建验证：AnXinFileProtect.sys 23040 bytes 编译链接成功（Inf2Cat/InfVerif 错误为签名/catalog 相关，与代码无关，.sys 已生成）。 VM 攻击回归验证（2026-07-30）：签名后部署到「病毒测试」VM（Win10 IoT LTSC 19044），3 驱动 BOOT_START 加载成功。VUL-045 受保护目录下文件写入被阻止（Access Denied）。

---

### VUL-046: 可信目录子串匹配 `\anxinsecurity\` 可被路径构造绕过

- **严重等级**: High
- **漏洞类型**: 身份验证绕过 / 授权绕过
- **影响模块**: `native/driver/src/driver.c`、`native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: `IsTrustedImagePath` (driver.c:580-601)、`IsAnxinProcess` (driver.c:560-562)、`IsCallerAuthorized` (minifilter.c:560-578)
- **描述**: VUL-038 的修复使用子串搜索检查路径是否包含 `\anxinsecurity\`，但这不是完整路径组件匹配。任意非特权用户可在自己可写的目录下创建名为 `anxinsecurity` 的子目录并放置恶意 `anxin-security.exe`。该路径会通过信任检查，恶意进程被判定为本产品进程，获得 `IsCallerAuthorized() == TRUE` 和 `IsAnxinProcess() == TRUE`，可调用 IOCTL 关闭所有保护或任意修改受保护文件。
- **攻击向量**: 攻击者在 `C:\Users\attacker\anxinsecurity\` 放置恶意 `anxin-security.exe`，运行后该进程获得授权身份，可调用 `IOCTL_ANXIN_CLEAR_PIDS` / `IOCTL_ANXIN_REMOVE_PID` 关闭进程保护，或在文件保护回调中被视为授权进程。
- **修复建议**: 改用路径组件解析（按 `\` 分割后逐组件比较），或绑定到服务注册的 ImagePath 父目录；考虑增加数字签名校验。
- **修复日期**: 2026-07-30
- **修复方式**: 在 `native/driver/src/driver.c` 的 `IsAnxinProcess` / `IsTrustedImagePath` 和 `native/file_protect/src/minifilter.c` 的 `IsCallerAuthorized` 中，将子串搜索改为路径组件匹配：定位候选子串后，校验其前一个字符是否为路径分隔符（`\\` 或 `/`），仅在路径组件边界匹配时才视为可信目录，阻止攻击者在任意目录下创建名为 `anxinsecurity` 的子目录绕过信任检查。
- **验证**: 2026-07-30 构建验证：AnXinProcProtect.sys 28672 bytes、AnXinFileProtect.sys 23040 bytes 编译链接成功。 VM 攻击回归验证（2026-07-30）：签名后部署到 VM，VUL-046 从非受信路径 anxinsecurity-fake 子目录进程调用 IOCTL 被驱动拒绝。

---

### VUL-047: RemoveProtectedPath 缺少路径长度校验导致栈缓冲区溢出

- **严重等级**: High
- **漏洞类型**: 栈缓冲区溢出
- **影响模块**: `native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: `RemoveProtectedPath` (L1017-1021)
- **描述**: `RemoveProtectedPath` 直接将 `Path->Length` 赋值给 `sp.Length` 并执行 `RtlCopyMemory`，没有像 `AddProtectedPath` (L992) 那样检查 `Path->Length >= MAX_PATH_LENGTH * sizeof(WCHAR)`。`buf` 大小为 1040 字节，若 `Path->Length > 1040` 则溢出。当前调用者 `FpmRemovePath` 限制了路径长度，但函数本身缺乏防御性校验。
- **修复建议**: 与 `AddProtectedPath` 一致，在函数入口添加 `Path->Length >= MAX_PATH_LENGTH * sizeof(WCHAR)` 检查。
- **修复日期**: 2026-07-30
- **修复方式**: 在 `RemoveProtectedPath` 入口添加 `Path->Length >= MAX_PATH_LENGTH * sizeof(WCHAR)` 长度校验，超长返回 `STATUS_INVALID_PARAMETER`，与 `AddProtectedPath` 的防御性检查保持一致，杜绝栈缓冲区溢出。
- **验证**: 2026-07-30 构建验证：AnXinFileProtect.sys 23040 bytes 编译链接成功。

---

### VUL-048: 注册表保护未拦截 RegRestoreKey/RegReplaceKey 可整体覆盖服务键

- **严重等级**: High
- **漏洞类型**: 注册表保护绕过
- **影响模块**: `native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: `RegProtectCallback` (L816-870)
- **描述**: `RegProtectCallback` 仅拦截 `RegNtPreDeleteKey`、`RegNtPreDeleteValueKey`、`RegNtPreSetValueKey`、`RegNtPreRenameKey`、`RegNtPreSetKeySecurity` 五种操作，未拦截 `RegNtPreRestoreKey`、`RegNtPreReplaceKey`、`RegNtPreLoadKey`。攻击者（需 SYSTEM 权限）可调用 `RegRestoreKey` 将受保护的服务键整体替换为攻击者构造的 hive 文件，修改 `ImagePath` 指向恶意驱动。
- **修复建议**: 在 `RegProtectCallback` 的 switch 中增加 `RegNtPreRestoreKey`、`RegNtPreReplaceKey`、`RegNtPreLoadKey`、`RegNtPreCreateKeyEx` 分支。
- **修复日期**: 2026-07-30
- **修复方式**: 在 `RegProtectCallback` 的 switch 中新增 `RegNtPreRestoreKey`、`RegNtPreReplaceKey`、`RegNtPreLoadKey`、`RegNtPreCreateKeyEx` 四个分支，对受保护服务键的这四种操作调用 `IsRegCallerAuthorized` 授权检查，未授权则返回 `STATUS_ACCESS_DENIED`，阻断通过 hive 整体覆盖服务键的攻击路径。
- **验证**: 2026-07-30 构建验证：AnXinFileProtect.sys 23040 bytes 编译链接成功。

---

### VUL-049: NetFilter 非接管者关闭句柄时清空全部 IRP 队列导致 DoS

- **严重等级**: High
- **漏洞类型**: 拒绝服务
- **影响模块**: `native/net_filter/src/driver.c`
- **状态**: Fixed
- **位置**: `AnxDispatchCleanup` (L253-269)
- **描述**: 当任何非接管进程关闭设备句柄时，`AnxDispatchCleanup` 调用 `AnxCsqFlushAll(STATUS_CANCELLED)` 清空 CSQ 中的**全部** IRP，而非仅当前进程的 IRP。I/O 管理器在 IRP_MJ_CLEANUP 前已通过 CSQ 取消例程处理了该文件对象的 IRP，此处的全量清理是多余的且误杀其他进程的 IRP。
- **攻击向量**: 任意 SYSTEM/Admins 进程 `CreateFileW` 打开设备然后关闭句柄，即可取消服务进程所有挂起的 `GET_EVENT` IRP，导致网络事件收集中断。
- **修复建议**: 移除非接管者分支的 `AnxCsqFlushAll` 调用。
- **修复日期**: 2026-07-30
- **修复方式**: 从 `AnxDispatchCleanup` 中移除 `AnxCsqFlushAll(STATUS_CANCELLED)` 调用。I/O 管理器在 IRP_MJ_CLEANUP 前已通过 CSQ 取消例程处理了该文件对象的 IRP，此处的全量清理是多余的且误杀其他进程的 IRP。移除后非接管进程关闭句柄仅完成自身 IRP，不影响服务进程挂起的 `GET_EVENT` IRP。
- **验证**: 2026-07-30 构建验证：AnXinNetFilter.sys 48640 bytes 编译链接成功。 VM 攻击回归验证（2026-07-30）：50 次非接管进程 open/close 设备句柄循环，AnXinNetFilter 始终 RUNNING，无 DoS。

---

### VUL-050: file_hook 句柄表全表清空（非 LRU）导致注入链检测绕过

- **严重等级**: High
- **漏洞类型**: 防护绕过 / 检测规避
- **影响模块**: `native/file_hook/src/file_hook_dll.cpp`
- **状态**: Fixed
- **位置**: `recordProcessHandle` (L690-692)
- **描述**: `gProcessHandleTargets` 超过 `kMaxTrackedProcessHandles`(2048) 时执行 `clear()` 全表清空，而非 LRU 逐出。攻击者用不带 `PROCESS_QUERY_LIMITED_INFORMATION` 的句柄操作目标时，`GetProcessId` 失败，PID 查找完全依赖该 map。攻击者线程 A 填满并触发 `clear()` 后，线程 B 的 `CreateRemoteThread` 因 map 被清空而 `targetPidFromProcessHandle` 返回 0，`shouldBlockRemoteThread(0, …)` 立即返回 false，注入不被阻断。
- **修复建议**: 改为 LRU 逐出最旧条目；或在 `targetPidFromProcessHandle` 失败时强制重开句柄获取 PID。
- **修复日期**: 2026-07-30
- **修复方式**: 新增 `std::deque<std::uintptr_t> gProcessHandleLru` 辅助队列记录句柄插入顺序，`recordProcessHandle` 在 `gProcessHandleTargets.size() > kMaxTrackedProcessHandles` 时从队列头部弹出最旧条目并从 map 中删除该单个条目，替代原来的 `clear()` 全表清空，阻断"填满表→清空→后续注入不被阻断"的攻击链。新增 `#include <deque>` 头文件。
- **验证**: 2026-07-30 构建验证：file_hook_detours.dll 134144 bytes 编译链接成功（CMake + v145 工具集）。

---

### VUL-051: file_hook 管道名来自环境变量可被重定向至攻击者管道

- **严重等级**: High
- **漏洞类型**: 防护绕过 / 中间人
- **影响模块**: `native/file_hook/src/file_hook_dll.cpp`
- **状态**: Fixed
- **位置**: `readPipeName` (L126-133)，被 `sendPayload` (L533) 和 `heartbeatThreadProc` (L497) 调用
- **描述**: Hook DLL 从被注入进程的环境变量 `ANXIN_HOOK_PIPE` 读取管道名。被注入进程的环境块由其父进程控制。恶意进程可设置 `ANXIN_HOOK_PIPE=\\.\pipe\evil` 指向攻击者管道，接收全部 hook 上报并回复 ACK 维持 hook 存活，真实服务端对该进程无可见性。
- **修复建议**: 管道名应硬编码或通过受保护的共享内存/注册表（仅 SYSTEM 可写）下发，不信任被注入进程的环境变量。
- **修复日期**: 2026-07-30
- **修复方式**: `readPipeName` 不再读取环境变量 `ANXIN_HOOK_PIPE`，直接返回硬编码常量 `kDefaultPipeName`（`\\\\.\\pipe\\anxin_security_filehook`）。被注入进程的环境块由其父进程控制，硬编码管道名杜绝了恶意父进程通过环境变量重定向 hook 上报到攻击者管道的中间人攻击。
- **验证**: 2026-07-30 构建验证：file_hook_detours.dll 134144 bytes 编译链接成功。

---

### VUL-052: file_hook 阻断后目标进程可能永久冻结

- **严重等级**: High
- **漏洞类型**: 拒绝服务 / 不可恢复状态
- **影响模块**: `native/file_hook/src/file_hook_dll.cpp`
- **状态**: Fixed
- **位置**: `HookCreateRemoteThreadImpl` (L1156-1206)、`HookCreateRemoteThreadExImpl` (L1296)、`HookNtCreateThreadExImpl` (L1444)
- **描述**: 阻断流程为 `suspendTargetProcessForDecision` → `sendProcessInjectionNotice` → 若恢复失败（句柄权限不足、进程已退出），无重试、无看门狗、无超时恢复。目标进程将永久挂起。与 VUL-051 配合，攻击者干扰管道通信使上报失败，目标进程被永久冻结。
- **修复建议**: 恢复失败时启动看门狗线程定时重试；或在挂起前注册最终一定会执行的恢复路径。
- **修复日期**: 2026-07-30
- **修复方式**: 新增 `resumeWatchdogThreadProc` 看门狗线程和 `ResumeWatchdogParams` 结构。阻断流程中 `NtResumeProcess` 失败时，将目标 PID 封装为 `ResumeWatchdogParams` 启动看门狗线程，线程在 `kMaxResumeRetries` 次内每 `kResumeRetryIntervalMs` 毫秒重试打开句柄并恢复进程，确保即使主流程恢复失败，目标进程也不会永久挂起。看门狗线程参数通过 `unique_ptr` 管理生命周期，避免泄漏。
- **验证**: 2026-07-30 构建验证：file_hook_detours.dll 134144 bytes 编译链接成功。

---

### VUL-053 ~ VUL-070（Medium 级别摘要）

以下 Medium 级别漏洞的详情见各文件对应位置：

- **VUL-053** [Medium] `IOCTL_ANXIN_ADD_WINSTA` 未调用 `IsCallerAuthorizedForWinsta()` 授权检查（driver.c:1145-1154）。当前 `ANXIN_ENABLE_WINSTA_OBCALLBACK` 默认未定义，漏洞不可直接利用。
- **VUL-054** [Medium] `AddProtectedPid` 不验证 PID 是否存在、是否属于本产品进程。授权调用方可预先添加空闲 PID，等待 PID 重用后新进程自动获得保护列表身份（driver.c:392-414）。
- **VUL-055** [Medium] `IMAGE_EVENT_PATH_CHARS=260` 截断长 NT 路径，截断后路径可能匹配信任规则前缀，导致用户态信任决策错误（driver.c:312-313）。
- **VUL-056** [Medium] `driver.inf` 未为服务注册表键设置 DACL，AnXinFileProtect 未启动时服务键可被修改（driver.inf:42-48）。
- **VUL-057** [Medium] 注册表保护 60 秒宽限期内除 Delete 外全部 fail-open 放行，攻击者可修改 ImagePath/DACL（minifilter.c:247,385,811-814）。
- **VUL-058** [Medium] `MinifilterPreSetInformation` 的 `FileRenameInformation`/`FileLinkInformation` 仅检查源路径，未检查目标路径，可将非保护文件重命名到受保护目录（minifilter.c:1117-1152）。
- **VUL-059** [Medium] `MinifilterPreFileSystemControl` 仅拦截 6 种 FSCTL，未拦截 `FSCTL_FILE_LEVEL_TRIM`（SSD TRIM 可清零文件数据）等（minifilter.c:1166-1173）。
- **VUL-060** [Medium] NetFilter 的 `SET_CONFIG`/`SET_RULES`/`SET_DOMAINS`/`SET_LIMITS`/`SET_VERDICT`/`FLUSH_CACHE`/`GET_STATS` IOCTL 未校验调用方是否为接管进程（net_filter/driver.c:306-365）。
- **VUL-061** [Medium] NetFilter `AnxStatAcquire` 为每个新进程创建统计节点无全局上限，可导致非分页池耗尽（net_filter/rules.c:920-1003）。
- **VUL-062** [Medium] NetFilter `SelfPid` 未校验可被任意管理员设置为豁免任意进程流量（net_filter/driver.c:122-170, callouts.c:405-407）。
- **VUL-063** [Medium] NetFilter `DecisionId` 顺序递增且 `AnxPendingResolve` 不校验调用方，可伪造裁决批量放行/拦截挂起连接（net_filter/pending.c:292,328-382, driver.c:172-184）。
- **VUL-064** [Medium] file_hook 心跳 ACK 用 `"ok"` 子串匹配，任何含 "ok" 的消息都会被误判为 ACK 成功（file_hook_dll.cpp:483-484）。
- **VUL-065** [Medium] file_hook 诊断文件无安全描述符且 `FILE_SHARE_WRITE` 允许并发写入，可被日志投毒（file_hook_dll.cpp:826-833）。
- **VUL-066** [Medium] file_hook `isProtectedProcessNameW` 仅按文件名匹配（如 `lsass.exe`），攻击者将恶意程序命名为 `lsass.exe` 可获得"不可挂起"豁免（file_hook_dll.cpp:283-307）。
- **VUL-067** [Medium] file_hook `normalizePathW` 对盘符路径直接返回不解析 `..`，与 VUL-005 同类问题（file_hook_dll.cpp:212-218）。
- **VUL-068** [Medium] file_hook 注入器仅检查 DLL 文件存在不校验路径合法性，相对路径可触发 DLL 搜索顺序劫持（file_hook_injector.cpp:194-248,282-292）。
- **VUL-069** [Medium] file_hook 注入器 `OpenProcess` 不校验目标是否为系统关键进程，可注入 lsass.exe 等（file_hook_injector.cpp:259-262）。
- **VUL-070** [Medium] file_hook `pruneInjectionChainsLocked` O(n²) 剪枝在持锁时执行，1024 条目约 100 万次比较导致 CPU 耗尽；刷量可驱逐合法链条目（file_hook_dll.cpp:658-673）。

---

### VUL-071 ~ VUL-090（Low 级别摘要）

以下 Low 级别漏洞为防御性编码或信息泄露问题：

- **VUL-071** [Low] `IOCTL_ANXIN_QUERY_PIDS` 未调用授权校验，泄露受保护 PID 列表和数量（driver.c:1119-1143）。
- **VUL-072** [Low] `DriverEntry` 错误清理路径未清理已注册的 Thread 通知和 Ob callbacks（driver.c:1509-1526）。
- **VUL-073** [Low] `ObRegisterCallbacks(Thread)` 失败被标记为 non-fatal 但 status 未重置，线程保护静默失效（driver.c:1434-1441）。
- **VUL-074** [Low] Thread 与 WinSta ObCallback 共用 Altitude "325801"，同时启用时第二个注册必失败（driver.c:1430,1469）。
- **VUL-075** [Low] Debug 构建中多处 `DbgPrint` 输出内核指针（ImageBase、对象指针）、PID、access mask，泄露内核地址辅助绕过 ASLR（driver.c 多处, minifilter.c 多处）。
- **VUL-076** [Low] `build_driver.bat` 未调用 signtool 签名，生产部署缺少签名路径（build_driver.bat:80-86）。
- **VUL-077** [Low] `IsAnxinProcess` 当 `fullPath->Length - targetName.Length == 1` 时 `tailChars` 下溢为 0xFFFF，潜在越界读（driver.c:560-562）。
- **VUL-078** [Low] `IsKernelDriverFile` 纯后缀匹配，攻击者可在任意目录创建 `system32\drivers\AnXinProcProtect.sys` 获得误保护（minifilter.c:894-932）。
- **VUL-079** [Low] `PortConnect` 中 `g_ClientPort` 检查与赋值无锁，两个授权进程同时连接可能导致端口句柄泄漏（minifilter.c:1231-1237）。
- **VUL-080** [Low] `RegProtectCallback` IRQL 检查 `> APC_LEVEL` 允许 APC_LEVEL(1) 时继续，但 `CmCallbackGetKeyObjectIDEx` 要求 `PASSIVE_LEVEL(0)`（minifilter.c:806,626）。
- **VUL-081** [Low] `FpmRemovePath` 不加尾部反斜杠与 `FpmAddPath` 不对称，`RtlCompareUnicodeString` 永不匹配，已添加路径无法删除（minifilter.c:1285-1301 vs 1260-1284）。
- **VUL-082** [Low] NetFilter `g_ObjectsAdded` 普通 BOOLEAN 无锁保护，延迟初始化线程和 BFE 回调并发时可能重复添加 WFP 对象（wfp.c:104-106）。
- **VUL-083** [Low] NetFilter IPv6 地址字段 `byteArray16` 未做 NULL 检查直接解引用，边缘场景可导致蓝屏（callouts.c:269-272,662-663）。
- **VUL-084** [Low] NetFilter `PendingCount` 上限检查与递增不在同一原子操作内，多核并发可超过 `ANX_NET_MAX_PENDING` 上限（pending.c:279-311）。
- **VUL-085** [Low] NetFilter 限速路径同时设置 `FWPS_STREAM_ACTION_DEFER` 和 `FWP_ACTION_BLOCK+ABSORB`，语义矛盾可能导致数据丢失而非延迟（callouts.c:852-855）。
- **VUL-086** [Low] NetFilter 令牌桶补充值 `(limit/1000)*elapsed` 在极端配置（`BytesPerSecIn=UINT64_MAX`）下强转 `LONG64` 变负数（rules.c:1114-1119）。
- **VUL-087** [Low] file_hook `DllMain` 中 `CreateThread` 创建心跳线程返回值未检查，失败时 hook 永久驻留无自卸载（file_hook_dll.cpp:1678）。
- **VUL-088** [Low] file_hook `CMakeLists.txt` 未显式启用 `/guard:cf`（Control Flow Guard），降低 ROP/JOP 攻击防护（CMakeLists.txt）。
- **VUL-089** [Low] `reflective_load_real_dll` PE 解析无边界检查：ILT 遍历无上界、ordinal 索引无 `>= NumberOfFunctions` 校验、RVA 无 `>= SizeOfImage` 校验（reflective_load_real_dll.cpp:680-711,780-805）。
- **VUL-090** [Low] `peb_unlink_real_dll` PEB LDR 链表操作无并发保护，其他线程加载/卸载 DLL 时链表可能损坏（peb_unlink_real_dll.cpp:367-440）。

---

### VUL-091: FileProtect PreWrite 路径在 DISPATCH_LEVEL 调用 ExAcquireFastMutex 导致蓝屏

- **严重等级**: Critical
- **漏洞类型**: IRQL 违规 / 蓝屏 (BSOD)
- **影响模块**: `native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: L1037 (`ExAcquireFastMutex`), L996-1010 (`IsFileProtectedByPath`), L1186-1199 (`MinifilterPreWrite`)
- **描述**: `MinifilterPreWrite` 调用 `IsFileProtectedByPath` → `IsPathProtected`，后者在 L1037 调用 `ExAcquireFastMutex(&g_PathListLock)`。`ExAcquireFastMutex` 要求调用方 IRQL <= APC_LEVEL，但 Windows 缓存管理器（Cache Manager）的 write-behind 线程会在 DISPATCH_LEVEL 发起 IRP_MJ_WRITE，此时 FltMgr 会以 DISPATCH_LEVEL 调用 PreWrite 回调。在 DISPATCH_LEVEL 获取 FastMutex 会立即触发 IRQL_NOT_LESS_OR_EQUAL (BugCheck 0xA) 蓝屏。
- **代码片段**:
  ```c
  // L1186-1192: PreWrite 入口
  FLT_PREOP_CALLBACK_STATUS MinifilterPreWrite(PFLT_CALLBACK_DATA Data, ...)
  {
      if (g_ShuttingDown) return FLT_PREOP_SUCCESS_NO_CALLBACK;
      if (!IsFileProtectedByPath(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
      // ...
  }

  // L1022-1037: IsPathProtected 内部
  BOOLEAN IsPathProtected(PUNICODE_STRING FilePath)
  {
      // ...
      ExAcquireFastMutex(&g_PathListLock);  // ← DISPATCH_LEVEL 下必蓝屏
      // ...
  }
  ```
- **攻击向量**: 任何进程对受保护路径（或驱动文件路径）发起写操作，若该写请求由缓存管理器 write-behind 线程在 DISPATCH_LEVEL 发出，即触发蓝屏。攻击者可通过大量缓冲文件写入（触发 cache manager 延迟写回）可靠复现。
- **修复建议**: 将 `g_PathListLock` 从 FAST_MUTEX 改为自旋锁（KSPIN_LOCK），或在 PreWrite 入口检查 `KeGetCurrentIrql() > APC_LEVEL` 时跳过路径列表查询（仅做 IsKernelDriverFile 的无锁后缀匹配）。注意 `IsPathProtected` 内部在栈上分配 1040 字节缓冲区（`WCHAR buf[MAX_PATH_LENGTH]`），在 DISPATCH_LEVEL 下栈空间也需评估。
- **修复日期**: 2026-07-30
- **修复方式**: `MinifilterPreWrite` 入口新增 `KeGetCurrentIrql() > APC_LEVEL` 分支：高 IRQL 下仅执行无锁的 `IsKernelDriverFile` 后缀匹配保护驱动文件，跳过 `IsPathProtected`（FastMutex）和 `IsCallerAuthorized`（SeLocateProcessImageName）。高 IRQL 下仅放行 System（PID 4，write-behind 线程上下文），非 System 写驱动文件 fail-closed 拒绝。安全性保证：非授权进程在 PreCreate（PASSIVE_LEVEL）已被拦截，无法获得受保护文件的可写句柄。

---

### VUL-092: FileProtect PreWrite 路径在 DISPATCH_LEVEL 调用 SeLocateProcessImageName 导致蓝屏

- **严重等级**: High
- **漏洞类型**: IRQL 违规 / 蓝屏 (BSOD)
- **影响模块**: `native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **位置**: L538 (`SeLocateProcessImageName`), L507-587 (`IsCallerAuthorized`), L1193 (PreWrite 调用点)
- **描述**: `MinifilterPreWrite` 在 L1193 调用 `IsCallerAuthorized()`，该函数在 L538 调用 `SeLocateProcessImageName(PsGetCurrentProcess(), &fullPath)`。`SeLocateProcessImageName` 文档明确要求 PASSIVE_LEVEL，但 write-behind I/O 使 PreWrite 运行在 DISPATCH_LEVEL。即使 VUL-091 的 FastMutex 问题被修复（使 `IsFileProtectedByPath` 不再蓝屏），执行流仍会到达 `IsCallerAuthorized` 并在此处触发 IRQL_NOT_LESS_OR_EQUAL (BugCheck 0xA)。
- **代码片段**:
  ```c
  // L1192-1193: PreWrite 中连续调用
  if (!IsFileProtectedByPath(Data)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
  if (IsCallerAuthorized())        return FLT_PREOP_SUCCESS_NO_CALLBACK;

  // L538: IsCallerAuthorized 内部
  status = SeLocateProcessImageName(proc, &fullPath);  // ← 要求 PASSIVE_LEVEL
  ```
- **攻击向量**: 与 VUL-091 相同。若 VUL-091 被单独修复（如加 IRQL 检查跳过路径列表），攻击流量仍会到达此处蓝屏。两个漏洞必须同时修复。
- **修复建议**: 在 PreWrite 中检查当前 IRQL：若 > APC_LEVEL，跳过 `IsCallerAuthorized`（write-behind 线程的发起进程是 System PID 4，已在 L520 被快速放行），或使用 `PsGetProcessImageFileName`（15 字节 ANSI，任意 IRQL 安全）做保守拒绝。注意 PreSetInformation / PreFileSystemControl / PreAcquireForSectionSync 始终在 PASSIVE_LEVEL 调用，不受此问题影响。
- **修复日期**: 2026-07-30
- **修复方式**: 与 VUL-091 同一修复。高 IRQL 分支完全跳过 `IsCallerAuthorized`，不再到达 `SeLocateProcessImageName`。

---

### VUL-093: NetFilter FwpsPendClassify0 失败后对未挂起分类调用 FwpsCompleteClassify0

- **严重等级**: Low
- **漏洞类型**: API 误用 / 潜在不稳定
- **影响模块**: `native/net_filter/src/callouts.c`
- **状态**: Fixed
- **位置**: L501-508 (`FwpsPendClassify0` 失败路径)
- **描述**: 当 `FwpsPendClassify0` 失败时（L502），代码调用 `AnxPendingResolve(decisionId, ANX_NET_ACTION_ALLOW, 0, 0)` 来清理已登记的 pending entry。`AnxPendingResolve` 内部调用 `AnxPendingCompleteEntry`，后者执行 `FwpsCompleteClassify0(Entry->ClassifyHandle, ...)` + `FwpsReleaseClassifyHandle0(...)`。但 `FwpsCompleteClassify0` 的文档要求仅用于已成功挂起（`FwpsPendClassify0` 返回成功）的分类。对未挂起的分类调用此函数属于未定义行为，可能导致 WFP 内部状态不一致。classify handle 本身通过此路径正确释放，不存在泄漏。
- **代码片段**:
  ```c
  // L501-508
  status = FwpsPendClassify0(classifyHandle, Filter->filterId, 0, ClassifyOut);
  if (!NT_SUCCESS(status)) {
      (void)AnxPendingResolve(decisionId, ANX_NET_ACTION_ALLOW, 0, 0);
      // AnxPendingResolve → AnxPendingCompleteEntry → FwpsCompleteClassify0 ← 不应对未挂起分类调用
      AnxApplyAction(ClassifyOut, ...);
      return;
  }
  ```
- **攻击向量**: `FwpsPendClassify0` 失败是极罕见的边缘场景（系统资源极度耗尽时），实际利用难度极高。理论上可能导致 WFP 引擎内部断言失败或后续分类行为异常。
- **修复建议**: 在 `FwpsPendClassify0` 失败路径中，不调用 `AnxPendingResolve`（它会走 Complete 路径），而是直接从 pending 链表摘除 entry、释放 handle（`FwpsReleaseClassifyHandle0`）、释放内存，跳过 `FwpsCompleteClassify0`。可新增 `AnxPendingCancel(decisionId)` 函数专门处理"已登记但未成功挂起"的回滚。
- **修复日期**: 2026-07-30
- **修复方式**: 新增 `AnxPendingCancel(DecisionId)` 函数（pending.c），仅从链表摘除 entry、调用 `FwpsReleaseClassifyHandle0` 释放句柄、释放内存，不调用 `FwpsCompleteClassify0`。callouts.c 的 `FwpsPendClassify0` 失败路径改为调用 `AnxPendingCancel` 替代 `AnxPendingResolve`。

---

### VUL-094: NetFilter 状态修改类 IOCTL 未校验调用方为已接管客户端（BYOVD）

- **严重等级**: Medium
- **漏洞类型**: 访问控制缺失 / BYOVD
- **影响模块**: `native/net_filter/src/driver.c`
- **状态**: Fixed
- **位置**: L317-376 (`AnxDispatchDeviceControl` switch 分支)
- **描述**: NetFilter 的 `AnxDispatchDeviceControl` 对 SET_CONFIG、SET_RULES、SET_DOMAINS、SET_LIMITS、SET_VERDICT、FLUSH_CACHE 等状态修改类 IOCTL 不校验调用方是否为已通过 GET_VERSION 握手的已接管客户端。设备 SDDL 限定 SYSTEM/Administrators 可打开设备，但任何 Admin 进程（包括被 BYOVD 攻击者利用的合法签名漏洞驱动提权后的进程）都能直接下发 SET_CONFIG 关闭防火墙、注入规则或伪造裁决，无需先完成版本握手。
- **代码片段**:
  ```c
  // 修复前：无接管检查
  case IOCTL_ANX_NET_SET_CONFIG:
      status = AnxIoctlSetConfig(Irp, irpSp);  // 任何 Admin 进程均可调用
      break;
  ```
- **攻击向量**: 攻击者通过 BYOVD（加载合法签名但有漏洞的驱动）获得 SYSTEM 权限后，打开 `\\.\AnXinNetFilter` 设备，发送 SET_CONFIG（Enabled=0）即可关闭全部网络防火墙保护，或发送 SET_RULES 注入全放行规则。无需与 AnXin 服务竞争接管。
- **修复日期**: 2026-07-30
- **修复方式**: 在 SET_CONFIG、SET_RULES、SET_DOMAINS、SET_LIMITS、SET_VERDICT、FLUSH_CACHE 六个状态修改类 IOCTL 分支入口添加 `AnxIsAttached()` 检查，未接管时返回 `STATUS_DEVICE_NOT_READY`。仅完成 GET_VERSION 握手的客户端进程能修改防火墙状态。GET_STATS 和 GET_EVENT 保持原有逻辑（GET_EVENT 已有独立的 `AnxIsAttached()` 检查）。

---

### VUL-095: 注册表保护迁移后应用自身服务键静默失去保护，且 Rust 仍调用已删除的 REG_KEY 死 IOCTL

- **严重等级**: High
- **漏洞类型**: 防护失效 / 自保绕过 / IOCTL 接口漂移
- **影响模块**: `native/file_protect/src/minifilter.c`, `src-tauri/src/utils/driver_client.rs`, `src-tauri/src/services/windows_service.rs`, `src-tauri/src/services/driver_install_service.rs`, `src-tauri/src/main.rs`
- **状态**: Fixed
- **描述**: 注册表自保功能已整体从 `AnXinProcProtect.sys`（`driver.c`）迁移到 `AnXinFileProtect.sys`（CmRegisterCallbackEx + 服务键 DACL + 硬编码服务键列表），迁移后 `driver.c` 删除了 REG_KEY IOCTL 族（0x806-0x808，即 `IOCTL_ANXIN_ADD_REG_KEY` / `REMOVE_REG_KEY` / `CLEAR_REG_KEYS`）。但：
  1. **Rust 侧仍定义并调用这 3 个死 IOCTL**：`driver_client.rs` 保留常量与方法（`add_reg_key`/`remove_reg_key`/`clear_reg_keys`），`windows_service.rs` 仍调用 `register_registry_protection()`，`driver_install_service.rs` 的 `release_self_protection()` 仍调用 `clear_reg_keys()`，`main.rs` 的 `--protect-dir` 分支仍调用 `protect_driver_services()`。调用必然返回 `STATUS_INVALID_DEVICE_REQUEST`，静默失败。
  2. **应用自身服务键 `AnXinSecurityService` 静默失去注册表保护**：迁移后 `AnXinFileProtect` 的硬编码保护列表只有 3 个驱动服务键（ProcProtect/FileProtect/NetFilter），不再包含应用自身服务键。迁移前该键由 Rust 通过（当时仍然有效的）REG_KEY IOCTL 登记保护；迁移删除 IOCTL 后，攻击者可直接改写 `HKLM\SYSTEM\CurrentControlSet\Services\AnXinSecurityService` 的 `ImagePath`/`Start` 禁用或劫持自保服务，无人拦截。
  3. **IOCTL 一致性测试失败**：`test_ioctl_constants_derived_from_driver_source` 直接解析 `driver.c` 的 CTL_CODE 实参，因 3 个 REG_KEY 常量在驱动源中已不存在而 panic。
- **攻击向量**: 本地高权限进程（或已突破文件自保、但尚未拿到服务键写入权限的攻击者）修改 `AnXinSecurityService` 服务注册表键的 `ImagePath`/`Start`，在系统重启或服务重启时以 SYSTEM 身份运行攻击者镜像，或直接禁用安芯自保服务。
- **修复日期**: 2026-08-07
- **修复方式**:
  1. `driver_client.rs`：删除 3 个死常量、3 个方法（`add_reg_key`/`remove_reg_key`/`clear_reg_keys`）及 `EXPECTED_IOCTLS` 测试表中对应条目；`test_ioctl_field_decomposition` 中「METHOD_NEITHER 三条」改为「两条」。新增注释说明 REG_KEY IOCTL 族已随注册表保护迁移到 `AnXinFileProtect.sys`，Rust 侧不得再定义/调用这些死常量。
  2. `windows_service.rs`：删除对 `register_registry_protection()` 的调用及整个函数（原保护 5 个注册表路径：服务键、卸载入口、制造商/产品键、WoW64 变体）。服务键改由 FileProtect 硬编码列表接管，其余路径不再保护（记录于「残余」）。
  3. `driver_install_service.rs`：`release_self_protection()` 只调 `clear_pids()`，不再调 `clear_reg_keys()`；删除 `protect_driver_services()` 函数，替换为注释说明驱动服务键现由 FileProtect 硬编码 CmCallback 列表保护。
  4. `main.rs`：`--protect-dir` 分支删除 `protect_driver_services()` 调用。
  5. `minifilter.c`：`MAX_PROTECTED_KEYS` 3→4，新增 `SVC_KEY_APP_STR = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\AnXinSecurityService"` 并加入 `RegProtectServiceKeysDacl` 的 `keys[]` 数组，使应用自身服务键重新受 CmRegisterCallback + DACL 保护。
- **验证**: `cargo check` 通过；`cargo test --lib` 346/346 通过（含 IOCTL 一致性测试）。`AnXinFileProtect.sys` 用 WDK/MSBuild 重建（SignMode=Off），dumpbin/strings 确认新产物（23552 bytes）中内嵌 `SVC_KEY_APP_STR` 完整宽字符串路径，且 4 个服务键宽字符串均在二进制中；Inf2Cat/InfVerif 报错为签名/catalog 相关（与代码无关，.sys 已生成），与 buglist VUL-091 等既有记录一致。
- **残余（评估完成 2026-08-07，维持不保护 / 接受风险）**: 迁移前由 `register_registry_protection()` 保护的卸载入口键、制造商/产品键、WoW64 变体（共 4 条：`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\AnXin Security`、`HKLM\SOFTWARE\AnXin Security` 及其 WOW6432Node 变体）在迁移后不再受注册表自保覆盖（FileProtect 硬编码列表只覆盖 4 个服务键）。**评估结论：既不纳入 FileProtect 硬编码列表，也不恢复按需登记机制，维持不保护。** 理由：
  1. **无安全价值**：这 4 条路径只存放安装器元数据（DisplayName/UninstallString/DisplayIcon/安装位置）。应用运行时配置为文件型（`config/app.json`，见 `models/config.rs::resolve_save_path`），服务参数在已受保护的 4 个服务键下，安装目录与 `unins000.exe` 已由文件 minifilter 在安装期经 `--protect-dir "$INSTDIR"` 保护（nsis-hooks.nsh POSTINSTALL）。能写这些键的攻击者已是管理员，本可写 Run 键等大量等价持久化位置，写这些键不获得任何额外能力；「隐藏卸载入口」仅为美观层，不削弱任何防护。
  2. **硬编码 DACL 会破坏卸载**：`RegProtectServiceKeysDacl()` 用 `ZwSetSecurityObject` 写入的 DACL 是持久的（SYSTEM=ALL / Everyone=READ），随键存活、不随驱动卸载消失；NSIS 卸载器以管理员用户身份运行（非 PID 4/SYSTEM、非 services.exe、非 anxin-security.exe，`IsRegCallerAuthorized()` 不覆盖），删除自身卸载入口将 ACCESS_DENIED，卸载流程中断。
  3. **硬编码 DACL 时机错位（只有代价没有收益）**：`RegProtectServiceKeysDacl` 只在驱动加载时（BootReinitCallback）对「已存在」的键设 DACL；这些键由安装器在驱动加载之后才创建，首次安装尚未重启的窗口内不会被保护，待下次启动被保护时又恰给卸载器制造 ACCESS_DENIED——对这批键既覆盖不了生命周期前段，又只会在后段添乱。
  4. **仅回调（不加 DACL）会破坏升级**：只要运行时把该键登记进 ObjectID 列表，升级/覆盖安装器（管理员用户、非授权调用方）重写卸载入口就会被 CmCallback 拦截，升级中断；旧按需机制同样存在此问题（升级前须先 `--uninstall-drivers` 清登记，增加耦合与失败面）。
  5. **恢复按需登记重造死握手**：REG_KEY IOCTL 族（0x806-0x808）已从 driver.c 彻底删除，FileProtect 为 minifilter（通信端口、无 IOCTL 设备）；恢复需重加 IOCTL 族 + 运行时 ObjectID 缓存 + Rust 侧 `add_reg_key` + 启动期接线，正是本次迁移刻意消除的「安装期静默失效」模式（旧 `register_registry_protection` 二次 connect 因共享冲突必然失败且仅被 eprintln 吞掉），违背迁移到确定性硬编码保护的方向。
  **后续方向**：若未来产品把敏感配置写入 `HKLM\SOFTWARE\AnXin Security`，应改用文件型/APPDATA+DPAPI 存储（复用 config.rs 现有文件型方案）而非扩充注册表自保列表；对卸载器反篡改的正确载体是文件层（`unins000.exe` 已随安装目录受文件自保保护），而非注册表。

---

### VUL-096: WebView2 前端进程未受进程保护（isChildOfProtected 遗漏 pending 队列）

- **严重等级**: High
- **漏洞类型**: 防护失效 / 自保绕过（前端依赖进程）
- **影响模块**: `native/driver/src/driver.c`
- **状态**: Fixed
- **修复日期**: 2026-08-13
- **修复方式**: `ProcessNotifyCallback` 的子进程保护判断 `isChildOfProtected`（driver.c:1637）覆盖 pending 待提升队列——父进程处于 2s 提升窗口（pending 队列）时其子进程同样登记保护（driver.c:1653-1656），消除提升窗口内产生的 webview 子进程永不受保护问题。
- **描述**: 进程自保的 `ProcessNotifyCallback`（driver.c:1230）对子进程继承判断用 `isChildOfProtected`（driver.c:1270），它只查**已提升（fully-promoted）保护列表** `IsProtectedPidTry`，不查 **pending 待提升队列**。进程创建后需经 `PROMOTION_DELAY_MS = 2000`（driver.c:168）的 DPC 延迟才提升进保护列表；UI 进程（anxin-security.exe）启动后立刻创建 webview 子进程，这些子进程在 2s 提升窗口内产生，父进程当时不在保护列表 → 子进程**永不被注册保护**。
- **攻击向量**: 本地任意进程执行 `taskkill /f /im msedgewebview2.exe` 即可一次性终止软件前端所依赖的全部 WebView2 进程（browser/renderer/GPU/utility），导致前端界面崩溃/降级。与 TER-05（VUL-100）组合，可先杀 UI 再杀 webview，完整瘫痪前端。
- **验证（2026-08-13 来宾实测）**: TER-03 `taskkill /f /im msedgewebview2.exe` 成功终止全部 7 个 webview 进程（保护有效时 UI/service 的 taskkill 均被拒）。对照：受保护 PID 的 taskkill/TerminateProcess/NtSuspendProcess/NtSuspendThread/DebugActiveProcess 全部被拒（TER-01/02/04、SUS-01/02/04），唯独 webview 子进程无任何拦截。
- **修复方向**: `isChildOfProtected` 需同时检查 pending 队列（对父进程在 pending 中的情况同样登记子进程），或将 `PROMOTION_DELAY_MS` 改为父进程的"保护作用域"传播（子进程继承父进程保护状态），消除提升窗口内产生的子进程漏洞。

---

### VUL-097: 安装目录文件保护运行期注册未生效，exe 未运行时可直接删除/覆盖安装目录文件

- **严重等级**: High
- **漏洞类型**: 防护失效 / 自保绕过（软件本体文件）
- **影响模块**: `src-tauri/src/services/windows_service.rs`、`src-tauri/src/utils/driver_client.rs`、`native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **修复日期**: 2026-08-13
- **修复方式**: Rust 侧 `register_file_protection_paths`（driver_client.rs）改为独立线程 + 有效回复缓冲（4 + MAX_PROTECTED_PATHS*520*2）+ 8s 超时守卫发送 `FpmAddPath`（原来主线程 NULL 缓冲调用在 FLTLIB.DLL 内 AV），安装目录 NT 路径运行期注册生效；2026-08-13 重测安装目录 `anxin-security.exe` 的 DEL / OVERWRITE / RENAME 全部 DENIED。
- **描述**: 安装目录文件保护依赖服务启动时 `register_file_protection()` 经 `FilterConnectCommunicationPort` + `FpmAddPath` 把安装目录 NT 路径登记进 AnXinFileProtect minifilter。实测该登记**在运行期未生效**：minifilter 只对 3 个 .sys 驱动文件（boot-time `IsKernelDriverFile` 后缀匹配）生效，对安装目录文件无任何拦截。
- **攻击向量**: 本地管理员在 `anxin-security.exe` 未运行时可直接 `del C:\Program Files\AnXinSecurity\anxin-security.exe`（实测成功）或 `echo evil >` 覆盖成 7 字节文件（实测成功），篡改/删除软件本体可执行文件。即使 exe 运行时 rename 被 OS 镜像锁拦下，进程停止后立即失效。
- **验证（2026-08-13 来宾实测）**: UI+service 被 TER-05 终止后，`del /f` 安装目录 exe 返回成功（EXISTS_AFTER=False），随后 echo 覆盖成功（SIZE=7）。与 APP-05（rename 成功）、APP-07（新建文件成功）一致。Rust 侧 `register_file_protection_paths` 对 `FpmAddPath` 的 send_result 有错误检查（driver_client.rs:71），故注册失败会返回 Err 但仅被 `init_driver_protection` eprintln 吞掉（非致命）；`--query-protected-paths` 又因 FpmQueryPaths 挂起（见 VUL-102）无法自证，最终表现为静默失效。根因待抓 DbgPrint 定位：可能是服务启动时 minifilter 端口尚未就绪、FpmAddPath 消息结构不匹配、或路径匹配逻辑失效。
- **修复方向**: ① 让 `register_file_protection` 失败**非静默**（进事件日志/持久化状态）；② 修复 FpmQueryPaths 以便自证；③ 卸载期/运行期补抓 DbgPrint 确定 FpmAddPath 具体失败点；④ 考虑把安装目录也纳入 boot-time 硬编码保护（与 .sys 同级），消除运行时注册依赖。

---

### VUL-098: 驱动服务键注册表保护运行时仅 2/4 键生效，AnXinSecurityService 与 AnXinNetFilter 键可被管理员删除

- **严重等级**: High
- **漏洞类型**: 防护失效 / 自保绕过（驱动注册表 + 应用服务键）
- **影响模块**: `native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **修复日期**: 2026-08-13
- **修复方式**: `RegProtectCallback` 改用 `CmCallbackGetKeyObjectIDEx` 稳定 ObjectID + 按路径名 `IsRegProtectedKeyPathName` 识别受保护键，不再依赖 boot 期 ObjectID 缓存是否成功，4 个服务键运行时 DACL / 拦截全生效；2026-08-13 重测 `reg delete` 4 键（含 AnXinSecurityService/AnXinNetFilter）+ `sc delete` 3 驱动键全部 DENIED。
- **描述**: `RegProtectServiceKeysDacl`（minifilter.c:709-833）对 4 个服务键（ProcProtect/FileProtect/NetFilter/App）统一执行 ZwOpenKey → ObReferenceObjectByHandle → CmCallbackGetKeyObjectIDEx 缓存 ObjectID → ZwSetSecurityObject 设 DACL（SYSTEM=ALL / Everyone=KEY_READ）。实测运行期**只有 ProcProtect 与 FileProtect 两个键获得 DACL/ObjectID**，AnXinSecurityService 与 AnXinNetFilter 键无保护。部署的 AnXinFileProtect.sys（30976 字节，2026-08-08 构建）**确实内嵌 4 个键的 UTF-16LE 路径字符串**（字节级 grep 证实 SVC_KEY_APP_STR 与 SVC_KEY_NETFILTER_STR 均在二进制中），即 VUL-095 的修复已部署，但运行时对该 2 键未生效——VUL-095 声称的对 AnXinSecurityService 键的修复实际未落地。
- **攻击向量**:
  - 本地管理员 `reg delete HKLM\SYSTEM\CurrentControlSet\Services\AnXinSecurityService` 直接删除应用服务键（实测 REG-01del "操作成功完成"），服务自启动配置被清空，重启后自保服务不再拉起。
  - `sc delete AnXinNetFilter`（驱动停止时）删除网络防火墙驱动服务键（实测 UNL-06 SVCKEY EXISTS=False），WFP 防火墙驱动无法再随系统启动。
- **验证（2026-08-13 来宾实测）**: `Get-Acl` 确认 ProcProtect/FileProtect 键 DACL 为 minifilter 设置值（SYSTEM Full + Everyone ReadKey）；AnXinSecurityService/AnXinNetFilter 键无该 DACL 且可删。根因待抓 DbgPrint：`RegProtectServiceKeysDacl` 对该 2 键的 `ZwOpenKey(READ_CONTROL|WRITE_DAC)` 或 `ObReferenceObjectByHandle` 失败被 `continue` 跳过（该键在调用时状态异常，或启动期键尚未按最终形态就绪）。
- **修复方向**: 抓 DbgPrint 确认 2 键跳过点；提高 DACL/回调对"键后建/重建"的健壮性（在 `RegNtPreCreateKeyEx` 中拦截对 4 个受保护键的重建，或对服务键变更作独立 ObjectID 重缓存）；修复后重测 4 键删除拦截。

---

### VUL-099: IOCTL_ANXIN_SET_DIAG 无调用方授权校验，任意管理员可关闭 Ob 进程/线程自保护

- **严重等级**: Critical
- **漏洞类型**: 授权缺失 / 自保绕过（直接关闭内核保护）
- **影响模块**: `native/driver/src/driver.c`
- **状态**: Fixed
- **修复日期**: 2026-08-13
- **修复方式**: SET_DIAG 处理器增加 `IsCallerFamilyTry` 调用方授权校验（driver.c:1914），仅受信族系（完整路径 `\anxinsecurity\anxin-security.exe` 等）可置 DIAG 标志；非授权进程 `DeviceIoControl` 被拒。2026-08-13 重测：非授权（test）进程打开 `\\.\AnXinProcProtect` 设备被 DACL 拒绝，POST-DIAG 后 taskkill 受保护 app 仍 DENIED。
- **描述**: `IOCTL_ANXIN_SET_DIAG(0x80A)` 处理器（driver.c:1914-1923）直接 `g_DiagFlags = *(PULONG)Irp->AssociatedIrp.SystemBuffer`，**无任何调用方授权校验**。`DIAG_DISABLE_AUTOPROTECT(0x1)` / `DIAG_DISABLE_LOADIMAGE(0x2)` / `DIAG_DISABLE_OBPROCESS(0x4)` / `DIAG_DISABLE_OBTHREAD(0x8)` 中，置位 0x4/0x8 即关闭 Ob 回调对进程/线程的保护。设备 DACL 仅限定管理员可打开（VUL-033 修复后），但本测试威胁模型就是"本地高权限管理员 R3"，故该 IOCTL 对管理员完全可用，等价于管理员可一键关闭全部进程/线程自保护。
- **攻击向量**: 本地管理员 `DeviceIoControl(\\.\AnXinProcProtect, IOCTL_ANXIN_SET_DIAG, 0xF)` 关闭全部 Ob 保护后，`taskkill /f` 可终止任何受保护 PID（含 anxin-security 服务与 UI），再配合 sc stop/sc delete 完成卸载（详见 VUL-096/101 相关测试）。
- **验证（2026-08-13 来宾实测）**: SET_DIAG=0xF 后 `taskkill /f /pid <受保护 spoof 进程 1316>` 从 DENIED 变为成功终止；SET_DIAG=0x0 恢复后再次 DENIED。DeviceIoControl 返回 ok=True（IOCTL 码 0x22A028 = FILE_WRITE_DATA 分支）。
- **修复方向**: SET_DIAG 处理器增加与 ADD_PID 同级的调用方授权校验（VUL-043 修复模式：校验调用进程路径为 `anxin-security.exe` 且包含 `\anxinsecurity\` 组件），或移除 DIAG 功能对生产构建的暴露。

---

### VUL-100: Ob 进程授权仅按 14 字节 ANSI 文件名前缀匹配，名称伪装进程可终止受保护服务与 UI

- **严重等级**: Critical
- **漏洞类型**: 授权绕过 / 自保绕过（名称伪装）
- **影响模块**: `native/driver/src/driver.c`
- **状态**: Fixed
- **修复日期**: 2026-08-13
- **修复方式**: Ob 回调对授权进程的判定改由 `IsCallerFamilyTry`（driver.c:1446）按**完整路径**族系校验，仅保留前缀匹配作为快速排除、不作为授权依据；名称伪装（复制 powershell 为 `anxin-security.exe`）的非可信进程不再获得内核授权。2026-08-13 重测 SPOOF-STOP（Temp 伪装名进程 Stop-Process 受保护 app）返回 DENIED。
- **描述**: 进程保护 Ob 回调对"可信进程"的授权判定使用 EPROCESS.ImageFileName 的 **14 字节 ANSI 前缀匹配**（"anxin-security"），**无路径校验**。任何被命名为 `anxin-security.exe` 的进程（无论位于哪个目录、是否可信、是否由攻击者复制而来）都会被视为受信任，其 OpenProcess(PROCESS_TERMINATE) 等操作不会被 Ob 回调剥离权限。VUL-038（仅按可伪造进程文件名授予内核信任）标记 Fixed，但修复未覆盖本 Ob 授权路径——实测该按名授权仍在。
- **攻击向量**: 本地攻击者把 `powershell.exe` 复制成 `C:\Windows\Temp\anxin-security.exe` 并运行，该进程即可打开受保护服务/UI 进程的 PROCESS_TERMINATE 句柄并成功终止（不经过 Ob 回调拦截）。无需物理机、无需提权到 SYSTEM。
- **验证（2026-08-13 来宾实测）**: TER-05a/05b 用 spoofed `C:\Windows\Temp\anxin-security.exe`（实为 powershell）分别 `Stop-Process -Force` 终止了服务进程（PID 4680）与 UI 进程（PID 6140），两者均死亡；而普通进程（未伪装名）对受保护 PID 的 taskkill/TerminateProcess 全部被拒。
- **修复方向**: Ob 回调授权改为按**完整路径**校验（对受保护进程的授权访问者必须是全路径 `*:\...\anxinsecurity\anxin-security.exe`），与 minifilter 的 `IsCallerAuthorized` 对齐；名称前缀只能作为快速排除，不能作为授权依据。

---

### VUL-101: 卸载程序重启一次后残留 3 个驱动 .sys 文件（重启删除登记被仍在加载的 minifilter 拦截）

- **严重等级**: Medium
- **漏洞类型**: 卸载不彻底 / 清理失效
- **影响模块**: `build/nsis-hooks.nsh`、`src-tauri/src/services/driver_install_service.rs`、`native/file_protect/src/minifilter.c`
- **状态**: Fixed
- **修复日期**: 2026-08-13
- **修复方式**: 卸载时 `stop_and_delete_service` 改为用一次性 SYSTEM 计划任务（`schtasks /ru SYSTEM` 执行 `reg delete`）直接删 4 个服务注册表键。根因双层：① 驱动故意不注册 DriverUnload → sc stop 1052 → `sc delete` 对 RUNNING 服务只标记删除、键不落地；② 服务键被驱动设 DACL（SYSTEM 全控 / Everyone 只读），管理员 reg delete 被 DACL 拒绝（DACL 检查先于 CmCallback，授权窗口救不了）。SYSTEM 身份满足 DACL + 窗口内 CmCallback 放行 → 键删除必达；键删后重启 SCM 不再加载驱动，3 个 .sys 的 PFRO 重启删除成功。2026-08-13 重测"卸载 + 重启一次"全清：4 服务 gone、无 .sys、安装目录/卸载项 gone、无进程、PFRO 已消费。
- **描述**: 卸载流程在驱动服务仍加载时尝试 `remove_driver_file`（`std::fs::remove_file` 失败后走 `schedule_delete_on_reboot`，MoveFileExW + MOVEFILE_DELAY_UNTIL_REBOOT）与 NSIS `Delete /REBOOTOK`。实测卸载结束后 `HKLM\...\Session Manager\PendingFileRenameOperations` 中**没有任何 .sys 条目**（只有 NSIS 自身临时文件），重启一次后 3 个驱动文件 `AnXinProcProtect.sys`/`AnXinFileProtect.sys`/`AnXinNetFilter.sys` **全部残留**于 `C:\Windows\System32\drivers\`。根因：卸载时 AnXinFileProtect minifilter 仍加载（服务被 sc stop 拒，1052），其 boot-time `.sys` 后缀自保护（`IsKernelDriverFile`）拦截了 MoveFileExW/NSIS 对受保护 .sys 文件的重启删除登记，导致"重启后删除"从未被安排。卸载器 POSTUNINSTALL 的 Safe Mode 兜底提示未自动执行。
- **攻击向量**: 不适用（这是卸载器自身的清理缺陷）。但需与"只有卸载程序能彻底清除"需求对齐——若卸载后残留 .sys 被第三方（如另一 BYOVD 场景）利用或造成磁盘垃圾/合规问题。
- **验证（2026-08-13 来宾实测）**: `uninstall.exe /S` 退出码 0；卸载后 4 服务全部 1060、安装目录与卸载项删除、无残留进程；但 3 个 .sys 文件重启后仍存在（34184/30976/56064 字节）。控制组：驱动卸载后 `del /f` 三个 .sys 全部成功（证明文件本身可删，非"无法删除"，而是卸载器未安排删除）。
- **修复方向**: ① 在 FileProtect minifilter 卸载完成后（服务标记删除、驱动下次启动不再加载）再执行 .sys 重启删除——可改用 **RunOnce/ScheduledTask 在首次重启后以 SYSTEM 执行 `del`**，此时 minifilter 不再加载、文件可删；② 或让 minifilter 对"卸载者 anxin-security.exe --uninstall-drivers"放行 .sys 的 MoveFileEx 登记（授权路径校验后放行重启删除登记）；③ 修复后重测"卸载 + 重启一次"全清。

---

### VUL-102: FpmQueryPaths 诊断查询挂起（FilterSendMessage 无响应），`--query-protected-paths` 死锁

- **严重等级**: Low
- **漏洞类型**: 可用性 / 诊断失效（潜在 DoS）
- **影响模块**: `native/file_protect/src/minifilter.c`、`src-tauri/src/utils/driver_client.rs`
- **状态**: Fixed
- **修复日期**: 2026-08-13
- **修复方式**: 驱动侧 FpmQueryPaths 回复改紧凑格式（ULONG PathCount + 每路径 NUL 结尾 WCHAR 串），体积远小于旧定长 130KB 槽位版本（后者超过滤通信端口回复上限导致 FilterSendMessage 永久挂起）；Rust 侧 `query_file_protection_paths` 在独立线程发送 + 8s 超时守卫（mpsc recv_timeout）。2026-08-13 重测 `--query-file-protect` 0.22s 返回（不再挂起）。
- **描述**: `anxin-security.exe --query-protected-paths`（走 `query_file_protection_paths`，FpmQueryPaths=4）实测**挂起无响应**，`FilterSendMessage` 不返回。FpmQueryPaths 处理器（minifilter.c:1530-1553）在 `ExAcquireFastMutex(&g_PathListLock)` 下遍历并写输出缓冲，且不设置/返回正确的 `ReturnOutputBufferLength`；Rust 侧若输出缓冲过小或期望长度不一致，会导致 FilterSendMessage 阻塞或驱动侧不完成消息。
- **攻击向量**: 调用方线程被永久阻塞（本地调用方 DoS）；更重要的是诊断接口不可用导致文件保护状态无法自证（VUL-097 的注册失效因此更难排查）。
- **验证（2026-08-13 来宾实测）**: CLI 调用挂起超 120s，Invoke-Command 超时；需手动 kill 挂起进程。
- **修复方向**: 修复 FpmQueryPaths 的缓冲大小协商与 `ReturnOutputBufferLength`；或 Rust 侧加超时/异步退出；修好后用 `--query-protected-paths` 复核 VUL-097 的注册状态。

---

### VUL-103: 受保护进程线程的 OpenThread(THREAD_GET/SET_CONTEXT) 句柄可打开

- **严重等级**: Low
- **漏洞类型**: 防护缺口（线程劫持面）
- **影响模块**: `native/driver/src/driver.c`
- **状态**: Fixed
- **修复日期**: 2026-08-13
- **修复方式**: 线程 Ob 回调对受保护 PID 线程的权限剥离集合补入 `THREAD_GET_CONTEXT` / `THREAD_SET_CONTEXT` / `THREAD_QUERY_INFORMATION`（driver.c:245-249，与 THREAD_SUSPEND_RESUME/TERMINATE 同级）；2026-08-13 重测 OPEN-THREAD ctx 对受保护 app 线程返回 DENIED。
- **描述**: 进程/线程 Ob 回调对受保护线程的授权剥离不覆盖 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT/THREAD_QUERY_INFORMATION。实测对受保护 UI 进程的线程，`OpenThread(THREAD_GET_CONTEXT|THREAD_SET_CONTEXT|THREAD_QUERY_INFORMATION)` **成功**。本地攻击者取得句柄后可 `SetThreadContext` 劫持受保护线程执行流（配合注入面），或读线程上下文窃取栈/寄存器状态。
- **攻击向量**: 本地管理员对受保护 UI/服务进程的线程打开 GET/SET_CONTEXT 句柄，实施线程上下文劫持（虽 CreateRemoteThread/QueueUserAPC 已被 TER/INJ 测试证明失败，但 SetThreadContext 劫持独立于注入面）。
- **验证（2026-08-13 来宾实测）**: SUS-03 OpenThread(GET/SET_CONTEXT|QUERY_INFORMATION) 返回成功；对照 TER-04/SUS-01/INJ-01 等对进程句柄的访问均被剥离。威胁等级 Low：劫持需配合可执行代码投放，而注入面已封闭，实际利用难度高。
- **修复方向**: 线程 Ob 回调对受保护 PID 的线程追加剥离 THREAD_GET_CONTEXT/THREAD_SET_CONTEXT 权限（与 THREAD_SUSPEND_RESUME/THREAD_TERMINATE 一致）。

### VUL-104: AnXinProcMon 构建缺 /INTEGRITYCHECK，进程/线程回调注册被 CI 拒绝（0xC0000022）

- **严重等级**: High
- **漏洞类型**: 功能缺陷（关键采集回调静默缺失）
- **影响模块**: `native/proc_monitor/AnXinProcMon.vcxproj`（构建配置）
- **状态**: Fixed
- **修复日期**: 2026-08-14
- **修复方式**: `AnXinProcMon.vcxproj` 的 Debug/Release Link 段补 `<AdditionalOptions>/INTEGRITYCHECK %(AdditionalOptions)</AdditionalOptions>`；重编译后 dumpbin 验证 DLL characteristics 从 `0x4160` 变为 `0x41E0`（与 AnXinProcProtect.sys 一致）；VM 重部署后 GET_HEALTH 诊断位显示进程/线程/映像三回调全部注册成功（procErr=0x0）。
- **描述**: MSBuild WDK 构建的 AnXinProcMon.sys **缺少 IMAGE_DLLCHARACTERISTICS_INTEGRITY_CHECK（0x80）标志**。驱动本身能加载、minifilter/FltRegisterFilter/LoadImage 回调正常，但 `PsSetCreateProcessNotifyRoutineEx` 与 `PsSetCreateThreadNotifyRoutineEx` 返回 **0xC0000022（STATUS_ACCESS_DENIED）**——Windows 10 19044 的 CI（代码完整性）拒绝无完整性校验标志的驱动注册进程/线程通知回调（`PsSetLoadImageNotifyRoutine` 不受此限，故 IMAGE_LOAD 事件正常而 **CREATE/EXIT/REMOTE_THREAD 事件全部缺失**，EDR 溯源主干静默失效）。
- **攻击向量**: 无直接安全利用，但该缺陷导致进程生命周期采集静默失效：攻击者若察觉回调未注册（无 CREATE 事件），进程监控形同虚设；且 BYOVD 主动探针因收不到回报会误报失明（运维误导）。
- **验证（2026-08-14 来宾实测）**: 干净基线（8/13 检查点）部署后：GET_HEALTH DiagFlags=0x00040000（仅 image 注册）、进程/线程回调 err=0x22（截断诊断）/完整诊断 0x00000022（STATUS_ACCESS_DENIED）；`CreateDiag` 读事件流仅见 IMAGE_LOAD（evt=3）无 CREATE（evt=1）；补齐 /INTEGRITYCHECK 后 DiagFlags=0x07000000（三回调全部注册）、探针 4/4 CREATE 回报、延迟 0-94ms。
- **根因与同类教训**: 与 net_filter 当年 MSBuild WDK PE 问题同源（continuous-running.md 第 15 条：映像基址/GsDriverEntry/CFG/INTEGRITYCHECK 四项内核不兼容）；ProcProtect 手工 cl/link 构建自带 /INTEGRITYCHECK，ProcMon 用 MSBuild WDK 时需显式补充。

### VUL-105: 服务模式 IPC 唯一处理线程被批量扫描阻塞，状态刷新 broken-pipe、开关卡死、扫描无法取消

- **严重等级**: Medium
- **漏洞类型**: 本地可用性 / 线程管理缺陷（服务进程控制通道饥饿）
- **影响模块**: `src-tauri/src/services/ipc_server.rs`
- **状态**: Fixed
- **修复日期**: 2026-08-18
- **修复方式**: 把 `IpcServer::handle_client` 从「读循环线程上同步执行每个请求」改为「读循环只负责读入与分派，每个客户端连接创建**有界请求工作池**（`IPC_WORKERS_PER_CLIENT = 4`）并发执行请求」。请求在工作线程上执行，响应经线程安全的 `client.writer` 写回（客户端按 request id 匹配，天然支持乱序）。新增 `spawn_worker_queue`（按工厂为每个 worker 生成独立 handler，避免共享 handler 串行化）与 `execute_request`，并用 `catch_unwind` 兜住单个 handler panic。新增单测验证「长任务占住 worker 时短任务仍并发完成」。
- **描述**: 服务模式下，`SCAN_FILE`/`SCAN_BATCH` 用 `runtime_handle.block_on(async move { … engine.scan_file(…).await … })` 在**唯一的读循环线程**上整段执行批量/单文件扫描。扫描期间该线程既读不了新请求也答不了旧请求：UI 的 `GET_STATUS`（状态轮询）、三个监控开关（`SET_BEHAVIOR/PROCESS/FILE_MONITORING`）、甚至 `CANCEL_SCAN` 全部排队无人消费 → 客户端管道写缓冲积压，`FlushFileBuffers` 返回 `ERROR_BROKEN_PIPE (0x8007006D, 管道已结束)` 或 5s 超时；而状态/开关命令是同步 `#[tauri::command]`，反复失败让前端依赖它的处理停滞（开关卡死）。
- **攻击向量**: 本地可用性：用户进行大目录扫描时，服务端安全控制通道（状态查询、防护开关、取消扫描、防火墙裁决）在一段时间内不可用，无法取消扫描或实时调整防护；严重时 UI 反复 broken-pipe。非远程利用。
- **验证**: `cargo check` 通过；新增单测 `services::ipc_server::tests::worker_queue_runs_long_and_short_jobs_concurrently` 通过（0.25s）。服务模式真实扫描场景的手动复现/回归待部署 VM 实测后再在 continuous-running.md 定档为「已验证」。

---

### VUL-106: IPC 客户端身份校验仅按镜像文件名白名单，无安装目录/签名比对

- **严重等级**: Medium
- **漏洞类型**: 身份校验不足（同名伪装）
- **影响模块**: `src-tauri/crates/anxin-core/src/services/identity_verification_service.rs`
- **状态**: Open
- **发现日期**: 2026-08-23（三进程拆分安全复查）
- **漏洞描述**: `verify_pipe_client` 的客户端校验链为「镜像文件名白名单 + 交互会话 + SID + 完整性 ≥ Medium」，其中路径校验仅做文件名比对与排除 target 目录，**不校验安装目录，也不做 WinVerifyTrust 签名校验**。同一交互式会话内的 medium-integrity 恶意进程将自身可执行文件命名为白名单内名称即可通过校验，进而调用 `handle_interception`（放行/阻止任意被挂起进程）、`shutdown_service`（停止整个防护服务）等决策通道。三进程拆分将白名单从 `anxin-security.exe` 扩至含 `anxin-tray.exe`（identity_verification_service.rs ANXIN_EXE_NAMES），同名伪装面随之增大。
- **代码位置**: identity_verification_service.rs:77（ANXIN_EXE_NAMES）、is_valid_anxin_path、verify_pipe_client。
- **攻击向量**: 本地已执行恶意程序（medium integrity，同用户会话）→ 命名为 anxin-tray.exe → 连接 `\\.\pipe\Global\AnXinSecurityIPC` → 通过身份校验 → 提交拦截放行决策或请求停服。
- **修复方向**: 生产模式在文件名白名单之上增加强校验：① 客户端镜像父目录 == 服务自身安装目录；或 ② WinVerifyTrust 校验 AnXin 签名；两者任一失败即 fail-closed。开发模式维持现状（ANXIN_DEV_MODE=1）。

---

### VUL-107: Rust 依赖审计——sqlx 0.7.4 RUSTSEC-2024-0363（quick-xml/rsa 经产物验证不可达）

- **严重等级**: Low
- **漏洞类型**: 第三方依赖漏洞（cargo-audit 2026-08-23，RustSec advisory-db 1225 条）
- **影响模块**: `src-tauri/Cargo.lock`（anxin-core / anxin-security 依赖树，629 crate）
- **状态**: Accepted
- **发现日期**: 2026-08-23
- **审计结果**: 4 vulnerabilities + 23 unmaintained warnings。
  - quick-xml 0.39.2 ×2（RUSTSEC-2026-0194/0195, high DoS）：来自 tauri 的 Linux/macOS 跨平台链；Windows release 产物符号抽查 `quick_xml=False`，不可达。
  - rsa 0.9.10（RUSTSEC-2023-0071, medium Marvin timing）：同上跨平台链且上游无修复版；产物符号抽查 `rsa_=False`，不可达。
  - sqlx 0.7.4（RUSTSEC-2024-0363）：唯一直接依赖相关条目。该 advisory 为 wire-protocol 二进制误读（PG/MySQL），本项目仅用 SQLite 嵌入式驱动，实际可达性受限。
  - 23 条 unmaintained 警告：gtk/atk/gdk 系列为 Linux GUI 链（Windows 构建不含），paste/proc-macro-error/fxhash/unic-* 为宏工具类间接依赖，无可用替代修复。
- **处置决策**: 接受现状并持续观察。sqlx 0.7 → 0.8 涉及 API 大版本迁移（query_as 宏、ConnectOptions 等）与全量回归，单独立项评估而非顺手升级；tauri 后续版本升级时关注 quick-xml 是否随之进入 >=0.41。
- **复现命令**: `cargo install cargo-audit --locked && cargo audit`（在 src-tauri 下执行）
