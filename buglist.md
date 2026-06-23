# AnXinSecurity 安全漏洞清单

> 本文件记录项目中已发现的安全漏洞，需持续更新。
> 最后更新：2026-06-22

---

## 漏洞索引

| 编号 | 严重等级 | 漏洞类型 | 影响模块 | 状态 |
|------|---------|---------|---------|------|
| VUL-001 | Critical | DLL 注入路径未校验 | process_monitor_service | Open |
| VUL-002 | Critical | 命名管道无安全描述符 | hook_service | Open |
| VUL-003 | High | 签名验证跳过证书吊销检查 | trust_service / process_monitor_service | Open |
| VUL-004 | High | 隔离区原文件简单删除未安全擦除 | quarantine_service | Open |
| VUL-005 | High | 路径遍历：normalize_path 保留 `..` | path_policy_service | Open |
| VUL-006 | High | Tauri capability 权限过宽 | capabilities/default.json | Open |
| VUL-008 | Medium | 环境变量泄露加密密钥 | quarantine_service | Open |
| VUL-009 | Medium | NativeEngineService 手动实现 Send/Sync | native_engine_service | Open |
| VUL-010 | Medium | 签名缓存可被时间回拨欺骗 | trust_service | Open |
| VUL-011 | Medium | 拦截决策无审计日志 | interception_service | Open |
| VUL-013 | Medium | 错误信息泄露内部路径 | 多个模块 | Open |
| VUL-014 | Low | 进程监控 eprintln 输出路径信息 | process_monitor_service | Open |
| VUL-015 | Low | config 中残留测试规则 | config/etw_match_rules.json | Open |
| VUL-016 | High | ETW EVENT_RECORD 本地结构体布局错误导致实时注入检测失效 | etw/session / etw_service | Fixed |

| VUL-017 | High | 远程线程入口孤立信号误入自动挂起导致 cmd 控制链假死 | etw_service / risk_service / interception_service | Fixed |
| VUL-018 | High | ETW Image/load 设备路径验签失败导致系统 DLL 被误判为未签名注入模块 | etw_service / trust_service | Fixed |
| VUL-019 | High | ETW Image/load 事后挂起存在短时间执行窗口 | etw_service / interception_service / file_hook | Open |
| VUL-020 | High | 弱证据自动挂起导致拦截队列风暴和主页卡死 | snapshot_service / risk_service / interception_window | Fixed |

---

## 漏洞详情

### VUL-001: DLL 注入路径未校验

- **严重等级**: Critical
- **漏洞类型**: DLL 注入 / 路径注入
- **影响模块**: `src-tauri/src/services/process_monitor_service.rs`
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

---

### VUL-002: 命名管道无安全描述符

- **严重等级**: Critical
- **漏洞类型**: 未授权访问 / 提权
- **影响模块**: `src-tauri/src/services/hook_service.rs`
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

- **严重等级**: Low
- **漏洞类型**: 配置安全
- **影响模块**: `config/etw_match_rules.json`
- **位置**: L23-L35
- **描述**: ETW 匹配规则配置文件中包含测试规则，这些规则可能在生产环境中被意外启用，导致误报或规则引擎性能下降。测试规则应与生产规则分离，或通过明确的启用/禁用标志控制。

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
- **验证**: 已通过 `cargo test --manifest-path src-tauri\Cargo.toml fanout --lib --quiet`、`cargo test --manifest-path src-tauri\Cargo.toml realtime_rule_policy --lib --quiet` 和本地 `cargo check`。管理员 VM 运行态仍需短统计复测确认刷屏和数据库写入风暴消失。

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
- **状态**: Open
- **描述**: `Image/load` ETW 事件属于镜像已经加载后的通知。即使 `trusted_process_unsigned_image_load` 能够正确命中，目标 DLL 的 `DllMain` 或远程线程入口仍可能在 AnXinSecurity 完成验签、风险升级和 `NtSuspendProcess` 前已经执行。现场表现为“能告警/能挂起，但短生命周期 payload 有概率已经完成动作”。
- **攻击向量**: 注入载荷在 DLL attach 或远程线程入口中执行极短动作，然后迅速返回或自卸载；ETW 事件到达后再挂起宿主进程时，关键行为已经发生。
- **缓解状态**: 2026-06-19 已将 `InterceptionService::enqueue` 的顺序优化为先挂起、再查询 PID 身份和写恢复台账，减少 ETW 后置处置延迟；同日补上 APIHook 源头行为链检测/阻断。2026-06-20 进一步把 APIHook 处置对象从“拦截源头 PID”修正为“先挂起被注入目标 PID 并触发拦截窗口”：`file_hook_detours.dll` 在 `OpenProcess / VirtualAllocEx / WriteProcessMemory / CreateRemoteThread(Ex)` 形成强链路时，先尝试 `NtSuspendProcess(targetPid)`，再阻断 `CreateRemoteThread*` 并上报 `blocked=true`、`targetSuspended=true`；Rust `hook_service.rs` 按 `(source_pid, target_pid)` 聚合后以 `remote_thread_injection_target` 将目标 PID 推入 `InterceptionService::enqueue_pre_suspended`，避免二次挂起和恢复计数不对称。若原生侧挂起后上报失败、Rust 入队失败、应用退出中或目标属于 AnXin 控制链，会尝试恢复目标，避免无弹窗残留挂起。受控 `file_hook_injector.exe` 仍支持检测到 Hook 管道后自加载 Hook DLL，便于现场手工探测；AnXin 内部 APIHook watcher 调用注入器时通过 `ANXIN_FILE_HOOK_INJECTOR_SKIP_SELF_HOOK=1` 跳过自 Hook，避免布防动作自拦截。该缓解已通过单测、`cargo check`、x64/x86 CMake 构建和运行目录 DLL 哈希确认，但 VUL-019 仍保持 Open：任意短生命周期且尚未被用户态 APIHook 布防的外部注入器仍可能在 ETW `Image/load` 后置处置前完成执行，后续需要 ETW Threat Intelligence 或更低层回调来补第一时间源头信号。
- **后续修复方向**: 增加注入源头侧或文件落地侧前置拦截，例如对受保护宿主的可疑 `OpenProcess` / `VirtualAllocEx` / `WriteProcessMemory` / `CreateRemoteThread` 链路做更早的检测与拦截，或接入更靠前的 Windows 安全事件源；不要把 ETW `Image/load` 单独宣称为加载前阻断。

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
- **验证**: 已通过相关 Rust 单测、`cargo check`、`npm run typecheck` 和独立拦截窗口结构测试。尚未完成管理员桌面端到端复测，因此现场效果仍需重启应用后用 `interception_diagnostics.jsonl` 复核队列是否不再被弱证据刷屏。

