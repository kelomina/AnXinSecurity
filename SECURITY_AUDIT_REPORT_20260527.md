# AnXinSecurity 安全审计报告

**审计日期**: 2026-05-27
**审计范围**: Tauri 应用 (Rust 后端 + React 前端)
**审计目标**: 识别中等严重度及以上的已确认漏洞，且必须具备可演示的端到端利用路径

---

## 审计摘要

经过系统性审计，本代码库**未发现中等或更高严重度的已确认漏洞**。

本报告对以下攻击面进行了深入分析：
- 认证与访问控制
- 注入向量（SQL、命令执行、文件路径）
- 外部交互接口
- 敏感数据处理

所有高风险操作均具有适当的安全控制措施。

---

## 架构概述

| 组件 | 技术栈 | 信任边界 |
|------|--------|----------|
| 后端 | Rust + Tauri 2.0 | 进程内 IPC，通过 Tauri 命令调用 |
| 前端 | React + TypeScript | 用户界面，无直接系统访问 |
| 存储 | SQLite + DPAPI 加密 | 运行时列表受 Windows DPAPI 保护 |
| 原生组件 | C++ (Detours) | 进程注入，需高权限运行 |

**关键信任边界**：
- Tauri 命令层（Rust）是唯一可操作系统资源的入口
- 配置文件存储在 APPDATA，使用 Windows DPAPI 加密运行时数据
- 进程注入和监控是应用核心功能，需高权限运行

---

## 已审计攻击面详细分析

### 1. 认证与访问控制

#### 进程控制命令
**位置**: [src-tauri/src/commands/process.rs](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/process.rs)

| 命令 | 保护机制 | 评估结果 |
|------|----------|----------|
| `suspend_process` | 白名单保护（csrss.exe, smss.exe, wininit.exe, services.exe, lsass.exe）+ 自保护检查 | ✅ 安全 |
| `resume_process` | 白名单保护 + 自保护检查 | ✅ 安全 |
| `terminate_process` | 白名单保护 + 自保护检查 | ✅ 安全 |
| `start_process_watcher` | 需配置注入器和 DLL 路径 | ⚠️ 需注意 |

**分析**：
- 所有进程控制命令均实现了系统进程白名单保护
- 自保护检查防止操作当前进程
- 这是安全工具的**设计决策**，而非漏洞

#### 开发者设置
**位置**: [src-tauri/src/commands/dev_settings.rs](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/dev_settings.rs)

**发现 #1**: 密码验证逻辑存在缺陷（功能性问题，非安全漏洞）

- `dev_settings_save` 将密码哈希写入 `passwordHash` 字段（64字符 SHA-256 hex）
- `dev_settings_unlock` 从 `salt` 字段读取验证（仅为哈希前32字符）
- 实际影响：**密码验证功能在当前实现下会永久失败**

```rust
// dev_settings_save 写入：
"passwordHash": hash  // 64字符完整哈希

// dev_settings_unlock 读取：
let password_hash = dev.get("salt").and_then(|v| v.as_str()).unwrap_or("");
// 实际只取了前32字符
```

**利用路径**: 无（此缺陷导致功能不可用，而非安全绕过）
**严重度**: 不适用（功能缺陷，非安全漏洞）

---

### 2. 注入向量

#### SQL 注入
**评估**: ✅ **未发现漏洞**

所有数据库操作使用 `sqlx` 参数化查询：

```rust
// 示例：quarantine_service.rs
sqlx::query(
    r#"INSERT INTO quarantine_items (id, original_path, ...) VALUES (?, ?, ?, ...)"#
)
.bind(&id)
.bind(file_path)
// ...
```

**证据**：
- [quarantine_service.rs](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/quarantine_service.rs) - 所有查询使用 `.bind()` 参数化
- [process_monitor_service.rs](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/process_monitor_service.rs) - 无原始 SQL
- [trust_service.rs](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/trust_service.rs) - 使用参数化查询

#### Shell 命令注入
**评估**: ✅ **未发现漏洞**

- [system.rs](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/system.rs) 使用 `Command::new("wmic")` 硬编码参数，无用户输入拼接
- 进程注入器路径由配置提供，不经过用户输入

```rust
// system.rs - 安全实现
Command::new("wmic")
    .args(["cpu", "get", "name", "/format:value"])
```

#### 文件路径操作
**评估**: ✅ **已安全处理**

- ETW 事件中的文件路径经过 `normalize_path()` 标准化
- 目录遍历使用 `canonicalize()` 检测循环
- 深度保护限制为 32 层

**证据**：
- [path_policy_service.rs:233-255](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/path_policy_service.rs#L233-L255) - 路径规范化函数
- [fs.rs:80-84](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/fs.rs#L80-L84) - 循环检测
- [fs.rs:163](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/fs.rs#L163) - 深度限制

```rust
// 路径规范化
fn normalize_path(path: &str) -> String {
    // 转换为反斜杠、小写化、去除前缀
}

// 循环检测
if let Ok(canonical) = path.canonicalize() {
    if !visited.insert(canonical) {
        continue; // 已访问过，跳过
    }
}

// 深度保护
if depth > 32 {
    return;
}
```

---

### 3. 外部交互

#### ETW 事件处理
**评估**: ✅ **已安全处理**

- ETW 事件解析后使用 serde 反序列化验证
- 事件数据不直接用于文件操作
- 路径提取后经过规范化处理

**证据**：[etw/parser.rs](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/etw/parser.rs)

#### 命名管道通信
**评估**: ✅ **已安全处理**

- Hook 服务接收的 DLL 事件经过 JSON 解析验证
- 管道名称格式化为 `\\.\pipe\{}`，无注入风险
- 使用 `serde_json::from_str` 验证输入

**证据**：[hook_service.rs:200](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/hook_service.rs#L200)

```rust
if let Ok(event) = serde_json::from_str::<FileHookEvent>(trimmed) {
    events.push(event);
}
```

#### 网络请求
**评估**: ✅ **未发现外部通信**

代码库中无 HTTP/HTTPS 请求代码，无 Webhook 处理器，无第三方 API 调用。

---

### 4. 敏感数据处理

#### 运行时列表加密
**评估**: ✅ **良好实践**

- 排除项和允许列表使用 Windows DPAPI 加密
- 加密后存储在 `%APPDATA%\AnXinSecurity\runtime\`
- 支持从明文旧配置迁移

**证据**：[runtime_list_store.rs:115-149](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/runtime_list_store.rs#L115-L149)

```rust
fn protect_runtime_bytes(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    // 使用 CryptProtectData (DPAPI) 加密
    unsafe {
        CryptProtectData(&mut data_blob, PCWSTR::null(), ...)
    }
}
```

#### 隔离区加密密钥
**发现 #2**: 使用硬编码回退密钥

**位置**: [quarantine_service.rs:113-131](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/quarantine_service.rs#L113-L131)

```rust
fn get_encryption_key() -> [u8; 16] {
    if let Ok(hex_key) = std::env::var("ANXIN_SECURITY_QUARANTINE_KEY") {
        // 优先使用环境变量
        if hex_key.len() == 32 {
            // 解析并返回
        }
    }
    // 安全警告: 回退密钥仅用于开发/演示
    eprintln!("[QuarantineService] WARNING: 使用硬编码回退加密密钥...");
    *b"AnXinSecurityKey"  // 硬编码回退密钥
}
```

**利用条件**: 仅当 `ANXIN_SECURITY_QUARANTINE_KEY` 环境变量未设置时触发

**缓解措施**:
- 代码中明确警告生产环境必须设置环境变量
- 日志输出可见警告信息

**严重度**: 低（需物理访问或环境配置错误）
**可利用性**: 无法在运行时远程利用

#### 文件加密
**评估**: ✅ **良好实践**

- 使用 AES-128-GCM 加密隔离文件
- 随机 nonce 生成
- 密钥长度验证

**证据**：[utils/crypto.rs](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/utils/crypto.rs)

---

### 5. 进程控制与 DLL 注入

#### 进程监控
**发现 #3**: 进程监控可加载配置中指定的 DLL

**位置**:
- [process.rs:198-215](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/process.rs#L198-L215) - start_process_watcher
- [process_monitor_service.rs:485](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/process_monitor_service.rs#L485)

```rust
std::process::Command::new(injector)
    .args(["--pid", &pid.to_string(), "--dll", dll])
    .spawn();
```

**攻击者画像**: 需要能修改前端配置或应用启动参数

**评估**: 这是安全监控的核心功能。恶意利用需要：
1. 修改应用程序配置或启动参数
2. 在运行时替换 DLL 文件

**严重度**: 低（需先获取应用程序控制权）

---

## 安全实践评估

| 安全实践 | 状态 | 证据位置 |
|----------|------|----------|
| 参数化 SQL 查询 | ✅ 良好 | 所有数据库操作使用 `.bind()` |
| DPAPI 加密敏感数据 | ✅ 良好 | runtime_list_store.rs |
| 进程保护白名单 | ✅ 良好 | process.rs 白名单常量 |
| 路径规范化 | ✅ 良好 | path_policy_service.rs |
| 循环检测（symlink） | ✅ 良好 | fs.rs canonicalize() |
| 深度限制 | ✅ 良好 | fs.rs depth > 32 |
| 错误处理 | ✅ 良好 | 不泄露敏感信息 |
| 敏感数据日志 | ✅ 未发现 | 无硬编码密钥日志 |
| 命令注入防护 | ✅ 良好 | 硬编码命令参数 |
| 外部通信 | ✅ 安全 | 无网络请求代码 |

---

## 建议（非必需）

以下为可选的安全增强建议：

1. **开发者设置功能修复**: 统一 `dev_settings_save` 和 `dev_settings_unlock` 使用的字段名称
2. **进程控制审计日志**: 增加对终止/挂起操作的审计记录
3. **DLL 路径验证**: 验证 DLL 文件签名或路径在预期目录内
4. **强制环境变量检查**: 启动时检查 `ANXIN_SECURITY_QUARANTINE_KEY` 是否设置，未设置则拒绝启动

---

## 结论

**审计完成——未发现中等或更高严重度的已确认漏洞。**

代码库整体安全架构设计合理，遵循了 Rust 的内存安全特性，并正确使用了 Windows 安全 API（DPAPI、WinVerifyTrust）。主要发现：

1. **无注入漏洞**: 所有数据库操作使用参数化查询，文件系统操作有规范化保护
2. **无外部通信**: 代码库无 HTTP/Webhook 等外部交互
3. **数据加密**: 敏感数据使用 DPAPI 和 AES-128-GCM 加密
4. **进程保护**: 关键系统进程受白名单保护

主要风险点来自：
1. 应用程序作为安全工具的固有设计（可终止进程、可注入 DLL）
2. 开发/演示环境的配置要求（需设置环境变量）

这些风险在实际部署中可控，建议在生产环境部署清单中明确环境变量配置要求。

---

**报告生成时间**: 2026-05-27
**审计工具**: 自动化代码审计 + 人工复核
**审计范围**: 全代码库系统性分析
