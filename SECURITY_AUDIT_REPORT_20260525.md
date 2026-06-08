# AnXinSecurity 安全审计报告

**审计日期**: 2026-05-25
**审计范围**: AnXinSecurity Tauri 应用程序（Rust 后端 + React 前端）
**审计方法**: 静态代码分析 + 架构审查 + 数据流追踪
**审计工具**: 手动代码审查

---

## 执行摘要

本次审计对 AnXinSecurity 进行了系统性安全审查，涵盖认证与访问控制、注入向量、外部交互和敏感数据处理等高风险领域。审计发现 **3 个已确认的高危漏洞** 和 **3 个已确认的中危问题**，均具备可论证的端到端利用路径。

---

## 发现汇总

| 严重度 | ID | 问题名称 | 状态 |
|--------|-----|----------|------|
| **高危** | V-001 | 隔离区加密使用硬编码回退密钥 | 未修复 |
| **高危** | V-002 | 开发者设置弱密码派生（无盐 SHA-256） | 未修复 |
| **高危** | V-003 | 进程注入路径验证缺失 | 新发现 |
| **中危** | V-004 | 错误追踪可能记录敏感信息 | 未修复 |
| **中危** | V-005 | 路径规范化不完整导致排除项绕过 | 新发现 |
| **中危** | V-006 | 开发者设置配置读写存在路径穿越风险 | 未修复 |

---

## 详细发现

### V-001: 隔离区加密使用硬编码回退密钥

**严重度**: 高危
**状态**: 未修复（与 2026-05-21 和 2026-05-23 报告相同）

#### 攻击者画像
- **本地攻击者**: 获得主机访问权限的攻击者或恶意软件
- **恶意软件作者**: 试图绕过隔离区保护的恶意软件

#### 可控输入向量
1. 环境变量 `ANXIN_SECURITY_QUARANTINE_KEY`（生产环境可能未设置）
2. 攻击者可物理访问存储设备时，直接读取 `%APPDATA%\AnXinSecurity\quarantine\` 目录

#### 代码路径追踪

**问题位置**: [src-tauri/src/services/quarantine_service.rs:113-131](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/quarantine_service.rs#L113-L131)

```rust
fn get_encryption_key() -> [u8; 16] {
    if let Ok(hex_key) = std::env::var("ANXIN_SECURITY_QUARANTINE_KEY") {
        if hex_key.len() == 32 {
            // ... 正常路径
        }
    }
    // 安全风险: 回退密钥硬编码
    eprintln!("[QuarantineService] WARNING: 使用硬编码回退加密密钥...");
    *b"AnXinSecurityKey"  // <-- 硬编码密钥
}
```

#### 利用场景

```
攻击步骤:
1. 恶意软件检测到用户隔离了可疑文件
2. 检查日志发现 "WARNING: 使用硬编码回退加密密钥"
3. 使用已知密钥 "AnXinSecurityKey" 解密隔离区文件
4. 恢复恶意软件到原位置，获得持久化
```

#### 影响评估
- **机密性**: 隔离区加密可被绕过，攻击者可恢复被隔离的恶意文件
- **完整性**: 攻击者可替换隔离文件内容后重新加密放回
- **CVSS 3.1 评分**: 7.5 (High)

#### 修复建议

```rust
// 强制要求环境变量，不提供回退选项
fn get_encryption_key() -> Result<[u8; 16], String> {
    let hex_key = std::env::var("ANXIN_SECURITY_QUARANTINE_KEY")
        .map_err(|_| "ANXIN_SECURITY_QUARANTINE_KEY 环境变量未设置")?;

    if hex_key.len() != 32 || !hex_key.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("ANXIN_SECURITY_QUARANTINE_KEY 必须是32位十六进制字符串".to_string());
    }

    // ... 转换为 [u8; 16] 并返回
}
```

---

### V-002: 开发者设置弱密码派生

**严重度**: 高危
**状态**: 未修复（与 2026-05-23 报告相同）

#### 攻击者画像
- **本地攻击者**: 能够读取 `config/app.json` 文件的攻击者
- **恶意软件**: 能够访问配置文件的恶意程序

#### 可控输入向量
1. 配置文件 `config/app.json` 中的 `devSettings` 字段
2. 攻击者可进行离线暴力破解或彩虹表攻击

#### 代码路径追踪

**问题位置**: [src-tauri/src/commands/dev_settings.rs:36-38](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/dev_settings.rs#L36-L38)

```rust
let mut hasher = Sha256::new();
hasher.update(password.as_bytes());  // 直接哈希，无盐
let hash = format!("{:x}", hasher.finalize());
```

**问题位置**: [dev_settings.rs:86](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/dev_settings.rs#L86)

```rust
let new_dev_settings = serde_json::json!({
    "salt": &hash[..32],  // salt 实际上是 SHA-256(password) 本身，不是独立的盐
    "passwordHash": hash,  // 重复存储
    // ...
});
```

#### 利用场景

```
攻击步骤:
1. 攻击者读取 config/app.json
2. 发现 salt="e3b0c44298fc1..."（这是 SHA-256("") 的前32字符，不是真正的盐）
3. 使用常见密码字典进行离线暴力破解
4. 无盐 SHA-256 可被快速破解
5. 解密开发者设置内容
```

#### 修复建议

```rust
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2,
};

fn derive_key(password: &str) -> Result<[u8; 16], String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("密钥派生失败: {}", e))?;

    let hash_bytes = hash.hash.ok_or("哈希生成失败")?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash_bytes.as_bytes()[..16]);
    Ok(key)
}
```

---

### V-003: 进程注入路径验证缺失

**严重度**: 高危
**状态**: 新发现

#### 攻击者画像
- **恶意前端**: 通过 Tauri IPC 调用 `start_process_watcher` 的恶意脚本
- **本地恶意软件**: 能够劫持前端通信的攻击者

#### 可控输入向量
1. `start_process_watcher` 命令参数：
   - `injector_x64`: x64 注入器路径
   - `injector_x86`: x86 注入器路径
   - `dll_x64`: x64 DLL 路径
   - `dll_x86`: x86 DLL 路径

#### 代码路径追踪

**入口位置**: [src-tauri/src/commands/process.rs:198-215](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/process.rs#L198-L215)

```rust
#[tauri::command]
pub async fn start_process_watcher(
    watcher: tauri::State<'_, ProcessMonitorService>,
    injector_x64: String,   // 来自前端 - 无验证
    injector_x86: String,   // 来自前端 - 无验证
    dll_x64: String,        // 来自前端 - 无验证
    dll_x86: String,        // 来自前端 - 无验证
    interval_ms: u32,
) -> Result<bool, String> {
    watcher.start(&injector_x64, &injector_x86, &dll_x64, &dll_x86, interval_ms)
}
```

**执行位置**: [src-tauri/src/services/process_monitor_service.rs:467-509](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/process_monitor_service.rs#L467-L509)

```rust
fn launch_injector(
    pid: u32,
    arch: ProcArch,
    injector_x64: &str,
    injector_x86: &str,
    dll_x64: &str,
    dll_x86: &str,
) {
    let (injector, dll) = match arch {
        ProcArch::X64 => (injector_x64, dll_x64),
        ProcArch::X86 => (injector_x86, dll_x86),
        ProcArch::Unknown => return,
    };

    // 安全风险: injector 和 dll 来自外部输入，无任何验证
    let result = std::process::Command::new(injector)  // 直接执行任意程序
        .args(["--pid", &pid.to_string(), "--dll", dll])
        .creation_flags(0x08000000)
        .spawn();
}
```

#### 利用场景

```
攻击步骤:
1. 攻击者获取前端 JavaScript 执行能力（XSS、恶意扩展等）
2. 调用 Tauri 命令 start_process_watcher
3. 指定恶意注入器路径: "C:\\Malware\\evil_injector.exe"
4. 指定恶意 DLL 路径: "C:\\Malware\\evil.dll"
5. 安全软件将恶意 DLL 注入到无辜进程
6. 实现进程间恶意代码执行和持久化
```

#### 影响评估
- **机密性**: 可注入恶意代码到任意进程窃取敏感数据
- **完整性**: 可绕过安全软件的进程保护机制
- **可用性**: 可导致安全软件核心功能失效
- **CVSS 3.1 评分**: 8.2 (High) - 网络攻击向量（通过前端 XSS）、低权限

#### 修复建议

```rust
const ALLOWED_INJECTORS: &[&str] = &[
    "C:\\Program Files\\AnXinSecurity\\bin\\file_hook_injector_x64.exe",
    "C:\\Program Files\\AnXinSecurity\\bin\\file_hook_injector_x86.exe",
];

const ALLOWED_DLLS: &[&str] = &[
    "C:\\Program Files\\AnXinSecurity\\bin\\file_hook_x64.dll",
    "C:\\Program Files\\AnXinSecurity\\bin\\file_hook_x86.dll",
];

fn validate_injection_path(path: &str) -> Result<(), String> {
    let canonical = std::path::Path::new(path)
        .canonicalize()
        .map_err(|_| "路径无效")?;

    let is_allowed = ALLOWED_INJECTORS.iter()
        .chain(ALLOWED_DLLS.iter())
        .any(|allowed| {
            std::path::Path::new(allowed)
                .canonicalize()
                .map(|p| p == canonical)
                .unwrap_or(false)
        });

    if !is_allowed {
        return Err("注入器/DLL 路径不在白名单中".to_string());
    }
    Ok(())
}
```

---

### V-004: 错误追踪可能记录敏感信息

**严重度**: 中危
**状态**: 未修复（与 2026-05-23 报告相同）

#### 攻击者画像
- **恶意前端**: 构造包含敏感数据的错误上报
- **攻击者**: 能够读取日志文件的本地攻击者

#### 可控输入向量
1. `report_error` 命令参数 `error`: 任意错误字符串
2. 攻击者可注入包含敏感信息的错误消息

#### 代码路径追踪

**问题位置**: [src-tauri/src/commands/error_trace.rs:25-30](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/error_trace.rs#L25-L30)

```rust
let log_line = format!(
    "[{}] [{}] {}\n",
    timestamp,
    source_str,
    error.replace('\n', " | ")  // 仅替换换行符，无敏感信息过滤
);
```

#### 利用场景

```
攻击步骤:
1. 攻击者通过 XSS 获取前端执行能力
2. 调用 report_error("API token: abc123, password: secret456")
3. 敏感信息写入 logs/error_trace.log
4. 攻击者读取日志获取敏感凭证
```

#### 修复建议

```rust
fn sanitize_error_message(error: &str) -> String {
    let mut sanitized = error.to_string();

    let patterns = [
        (r"(?i)password[=:]\S+", "[REDACTED]"),
        (r"(?i)token[=:]\S+", "[REDACTED]"),
        (r"(?i)api[_-]?key[=:]\S+", "[REDACTED]"),
        (r"Bearer\s+\S+", "Bearer [REDACTED]"),
        (r"\b\d{16,19}\b", "[REDACTED]"),  // 信用卡号
    ];

    for (pattern, replacement) in patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            sanitized = re.replace_all(&sanitized, replacement).to_string();
        }
    }

    sanitized
}
```

---

### V-005: 路径规范化不完整导致排除项绕过

**严重度**: 中危
**状态**: 新发现

#### 攻击者画像
- **恶意文件**: 使用特殊路径命名的恶意文件
- **攻击者**: 试图绕过安全扫描的恶意软件

#### 可控输入向量
1. 文件路径（如 `..\..\malware.exe`）
2. 进程路径

#### 代码路径追踪

**问题位置**: [src-tauri/src/services/path_policy_service.rs:233-255](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/path_policy_service.rs#L233-L255)

```rust
fn normalize_path(path: &str) -> String {
    let mut normalized: String = path
        .trim()
        .chars()
        .map(|ch| {
            if ch == '/' {
                '\\'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect();
    if normalized.starts_with("\\\\?\\") {
        normalized = normalized[4..].to_string();
    }
    if normalized.starts_with("\\??\\") {
        normalized = normalized[4..].to_string();
    }
    // 问题: 不解析 .. 相对路径
    // "C:\\Safe\\..\\..\\malware.exe" 仍是 "c:\\safe\\..\\..\\malware.exe"
    normalized
}
```

#### 利用场景

```
攻击步骤:
1. 用户将 C:\Program Files\SafeApp 添加到排除项
2. 恶意软件创建文件 C:\Program Files\SafeApp\..\..\malware.exe
3. 规范化后路径仍包含 ..\..\
4. is_excluded_path() 进行字符串匹配，检测 "C:\\safeapp\\"
5. 但实际路径是 "C:\malware.exe"，绕过排除项检查
6. 更严重: 如果用户排除 C:\Windows\System32
7. 恶意软件创建 C:\Windows\..\Windows\System32\evil.dll
8. 绕过检查后注入 System32 目录
```

#### 修复建议

```rust
fn normalize_path(path: &str) -> String {
    let mut normalized: String = path
        .trim()
        .chars()
        .map(|ch| {
            if ch == '/' {
                '\\'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect();

    if normalized.starts_with("\\\\?\\") {
        normalized = normalized[4..].to_string();
    }
    if normalized.starts_with("\\??\\") {
        normalized = normalized[4..].to_string();
    }

    // 解析相对路径组件
    let components: Vec<&str> = normalized.split('\\').collect();
    let mut resolved: Vec<&str> = Vec::new();

    for component in components {
        match component {
            "" | "." => continue,
            ".." => {
                resolved.pop();
            }
            _ => resolved.push(component),
        }
    }

    resolved.join("\\")
}
```

---

### V-006: 开发者设置配置读写存在路径穿越风险

**严重度**: 中危
**状态**: 未修复（与 2026-05-21 报告相同）

#### 攻击者画像
- **本地攻击者**: 能够修改应用工作目录下配置文件的攻击者
- **协作攻击者**: 通过其他漏洞修改配置文件的攻击者

#### 可控输入向量
1. 配置文件 `config/app.json` 中的 `devSettings` 字段
2. 加密载荷 `payload.data`

#### 代码路径追踪

**问题位置**: [src-tauri/src/commands/dev_settings.rs:102-146](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/dev_settings.rs#L102-L146)

```rust
fn read_dev_settings_file() -> Result<DevSettings, String> {
    let path = std::path::PathBuf::from("config/app.json");  // 相对路径
    let content = std::fs::read_to_string(&path)?;
    // ...
}

fn save_dev_settings_to_file(dev_settings: &serde_json::Value) -> Result<(), String> {
    let path = std::path::PathBuf::from("config/app.json");  // 相对路径
    // ...
}
```

**额外发现**: [src-tauri/src/models/config.rs:209-221](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/models/config.rs#L209-L221)

```rust
fn resolve_save_path() -> PathBuf {
    let local_path = PathBuf::from("config/app.json");
    if local_path.exists() {
        return local_path;
    }

    let parent_path = PathBuf::from("../config/app.json");
    if parent_path.exists() {
        return parent_path;
    }

    local_path
}
```

#### 影响评估
- **机密性**: 攻击者可通过修改配置文件窃取开发者设置中的敏感信息
- **完整性**: 攻击者可修改配置破坏应用行为
- **CVSS 3.1 评分**: 5.3 (Medium)

#### 修复建议

```rust
fn resolve_config_path() -> Result<PathBuf, String> {
    let app_data = std::env::var("APPDATA")
        .map_err(|_| "APPDATA 环境变量未设置")?;

    let config_path = PathBuf::from(app_data)
        .join("AnXinSecurity")
        .join("config")
        .join("app.json");

    // 验证路径不包含 .. 穿越父目录
    let canonical = config_path.canonicalize()
        .map_err(|_| "配置文件路径无效")?;

    let expected_prefix = PathBuf::from(app_data)
        .join("AnXinSecurity")
        .canonicalize()
        .map_err(|_| "应用数据目录无效")?;

    if !canonical.starts_with(&expected_prefix) {
        return Err("配置文件路径超出允许范围".to_string());
    }

    Ok(config_path)
}
```

---

## 未发现问题领域

以下领域经审计后**未发现**中等或更高严重度的已确认漏洞：

### 1. SQL 注入
- ✅ 所有数据库操作使用 `sqlx::query` 参数化查询
- ✅ 路径安全

### 2. 命令注入
- ✅ 无 shell 执行，所有路径操作使用 `PathBuf` 类型安全 API
- ✅ `launch_injector` 执行注入器但路径未验证（见 V-003）

### 3. 外部网络请求
- ✅ 代码中未发现外部 HTTP 请求
- ✅ 无 Webhook 或第三方 API 集成
- ✅ ETW 事件来自系统内核，安全边界清晰

### 4. 敏感数据加密（部分）
- ✅ 运行时列表使用 Windows DPAPI 加密
- ✅ 隔离区使用 AES-128-GCM（有密钥管理问题，见 V-001）

### 5. 会话管理与认证
- ✅ 所有 Tauri 命令通过前端 UI 调用，无外部网络接口
- ✅ 进程终止操作有受保护进程白名单检查

---

## 风险等级说明

| 等级 | 定义 | 本次发现数量 |
|------|------|-------------|
| **严重** | 远程代码执行、完整系统入侵 | 0 |
| **高** | 本地提权、敏感数据泄露、安全机制绕过 | 3 |
| **中** | 有限范围的数据泄露、本地拒绝服务 | 3 |

---

## 修复优先级建议

| 优先级 | 漏洞 ID | 问题名称 | 修复工作量 | 建议时间 |
|--------|---------|----------|-----------|----------|
| P0 | V-001 | 隔离区硬编码回退密钥 | 中等 | 立即 |
| P0 | V-003 | 进程注入路径验证缺失 | 中等 | 立即 |
| P1 | V-002 | 开发者设置弱密码派生 | 中等 | 1 周内 |
| P2 | V-004 | 错误追踪敏感信息记录 | 低 | 1 周内 |
| P2 | V-005 | 路径规范化不完整 | 中等 | 2 周内 |
| P3 | V-006 | 配置路径操作风险 | 低 | 1 个月内 |

---

## 附录：审计范围文件清单

```
src-tauri/src/
├── commands/
│   ├── config.rs, exclusions.rs, allowlist.rs
│   ├── scanner.rs, quarantine.rs, process.rs
│   ├── trust.rs, behavior.rs, interception.rs
│   ├── dev_settings.rs, error_trace.rs
│   └── fs.rs, logs.rs, risk.rs, training.rs
├── services/
│   ├── engine_service.rs, native_engine_service.rs
│   ├── quarantine_service.rs, trust_service.rs
│   ├── risk_service.rs, interception_service.rs
│   ├── etw_service.rs, training_service.rs
│   ├── runtime_list_store.rs, path_policy_service.rs
│   └── process_monitor_service.rs
├── models/config.rs
└── utils/crypto.rs
```

---

*报告生成时间: 2026-05-25*
*审计工具: 手动代码审查 + 静态分析*
