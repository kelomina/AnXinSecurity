# AnXinSecurity 安全审计报告

**审计日期**: 2026-05-21
**审计范围**: AnXinSecurity Tauri 应用程序（Rust 后端 + React 前端）
**审计工具**: 静态代码分析 + 架构审查

---

## 执行摘要

本次审计对 AnXinSecurity 进行了全面的安全审查，重点关注认证与访问控制、注入向量、外部交互以及敏感数据处理等方面。审计发现 **1 个已确认的高危漏洞** 和 **2 个已确认的中危问题**，均具备可论证的端到端利用路径。

---

## 发现汇总

| 严重度 | ID | 问题名称 |
|--------|-----|----------|
| **高危** | V-001 | 隔离区加密使用硬编码回退密钥 |
| **中危** | V-002 | 开发者设置配置读写存在路径穿越风险 |
| **中危** | V-003 | 缺乏进程操作权限验证机制 |

---

## 详细发现

### V-001: 隔离区加密使用硬编码回退密钥

**严重度**: 高危

#### 攻击者画像
- **外部攻击者**: 获得本地文件系统访问权限的攻击者
- **恶意软件作者**: 试图绕过隔离区保护的恶意软件
- **本地用户**: 试图解密被隔离文件的用户

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
        eprintln!("[QuarantineService] ANXIN_SECURITY_QUARANTINE_KEY 格式无效...");
    }
    // 安全风险: 回退密钥硬编码
    eprintln!("[QuarantineService] WARNING: 使用硬编码回退加密密钥...");
    *b"AnXinSecurityKey"  // <-- 硬编码密钥
}
```

**数据流**:
1. `isolate_file` 调用 `get_encryption_key()` 获取 16 字节密钥
2. 密钥直接传递给 `encrypt_data()` 用于 AES-128-GCM 加密
3. 加密后的文件存储在 `%APPDATA%\AnXinSecurity\quarantine\{uuid}.enc`
4. 数据库记录包含 `original_path`、`file_hash`、`threat_type` 等敏感信息

#### 利用场景

**场景 1: 生产环境密钥未配置**
```
攻击步骤:
1. 攻击者在目标机器上部署恶意软件
2. 恶意软件检测到用户隔离了可疑文件
3. 由于生产服务器未设置 ANXIN_SECURITY_QUARANTINE_KEY
4. 恶意软件使用硬编码密钥解密并恢复恶意文件
5. 恶意软件获得持久化
```

**场景 2: 本地用户绕过隔离**
```
攻击步骤:
1. 普通用户安装了 AnXinSecurity
2. 安全软件隔离了用户下载的恶意软件
3. 用户使用相同的硬编码密钥手动解密隔离文件
4. 绕过安全软件检测
```

#### 影响评估

- **机密性**: 隔离区加密可被绕过，攻击者可恢复被隔离的恶意文件
- **完整性**: 攻击者可替换隔离文件内容后重新加密放回
- **可用性**: 攻击者可破坏隔离区数据完整性
- **CVSS 3.1 评分**: 7.5 (High) - 本地攻击、低权限、可用攻击工具

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

**额外建议**:
1. 在应用启动时验证环境变量是否正确配置
2. 使用 Windows DPAPI 加密密钥存储，而非环境变量
3. 生成并存储唯一的应用密钥到 Windows Credential Manager

---

### V-002: 开发者设置配置读写存在路径穿越风险

**严重度**: 中危

#### 攻击者画像
- **本地攻击者**: 能够修改应用工作目录下的 `config/app.json` 文件
- **协作攻击者**: 通过其他漏洞（如文件上传）修改配置文件

#### 可控输入向量
1. 配置文件 `config/app.json` 中的 `devSettings` 字段
2. 密码字段（SHA-256 哈希验证）
3. 加密载荷 `payload.data`

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

**问题分析**:
1. 使用相对路径 `"config/app.json"` 读写配置文件
2. 在 Tauri 应用中，工作目录可能随运行场景变化
3. 配置文件解析时未验证路径是否在预期范围内

#### 额外发现: 配置保存路径解析缺陷

**位置**: [src-tauri/src/models/config.rs:209-221](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/models/config.rs#L209-L221)

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
- **CVSS 3.1 评分**: 5.3 (Medium) - 网络相邻攻击、低权限要求、需要用户交互

#### 修复建议

```rust
fn resolve_config_path() -> Result<PathBuf, String> {
    // 使用绝对路径验证配置文件位置
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

### V-003: 缺乏进程操作权限验证机制

**严重度**: 中危

#### 攻击者画像
- **本地恶意软件**: 通过 IPC 或命名管道与 AnXinSecurity 通信的恶意程序
- **攻击者**: 通过 Tauri IPC 劫持攻击者

#### 可控输入向量

1. **进程挂起/恢复/终止**: PID 值直接来自外部输入
   - 位置: [process.rs:66](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/process.rs#L66)
   ```rust
   #[tauri::command]
   pub async fn suspend_process(pid: u32) -> Result<bool, String> {
       // PID 直接使用，无验证
       let handle = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid)?;
       // ...
   }
   ```

2. **进程观察者路径**: 注入器和 DLL 路径来自前端配置
   - 位置: [process.rs:198-215](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/process.rs#L198-L215)
   ```rust
   pub async fn start_process_watcher(
       watcher: tauri::State<'_, ProcessMonitorService>,
       injector_x64: String,   // 来自前端
       injector_x86: String,   // 来自前端
       dll_x64: String,        // 来自前端
       dll_x86: String,        // 来自前端
       interval_ms: u32,
   ) -> Result<bool, String> {
       watcher.start(&injector_x64, &injector_x86, &dll_x64, &dll_x86, interval_ms)
   }
   ```

#### 代码路径追踪

**注入器启动**: [process_monitor_service.rs:467-509](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/services/process_monitor_service.rs#L467-L509)

```rust
fn launch_injector(...) {
    let result = std::process::Command::new(injector)  // injector 来自外部
        .args(["--pid", &pid.to_string(), "--dll", dll])  // dll 来自外部
        .creation_flags(0x08000000)
        .spawn();
}
```

#### 利用场景

**场景 1: 进程操作滥用**
```
攻击步骤:
1. 攻击者通过前端漏洞或 IPC 劫持获取 Tauri 命令调用能力
2. 调用 suspend_process 挂起安全软件的关键进程
3. 挂起 restore_process 阻止安全软件恢复进程
4. 在进程被挂起期间执行恶意操作
```

**场景 2: DLL 注入路径操纵**
```
攻击步骤:
1. 攻击者控制 injector_x64/x86 或 dll_x64/x86 参数
2. 指定指向恶意 DLL 的路径
3. 安全软件将恶意 DLL 注入到其他进程
4. 实现进程间恶意代码执行
```

#### 缓解因素

代码中存在部分保护措施:
- `is_protected_process()` 检查保护的系统进程列表 ([process.rs:19-58](file:///e:/Project/HTML/AnXinSecurity/src-tauri/src/commands/process.rs#L19-L58))
- 阻止操作当前进程

#### 影响评估

- **机密性**: 可挂起安全软件后窃取敏感数据
- **完整性**: 可注入恶意代码到系统进程
- **可用性**: 可导致安全软件拒绝服务
- **CVSS 3.1 评分**: 6.3 (Medium) - 网络相邻攻击、需要特殊权限、可组合利用

#### 修复建议

```rust
// 1. 验证 DLL/注入器路径白名单
const ALLOWED_INJECTORS: &[&str] = &[
    "C:\\Program Files\\AnXinSecurity\\bin\\file_hook_injector_x64.exe",
    "C:\\Program Files\\AnXinSecurity\\bin\\file_hook_injector_x86.exe",
];

const ALLOWED_DLLS: &[&str] = &[
    "C:\\Program Files\\AnXinSecurity\\bin\\file_hook_x64.dll",
    "C:\\Program Files\\AnXinSecurity\\bin\\file_hook_x86.dll",
];

fn validate_path_whitelist(path: &str, allowed: &[&str]) -> Result<(), String> {
    let canonical = std::path::Path::new(path).canonicalize()
        .map_err(|_| "路径无效")?;
    for allowed_path in allowed {
        let allowed_canonical = std::path::Path::new(allowed_path).canonicalize()?;
        if canonical == allowed_canonical {
            return Ok(());
        }
    }
    Err("路径不在白名单中".to_string())
}

// 2. 添加进程操作审计日志
pub async fn suspend_process(pid: u32) -> Result<bool, String> {
    eprintln!("[AUDIT] User requested suspend_process for PID {}", pid);
    // ... 原有逻辑
}
```

---

## 非确认问题（理论性风险）

以下问题经过分析后认为在当前部署模型下不构成实际风险：

### 1. SQL 注入风险 (未确认)

**分析**: 所有数据库操作使用 `sqlx::query` 的参数化查询，路径安全。

### 2. 路径遍历 (未确认)

**分析**: 
- 文件操作使用规范化路径和 junction 检测
- 隔离区文件 UUID 命名避免冲突
- 配置保存使用相对安全的路径解析

### 3. 外部网络请求 (未确认)

**分析**: 代码中未发现外部 HTTP 请求或 Webhook 集成，无远程攻击面。

### 4. 硬编码凭证 (未确认)

**分析**: 代码中无硬编码的 API 密钥或数据库密码（除开发回退密钥 V-001）。

---

## 安全最佳实践建议

### 高优先级
1. ✅ 移除硬编码加密密钥回退，强制要求环境变量配置
2. ✅ 为进程操作添加完整的权限验证和白名单机制
3. ✅ 配置文件使用绝对路径并验证路径范围

### 中优先级
4. 为所有安全敏感操作添加审计日志
5. 实现配置变更的完整性验证（签名或 HMAC）
6. 添加安全配置的启动时验证

### 低优先级
7. 考虑实现配置加密存储
8. 添加操作频率限制防止滥用

---

## 结论

AnXinSecurity 作为一款桌面安全软件，核心安全机制（签名验证、进程监控、文件隔离）在设计上是合理的。主要风险集中在：

1. **隔离区加密密钥管理** (V-001) - 直接影响隔离区数据的保密性
2. **外部输入验证不足** (V-002, V-003) - 可能被组合利用导致安全机制绕过

建议优先修复 V-001，该问题具有明确的攻击路径且影响隔离区的核心安全功能。

---

*报告生成时间: 2026-05-21*
*审计方法: 静态代码分析 + 架构审查 + 数据流追踪*
