# AnXinSecurity 安全审计报告

**审计日期**: 2026-05-23
**审计范围**: AnXinSecurity Tauri 应用 (Rust 后端 + TypeScript/React 前端)
**审计方法**: 代码静态分析 + 架构审查

---

## 执行摘要

本次审计发现了 **2 个已确认的高严重度漏洞** 和 **2 个已确认的中等严重度问题**。这些漏洞具有明确的端到端利用路径，可能导致敏感数据泄露和本地权限绕过。

---

## 已确认漏洞详情

### VULN-001: 隔离区硬编码回退加密密钥 [严重度: 高]

#### 攻击者画像
- **类型**: 本地攻击者（具有主机访问权限的用户或恶意软件）
- **前提**: 生产环境未设置 `ANXIN_SECURITY_QUARANTINE_KEY` 环境变量

#### 可控输入向量
1. 攻击者可访问被隔离的加密文件 `%APPDATA%\AnXinSecurity\quarantine\*.enc`
2. 攻击者可观察应用日志输出（包含警告信息）

#### 完整利用路径

```
1. 攻击场景：
   - 管理员将恶意软件隔离到安全目录
   - 生产环境忘记设置环境变量 ANXIN_SECURITY_QUARANTINE_KEY

2. 代码路径分析：
   文件: src-tauri/src/services/quarantine_service.rs
   行号: 113-131 (get_encryption_key 函数)

   关键代码:
   ```
   fn get_encryption_key() -> [u8; 16] {
       if let Ok(hex_key) = std::env::var("ANXIN_SECURITY_QUARANTINE_KEY") {
           // ... 环境变量验证逻辑
       }
       // 安全警告: 回退密钥仅用于开发/演示
       eprintln!("[QuarantineService] WARNING: 使用硬编码回退加密密钥...");
       *b"AnXinSecurityKey"  // <-- 硬编码密钥
   }
   ```

3. 攻击步骤：
   a. 读取日志获取警告信息，确认使用回退密钥
   b. 使用已知密钥 "AnXinSecurityKey" 解密隔离区文件
   c. 恢复恶意软件到原位置或提取敏感数据

4. 影响：
   - **数据泄露**: 隔离的恶意样本可能被恢复用于二次攻击
   - **完整性破坏**: 安全机制可被绕过
```

#### 修复建议

```rust
// 方案1: 应用启动时强制检查环境变量
fn get_encryption_key() -> Result<[u8; 16], String> {
    let hex_key = std::env::var("ANXIN_SECURITY_QUARANTINE_KEY")
        .map_err(|_| "ANXIN_SECURITY_QUARANTINE_KEY 环境变量未设置")?;

    if hex_key.len() != 32 {
        return Err("密钥必须为32位十六进制字符串".to_string());
    }
    // ... 解析逻辑
}

// 方案2: 使用 Windows DPAPI 生成唯一密钥
fn get_encryption_key() -> Result<[u8; 16], String> {
    // 使用 DPAPI 保护用户级别密钥
    // 密钥存储在用户配置文件中
}
```

---

### VULN-002: 开发者设置弱密码派生 [严重度: 高]

#### 攻击者画像
- **类型**: 本地攻击者（具有配置文件读取权限）
- **前提**: 能够读取 `config/app.json` 文件

#### 可控输入向量
1. 攻击者可读取 `config/app.json` 中的 `devSettings` 字段
2. 攻击者可进行离线暴力破解或彩虹表攻击

#### 完整利用路径

```
1. 攻击场景：
   - 攻击者获取配置文件读取权限
   - 开发者使用弱密码保护敏感设置

2. 代码路径分析：
   文件: src-tauri/src/commands/dev_settings.rs

   问题1 - 弱密钥派生 (第36-38行):
   ```
   let mut hasher = Sha256::new();
   hasher.update(password.as_bytes());  // 直接哈希，无盐
   let hash = format!("{:x}", hasher.finalize());
   ```

   问题2 - "盐" 实际是哈希本身 (第86行):
   ```
   let new_dev_settings = serde_json::json!({
       "salt": &hash[..32],  // salt 实际上是 SHA-256(password)
       "passwordHash": hash,  // 重复存储
       // ...
   });
   ```

   问题3 - 直接使用密码作为 AES 密钥 (第77行):
   ```
   let encrypted = encrypt_data(plaintext.as_bytes(), password.as_bytes())?;
   // password 可能长度不足或过长，未正确派生密钥
   ```

3. 攻击影响：
   - **暴力破解**: 无盐的 SHA-256 可被快速破解
   - **彩虹表攻击**: 常见密码可被预计算哈希表匹配
   - **配置泄露**: 加密的开发者设置可被解密
```

#### 修复建议

```rust
// 使用 Argon2 或 PBKDF2 正确派生密钥
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

    // 从哈希中提取 16 字节密钥
    let hash_bytes = hash.hash.ok_or("哈希生成失败")?;
    let mut key = [0u8; 16];
    key.copy_from_slice(&hash_bytes.as_bytes()[..16]);
    Ok(key)
}
```

---

### VULN-003: 错误追踪可能记录敏感信息 [严重度: 中]

#### 攻击者画像
- **类型**: 本地攻击者（具有日志目录读取权限）
- **前提**: 能够读取 `logs/error_trace.log`

#### 可控输入向量
1. 前端通过 `report_error` API 上传任意错误字符串
2. 攻击者可注入包含敏感信息的错误消息

#### 完整利用路径

```
1. 代码路径分析：
   文件: src-tauri/src/commands/error_trace.rs
   行号: 25-30

   关键代码:
   ```
   let log_line = format!(
       "[{}] [{}] {}\n",
       timestamp,
       source_str,
       error.replace('\n', " | ")  // 仅替换换行符
   );
   ```

2. 攻击场景：
   - 前端错误可能包含用户文件路径、API 响应内容
   - 恶意用户可构造包含敏感数据的错误上报
   - 攻击者读取日志获取敏感信息

3. 影响：
   - **敏感数据泄露**: 文件路径、用户数据、令牌可能被记录
   - **合规风险**: 违反 GDPR/数据保护要求
```

#### 修复建议

```rust
// 实现敏感信息过滤
fn sanitize_error_message(error: &str) -> String {
    let mut sanitized = error.clone();

    // 移除可能的敏感模式
    let patterns = [
        r"password[=:]\S+",
        r"token[=:]\S+",
        r"api[_-]?key[=:]\S+",
        r"Bearer\s+\S+",
        r"\d{16,19}"  // 信用卡号等
    ];

    for pattern in patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            sanitized = re.replace_all(&sanitized, "[REDACTED]").to_string();
        }
    }

    sanitized
}
```

---

### VULN-004: IPC 配置端口绑定风险 [严重度: 中]

#### 攻击者画像
- **类型**: 本地攻击者（同一主机的其他进程）
- **前提**: IPC 功能被意外启用

#### 可控输入向量
1. 攻击者可连接本地端口 8765（如果启用）
2. 恶意进程可伪装为扫描引擎

#### 完整利用路径

```
1. 代码路径分析：
   文件: src-tauri/src/models/config.rs
   行号: 140-147

   配置定义:
   ```
   ipc: IpcConfig {
       enabled: false,      // 当前禁用
       prefer: false,
       host: "127.0.0.1",  // 本地绑定
       port: 8765,
       // ...
   }
   ```

2. 代码注释表明 TCP IPC 已被原生 DLL 取代：
   文件: src-tauri/src/services/engine_service.rs
   "原有的 TCP IPC 通信已被原生 DLL 直接加载取代"

3. 潜在风险：
   - 配置可能被错误启用
   - 端口冲突或安全边界混淆
   - 如果将来重新启用，可能引入漏洞
```

#### 修复建议

```rust
// 强化 IPC 配置验证
impl IpcConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.host != "127.0.0.1" && self.host != "localhost" {
            return Err("IPC 仅允许本地绑定".to_string());
        }

        if self.enabled && self.port < 1024 {
            return Err("IPC 端口不应使用特权端口".to_string());
        }

        Ok(())
    }
}
```

---

## 未发现问题的安全领域

以下领域经审计后**未发现**中等或更高严重度的已确认漏洞：

### 1. 认证与访问控制
- ✅ 所有 Tauri 命令通过前端 UI 调用，无外部网络接口
- ✅ 进程终止操作有受保护进程白名单检查
- ✅ 开发者设置使用密码保护

### 2. 注入向量
- ✅ SQL 查询使用 sqlx 参数化查询，无 SQL 注入风险
- ✅ 文件路径操作使用 `PathBuf` 类型安全 API
- ✅ 无命令注入风险（无 shell 执行）

### 3. 外部交互
- ✅ 无出站网络请求
- ✅ 无 Webhook 或第三方 API 集成
- ✅ ETW 事件来自系统内核，安全边界清晰

### 4. 敏感数据加密
- ✅ 运行时列表使用 Windows DPAPI 加密
- ✅ SQLite 数据库用于行为记录（非敏感数据）
- ✅ 隔离区使用 AES-128-GCM（有密钥管理问题，见 VULN-001）

---

## 风险等级说明

| 等级 | 定义 | 本次发现数量 |
|------|------|-------------|
| **严重** | 远程代码执行、完整系统入侵 | 0 |
| **高** | 本地提权、敏感数据泄露、安全机制绕过 | 2 |
| **中** | 有限范围的数据泄露、本地拒绝服务 | 2 |
| **低** | 理论风险、需特殊前提条件 | 0 |

---

## 修复优先级建议

| 优先级 | 漏洞 ID | 修复工作量 | 建议时间 |
|--------|---------|-----------|----------|
| P0 | VULN-001 | 中等 | 立即 |
| P0 | VULN-002 | 中等 | 立即 |
| P1 | VULN-003 | 低 | 1 周内 |
| P2 | VULN-004 | 低 | 1 个月内 |

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
│   └── behavior_service.rs
├── models/config.rs
└── utils/crypto.rs
```

---

*报告生成时间: 2026-05-23*
*审计工具: 手动代码审查 + 静态分析*
