use serde::{de::DeserializeOwned, Serialize};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

const ENCRYPTED_RUNTIME_LIST_MAGIC: &[u8] = b"ANXIN_RUNTIME_LIST_DPAPI_V1\n";
const RUNTIME_LIST_ENTROPY: &[u8] = b"AnXinSecurity.RuntimeList.v1";

/// 函数名称：runtime_directory
/// 函数作用：解析运行时可变数据目录，默认位于 `%APPDATA%\AnXinSecurity\runtime`。
/// Purpose: Resolves the runtime mutable data directory, defaulting to `%APPDATA%\AnXinSecurity\runtime`.
/// 调用方：runtime_file_path、ensure_runtime_parent。
/// Called by: runtime_file_path, ensure_runtime_parent.
/// 被调用方：std::env::var、PathBuf::from、PathBuf::join。
/// Calls: std::env::var, PathBuf::from, PathBuf::join.
/// 参数说明：无参数；依赖 APPDATA 环境变量，缺失时回退到当前工作目录下的 data/runtime。
/// Parameters: No parameters; depends on APPDATA and falls back to data/runtime under CWD.
/// 返回值说明：PathBuf，表示运行时文件目录。
/// Returns: PathBuf for the runtime file directory.
/// 内部关键变量：app_data 为 Windows 应用数据根目录。
/// Internal variables: app_data is the Windows application data root.
/// 接入方式：仅供运行时列表存储模块内部使用。
/// Integration: Internal to the runtime list store module.
/// 错误处理：不抛异常；APPDATA 缺失时使用仓库外逻辑不可用的本地回退目录。
/// Error handling: Does not throw; uses a local fallback when APPDATA is missing.
/// 副作用：无文件写入副作用。
/// Side effects: No file write side effects.
/// 事务边界：无 Unit of Work；无 commit/rollback。
/// Transaction boundary: No Unit of Work; no commit/rollback.
/// 并发与幂等：同一进程环境下重复调用结果稳定。
/// Concurrency and idempotency: Stable for repeated calls in the same process environment.
/// 中文关键词：运行时目录，APPDATA，可变数据，信任列表，排除项，开发重载，配置拆分，本地状态，路径解析，数据目录
/// English keywords: runtime directory, APPDATA, mutable data, allowlist, exclusions, dev reload, config split, local state, path resolution, data directory
fn runtime_directory() -> PathBuf {
    std::env::var("APPDATA")
        .map(|app_data| {
            PathBuf::from(app_data)
                .join("AnXinSecurity")
                .join("runtime")
        })
        .unwrap_or_else(|_| PathBuf::from("data").join("runtime"))
}

/// 函数名称：runtime_file_path
/// 函数作用：生成指定运行时 JSON 文件的完整路径。
/// Purpose: Builds the full path for a named runtime JSON file.
/// 调用方：load_runtime_list、save_runtime_list。
/// Called by: load_runtime_list, save_runtime_list.
/// 被调用方：runtime_directory、PathBuf::join。
/// Calls: runtime_directory, PathBuf::join.
/// 参数说明：file_name 为文件名，不应包含目录分隔符。
/// Parameters: file_name is a file name and should not contain path separators.
/// 返回值说明：PathBuf，表示运行时 JSON 文件路径。
/// Returns: PathBuf for the runtime JSON file.
/// 内部关键变量：无持久变量。
/// Internal variables: No persistent variables.
/// 接入方式：仅供本模块内部路径拼接使用。
/// Integration: Internal path composition helper.
/// 错误处理：不抛异常；调用方负责文件系统错误处理。
/// Error handling: Does not throw; callers handle filesystem errors.
/// 副作用：无。
/// Side effects: None.
/// 事务边界：无 Unit of Work。
/// Transaction boundary: No Unit of Work.
/// 并发与幂等：同名文件重复解析结果一致。
/// Concurrency and idempotency: Repeated resolution for the same name is stable.
/// 中文关键词：运行时文件，JSON路径，信任列表文件，排除项文件，路径拼接，APPDATA，配置拆分，本地状态，文件名，运行目录
/// English keywords: runtime file, JSON path, allowlist file, exclusions file, path join, APPDATA, config split, local state, file name, runtime directory
pub(crate) fn runtime_file_path(file_name: &str) -> PathBuf {
    runtime_directory().join(file_name)
}

fn runtime_migration_marker_path(file_name: &str) -> PathBuf {
    runtime_directory().join(format!("{}.encrypted", file_name))
}

/// 函数名称：ensure_runtime_parent
/// 函数作用：确保运行时文件的父目录存在。
/// Purpose: Ensures the parent directory of a runtime file exists.
/// 调用方：save_runtime_list。
/// Called by: save_runtime_list.
/// 被调用方：Path::parent、fs::create_dir_all。
/// Calls: Path::parent, fs::create_dir_all.
/// 参数说明：path 为目标运行时文件路径。
/// Parameters: path is the target runtime file path.
/// 返回值说明：成功返回 Ok(())；目录创建失败返回错误字符串。
/// Returns: Ok(()) on success; directory creation failures return String errors.
/// 内部关键变量：parent 为目标文件父目录。
/// Internal variables: parent is the target file parent directory.
/// 接入方式：保存运行时列表前调用。
/// Integration: Called before saving runtime lists.
/// 错误处理：保留原始 IO 错误上下文并向上返回。
/// Error handling: Preserves IO error context and propagates it upward.
/// 副作用：可能创建 `%APPDATA%\AnXinSecurity\runtime` 目录。
/// Side effects: May create `%APPDATA%\AnXinSecurity\runtime`.
/// 事务边界：无 Unit of Work；目录创建失败时不会写文件。
/// Transaction boundary: No Unit of Work; file write is skipped on directory creation failure.
/// 并发与幂等：create_dir_all 可重复调用。
/// Concurrency and idempotency: create_dir_all is repeatable.
/// 中文关键词：创建目录，运行时目录，APPDATA，可变数据，保存列表，文件父目录，错误传播，信任列表，排除项，配置拆分
/// English keywords: create directory, runtime directory, APPDATA, mutable data, save list, file parent, error propagation, allowlist, exclusions, config split
fn ensure_runtime_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create runtime data directory: {}", err))?;
    }
    Ok(())
}

fn protect_runtime_bytes(plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let mut data_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: RUNTIME_LIST_ENTROPY.len() as u32,
        pbData: RUNTIME_LIST_ENTROPY.as_ptr() as *mut u8,
    };
    let mut protected_blob = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &mut data_blob,
            PCWSTR::null(),
            Some(&mut entropy_blob),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut protected_blob,
        )
        .map_err(|err| format!("Failed to encrypt runtime list with DPAPI: {}", err))?;

        let protected_bytes =
            std::slice::from_raw_parts(protected_blob.pbData, protected_blob.cbData as usize)
                .to_vec();
        let _ = LocalFree(HLOCAL(protected_blob.pbData as _));

        let mut output =
            Vec::with_capacity(ENCRYPTED_RUNTIME_LIST_MAGIC.len() + protected_bytes.len());
        output.extend_from_slice(ENCRYPTED_RUNTIME_LIST_MAGIC);
        output.extend_from_slice(&protected_bytes);
        Ok(output)
    }
}

fn unprotect_runtime_bytes(content: &[u8]) -> Result<Vec<u8>, String> {
    if !content.starts_with(ENCRYPTED_RUNTIME_LIST_MAGIC) {
        return Err("Runtime list is not encrypted".to_string());
    }

    let encrypted_payload = &content[ENCRYPTED_RUNTIME_LIST_MAGIC.len()..];
    let mut encrypted_blob = CRYPT_INTEGER_BLOB {
        cbData: encrypted_payload.len() as u32,
        pbData: encrypted_payload.as_ptr() as *mut u8,
    };
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: RUNTIME_LIST_ENTROPY.len() as u32,
        pbData: RUNTIME_LIST_ENTROPY.as_ptr() as *mut u8,
    };
    let mut plaintext_blob = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &mut encrypted_blob,
            None,
            Some(&mut entropy_blob),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut plaintext_blob,
        )
        .map_err(|err| format!("Failed to decrypt runtime list with DPAPI: {}", err))?;

        let plaintext =
            std::slice::from_raw_parts(plaintext_blob.pbData, plaintext_blob.cbData as usize)
                .to_vec();
        let _ = LocalFree(HLOCAL(plaintext_blob.pbData as _));
        Ok(plaintext)
    }
}

/// 函数名称：load_legacy_list_from_app_config
/// 函数作用：从旧版 `config/app.json` 字段读取运行时列表，用于首次迁移兼容。
/// Purpose: Reads a runtime list from legacy `config/app.json` fields for first-run migration compatibility.
/// 调用方：load_runtime_list。
/// Called by: load_runtime_list.
/// 被调用方：fs::read_to_string、serde_json::from_str、Value::get、serde_json::from_value。
/// Calls: fs::read_to_string, serde_json::from_str, Value::get, serde_json::from_value.
/// 参数说明：legacy_field 为旧字段名，例如 exclusions 或 startupAllowlist。
/// Parameters: legacy_field is the old field name, such as exclusions or startupAllowlist.
/// 返回值说明：读取成功返回列表；字段缺失、读取失败或解析失败返回空列表。
/// Returns: Loaded list on success; missing field, read failure, or parse failure returns an empty list.
/// 内部关键变量：config_paths 为兼容 CWD 与 tauri dev 的候选路径。
/// Internal variables: config_paths are candidate paths for CWD and tauri dev compatibility.
/// 接入方式：仅作为旧配置迁移回退，不用于常规写入。
/// Integration: Used only as a legacy migration fallback, not for regular writes.
/// 错误处理：失败静默回退空列表，避免旧字段损坏阻断应用启动。
/// Error handling: Silently falls back to an empty list to avoid blocking startup on legacy field damage.
/// 副作用：仅读取文件，不写 `config/app.json`。
/// Side effects: Reads files only; does not write `config/app.json`.
/// 事务边界：无 Unit of Work。
/// Transaction boundary: No Unit of Work.
/// 并发与幂等：读取操作可重复。
/// Concurrency and idempotency: Read operation is repeatable.
/// 中文关键词：旧配置迁移，app.json，运行时列表，信任列表，排除项，兼容读取，配置拆分，首次迁移，回退，JSON字段
/// English keywords: legacy config migration, app.json, runtime list, allowlist, exclusions, compatible read, config split, first migration, fallback, JSON field
fn load_legacy_list_from_app_config<T>(legacy_field: &str) -> Vec<T>
where
    T: DeserializeOwned,
{
    let config_paths = [
        PathBuf::from("config/app.json"),
        PathBuf::from("../config/app.json"),
    ];
    for config_path in config_paths {
        let Some(list) = fs::read_to_string(&config_path)
            .ok()
            .and_then(|content| serde_json::from_str::<Value>(&content).ok())
            .and_then(|value| value.get(legacy_field).cloned())
            .and_then(|field_value| serde_json::from_value::<Vec<T>>(field_value).ok())
        else {
            continue;
        };
        return list;
    }
    Vec::new()
}

/// 函数名称：load_runtime_list
/// 函数作用：从 APPDATA 加密运行时文件读取可变列表；旧明文 runtime 文件仅首次兼容读取并立即加密迁移。
/// Purpose: Loads a mutable list from an encrypted APPDATA runtime file; legacy plaintext runtime files are read once and immediately migrated to encrypted storage.
/// 调用方：allowlist/exclusions Tauri commands。
/// Called by: allowlist/exclusions Tauri commands.
/// 被调用方：runtime_file_path、fs::read、unprotect_runtime_bytes、serde_json::from_slice、load_legacy_list_from_app_config。
/// Calls: runtime_file_path, fs::read, unprotect_runtime_bytes, serde_json::from_slice, load_legacy_list_from_app_config.
/// 参数说明：file_name 为运行时文件名；legacy_field 为旧 app.json 字段名。
/// Parameters: file_name is the runtime file name; legacy_field is the old app.json field name.
/// 返回值说明：成功返回 Vec<T>；加密文件篡改、解密失败、明文降级或 JSON 损坏返回错误；文件不存在时返回旧字段或空列表。
/// Returns: Vec<T> on success; tampered encrypted files, decrypt failures, plaintext downgrade, or damaged JSON return errors; missing files return legacy field or empty list.
/// 内部关键变量：runtime_path 为 APPDATA 中的目标文件路径。
/// Internal variables: runtime_path is the target file path under APPDATA.
/// 接入方式：用于运行时可变数据读取，不应读取主配置承载可变列表。
/// Integration: Use for mutable runtime data reads; mutable lists should not live in main config.
/// 错误处理：运行时文件存在但无法解密或无法解析时返回错误，避免静默接受篡改数据。
/// Error handling: Existing runtime files that cannot decrypt or parse return errors to avoid silently accepting tampered data.
/// 副作用：旧明文 runtime 文件首次读取后会被 DPAPI 加密写回。
/// Side effects: Legacy plaintext runtime files are encrypted back with DPAPI after first read.
/// 事务边界：无 Unit of Work。
/// Transaction boundary: No Unit of Work.
/// 并发与幂等：读取操作可重复。
/// Concurrency and idempotency: Read operation is repeatable.
/// 中文关键词：读取运行时列表，APPDATA，信任列表，排除项，DPAPI，加密迁移，防篡改，JSON解析，用户数据，可变数据
/// English keywords: load runtime list, APPDATA, allowlist, exclusions, DPAPI, encrypted migration, tamper resistance, JSON parse, user data, mutable data
pub fn load_runtime_list<T>(file_name: &str, legacy_field: &str) -> Result<Vec<T>, String>
where
    T: DeserializeOwned + Serialize,
{
    let runtime_path = runtime_file_path(file_name);
    if runtime_path.exists() {
        let content = fs::read(&runtime_path).map_err(|err| {
            format!(
                "Failed to read runtime list {}: {}",
                runtime_path.display(),
                err
            )
        })?;
        if content.starts_with(ENCRYPTED_RUNTIME_LIST_MAGIC) {
            let plaintext = unprotect_runtime_bytes(&content)?;
            return serde_json::from_slice::<Vec<T>>(&plaintext).map_err(|err| {
                format!(
                    "Failed to parse decrypted runtime list {}: {}",
                    runtime_path.display(),
                    err
                )
            });
        }

        let migration_marker = runtime_migration_marker_path(file_name);
        if migration_marker.exists() {
            return Err(format!(
                "Rejected unencrypted runtime list {} after encryption was enabled",
                runtime_path.display()
            ));
        }

        let legacy_items = serde_json::from_slice::<Vec<T>>(&content).map_err(|err| {
            format!(
                "Failed to parse legacy plaintext runtime list {}: {}",
                runtime_path.display(),
                err
            )
        })?;
        save_runtime_list(file_name, &legacy_items)?;
        return Ok(legacy_items);
    }

    let legacy_items = load_legacy_list_from_app_config(legacy_field);
    if !legacy_items.is_empty() {
        save_runtime_list(file_name, &legacy_items)?;
    }
    Ok(legacy_items)
}

/// 函数名称：save_runtime_list
/// 函数作用：将可变列表经 Windows DPAPI 加密后保存到 APPDATA 运行时文件，避免写入仓库内 `config/app.json`。
/// Purpose: Encrypts mutable lists with Windows DPAPI before saving them to APPDATA runtime files, avoiding writes to repository `config/app.json`.
/// 调用方：allowlist/exclusions Tauri commands。
/// Called by: allowlist/exclusions Tauri commands.
/// 被调用方：runtime_file_path、ensure_runtime_parent、serde_json::to_string_pretty、protect_runtime_bytes、fs::write。
/// Calls: runtime_file_path, ensure_runtime_parent, serde_json::to_string_pretty, protect_runtime_bytes, fs::write.
/// 参数说明：file_name 为运行时文件名；items 为要持久化的列表。
/// Parameters: file_name is the runtime file name; items is the list to persist.
/// 返回值说明：成功返回 Ok(())；序列化、加密、建目录或写文件失败返回错误字符串。
/// Returns: Ok(()) on success; serialization, encryption, directory creation, or write failures return String errors.
/// 内部关键变量：runtime_path 为目标文件路径；content 为格式化 JSON；encrypted_content 为 DPAPI 密文。
/// Internal variables: runtime_path is the target file path; content is formatted JSON; encrypted_content is DPAPI ciphertext.
/// 接入方式：用于保存用户可变数据；主应用静态配置仍由 AppConfig::save 管理。
/// Integration: Saves user mutable data; static app config remains managed by AppConfig::save.
/// 错误处理：保留路径与原始错误上下文向上返回给 Tauri command。
/// Error handling: Propagates path and original error context to Tauri commands.
/// 副作用：写入 `%APPDATA%\AnXinSecurity\runtime\*.json` 密文和迁移标记文件。
/// Side effects: Writes encrypted `%APPDATA%\AnXinSecurity\runtime\*.json` and a migration marker file.
/// 事务边界：无 Unit of Work；单文件写入失败直接返回。
/// Transaction boundary: No Unit of Work; single-file write failures return immediately.
/// 并发与幂等：不是并发写安全；同一列表重复保存结果一致。
/// Concurrency and idempotency: Not safe for concurrent writes; repeated saves of the same list are stable.
/// 中文关键词：保存运行时列表，APPDATA，信任列表，排除项，DPAPI，加密保存，防篡改，用户状态，本地数据，app.json隔离
/// English keywords: save runtime list, APPDATA, allowlist, exclusions, DPAPI, encrypted save, tamper resistance, user state, local data, app.json isolation
pub fn save_runtime_list<T>(file_name: &str, items: &[T]) -> Result<(), String>
where
    T: Serialize,
{
    let runtime_path = runtime_file_path(file_name);
    ensure_runtime_parent(&runtime_path)?;
    let content = serde_json::to_string_pretty(items).map_err(|err| {
        format!(
            "Failed to serialize runtime list {}: {}",
            runtime_path.display(),
            err
        )
    })?;
    let encrypted_content = protect_runtime_bytes(content.as_bytes())?;
    fs::write(&runtime_path, encrypted_content).map_err(|err| {
        format!(
            "Failed to write runtime list {}: {}",
            runtime_path.display(),
            err
        )
    })?;
    fs::write(runtime_migration_marker_path(file_name), b"dpapi")
        .map_err(|err| format!("Failed to write runtime list encryption marker: {}", err))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpapi_runtime_bytes_round_trip_and_detect_tampering() {
        let plaintext = br#"[{"path":"C:\\Safe\\app.exe"}]"#;
        let encrypted = protect_runtime_bytes(plaintext).expect("encrypt runtime list");

        assert!(encrypted.starts_with(ENCRYPTED_RUNTIME_LIST_MAGIC));
        assert!(!encrypted
            .windows(plaintext.len())
            .any(|window| window == plaintext));

        let decrypted = unprotect_runtime_bytes(&encrypted).expect("decrypt runtime list");
        assert_eq!(decrypted, plaintext);

        let mut tampered = encrypted;
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(unprotect_runtime_bytes(&tampered).is_err());
    }
}
