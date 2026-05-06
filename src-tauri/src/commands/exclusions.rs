use crate::services::path_policy_service::{
    load_exclusion_entries, ExclusionEntry, EXCLUSIONS_RUNTIME_FILE,
};
use crate::services::runtime_list_store::save_runtime_list;
use std::path::PathBuf;

/// 函数名称：list_exclusions
/// 函数作用：读取用户排除项列表，优先读取 APPDATA 运行时文件，兼容读取旧版 config/app.json 字段。
/// Function name: list_exclusions
/// Purpose: Loads user exclusion entries from the APPDATA runtime file, with a legacy config/app.json fallback.
/// 调用方：Tauri invoke 命令 list_exclusions；设置页和扫描相关页面可间接调用。
/// Called by: Tauri invoke command list_exclusions; settings and scan related views may call it indirectly.
/// 被调用方：load_exclusions，runtime_list_store::load_runtime_list。
/// Calls: load_exclusions, runtime_list_store::load_runtime_list.
/// 参数说明：无参数。
/// Parameters: No parameters.
/// 返回值说明：Result<Vec<ExclusionEntry>, String>，成功返回排除项列表，运行时 JSON 损坏时返回错误字符串。
/// Returns: Result<Vec<ExclusionEntry>, String>, returning exclusions on success and a String error for damaged runtime JSON.
/// 内部关键变量：无持久局部变量；列表由运行时存储模块返回。
/// Internal variables: No persistent local variables; the list is returned by the runtime store module.
/// 接入方式：仅作为接口层命令调用；业务代码不应直接读取 config/app.json 的可变字段。
/// Integration: Use as a presentation-layer command; business code should not read mutable config/app.json fields directly.
/// 错误处理：向上返回运行时文件读取或解析错误，不吞掉用户数据损坏问题。
/// Error handling: Propagates runtime file read or parse failures instead of hiding user data corruption.
/// 副作用：缺失运行时文件且旧字段存在时，底层迁移逻辑可能写入 APPDATA runtime JSON；不写仓库 config/app.json。
/// Side effects: The migration fallback may write APPDATA runtime JSON when legacy fields exist; it does not write repository config/app.json.
/// 事务边界：无 Unit of Work；无数据库事务。
/// Transaction boundary: No Unit of Work and no database transaction.
/// 并发与幂等：读取可重复；并发写入由保存命令承担风险边界。
/// Concurrency and idempotency: Reads are repeatable; concurrent write risks are bounded to save commands.
/// 中文关键词：排除项，排除列表，运行时配置，APPDATA，config拆分，开发重载，设置页，扫描页，兼容迁移，用户状态
/// English keywords: exclusions, exclusion list, runtime config, APPDATA, config split, dev reload, settings page, scan page, legacy migration, user state
#[tauri::command]
pub async fn list_exclusions() -> Result<Vec<ExclusionEntry>, String> {
    load_exclusions()
}

/// 函数名称：add_exclusion
/// 函数作用：校验路径存在后添加单个排除项，并保存到运行时排除项文件。
/// Function name: add_exclusion
/// Purpose: Validates that the path exists, adds one exclusion entry, and persists it to the runtime exclusions file.
/// 调用方：Tauri invoke 命令 add_exclusion；设置页或扫描流程可间接调用。
/// Called by: Tauri invoke command add_exclusion; settings or scan flows may call it indirectly.
/// 被调用方：PathBuf::from，PathBuf::exists，load_exclusions，save_exclusions，chrono::Utc::now。
/// Calls: PathBuf::from, PathBuf::exists, load_exclusions, save_exclusions, chrono::Utc::now.
/// 参数说明：path 为文件/目录/进程路径，不可为空且必须存在；entry_type 为排除类型；description 为可选描述。
/// Parameters: path is a non-empty existing file/directory/process path; entry_type is the exclusion kind; description is optional.
/// 返回值说明：Result<bool, String>，成功返回 true；路径不存在或重复时返回错误。
/// Returns: Result<bool, String>, true on success and errors for missing or duplicated paths.
/// 内部关键变量：path_buf 表示待校验路径；exclusions 表示当前运行时排除项列表；entry 表示待保存的新排除项。
/// Internal variables: path_buf is the path under validation; exclusions is the current runtime list; entry is the new entry.
/// 接入方式：接口层命令入口调用；不需要调用方持有 AppConfig 锁。
/// Integration: Called as a presentation-layer command; callers do not need an AppConfig lock.
/// 错误处理：非法路径、重复排除项、运行时文件读写失败均返回 String 错误。
/// Error handling: Invalid paths, duplicates, and runtime file read/write failures return String errors.
/// 副作用：写入 APPDATA runtime exclusions JSON；不写 config/app.json；不调用外部服务。
/// Side effects: Writes APPDATA runtime exclusions JSON; does not write config/app.json or call external services.
/// 事务边界：无 Unit of Work；单文件写入失败直接返回。
/// Transaction boundary: No Unit of Work; single-file write failures return immediately.
/// 并发与幂等：重复添加同一路径会返回错误；并发写入不是强一致。
/// Concurrency and idempotency: Repeated adds for the same path return errors; concurrent writes are not strongly consistent.
/// 中文关键词：添加排除项，路径校验，排除列表，运行时文件，APPDATA，重复检查，用户配置，开发重载，设置命令，扫描排除
/// English keywords: add exclusion, path validation, exclusion list, runtime file, APPDATA, duplicate check, user config, dev reload, settings command, scan exclusion
#[tauri::command]
pub async fn add_exclusion(
    path: String,
    entry_type: String,
    description: Option<String>,
) -> Result<bool, String> {
    let path_buf = PathBuf::from(&path);
    if !path_buf.exists() {
        return Err(format!("路径不存在: {}", path));
    }

    let mut exclusions = load_exclusions()?;
    if exclusions.iter().any(|entry| entry.path == path) {
        return Err("排除项已存在".to_string());
    }

    let entry = ExclusionEntry {
        path,
        entry_type,
        description,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    exclusions.push(entry);
    save_exclusions(&exclusions)?;

    Ok(true)
}

/// 函数名称：remove_exclusion
/// 函数作用：从运行时排除项列表中移除指定路径。
/// Function name: remove_exclusion
/// Purpose: Removes a path from the runtime exclusions list.
/// 调用方：Tauri invoke 命令 remove_exclusion；设置页可间接调用。
/// Called by: Tauri invoke command remove_exclusion; settings views may call it indirectly.
/// 被调用方：load_exclusions，Vec::retain，save_exclusions。
/// Calls: load_exclusions, Vec::retain, save_exclusions.
/// 参数说明：path 为需要移除的排除项路径，不可为空。
/// Parameters: path is the exclusion path to remove and must be non-empty.
/// 返回值说明：Result<bool, String>，成功删除返回 true，路径未命中返回错误。
/// Returns: Result<bool, String>, true when removed and an error when the path is missing.
/// 内部关键变量：exclusions 为当前排除项列表；original_len 用于判断是否实际删除。
/// Internal variables: exclusions is the current list; original_len detects whether a deletion occurred.
/// 接入方式：接口层命令调用；不需要事务或 AppConfig 状态锁。
/// Integration: Called as a presentation-layer command; no transaction or AppConfig state lock is required.
/// 错误处理：未找到排除项或运行时文件读写失败时返回 String 错误。
/// Error handling: Missing entries and runtime file failures return String errors.
/// 副作用：写入 APPDATA runtime exclusions JSON；不写仓库配置。
/// Side effects: Writes APPDATA runtime exclusions JSON and does not write repository config.
/// 事务边界：无 Unit of Work；单文件写入失败直接返回。
/// Transaction boundary: No Unit of Work; single-file write failures return immediately.
/// 并发与幂等：删除不存在项返回错误；并发写入不是强一致。
/// Concurrency and idempotency: Removing a missing path returns an error; concurrent writes are not strongly consistent.
/// 中文关键词：移除排除项，排除列表，运行时文件，APPDATA，用户状态，开发重载，配置拆分，设置页，路径删除，幂等
/// English keywords: remove exclusion, exclusion list, runtime file, APPDATA, user state, dev reload, config split, settings page, path removal, idempotency
#[tauri::command]
pub async fn remove_exclusion(path: String) -> Result<bool, String> {
    let mut exclusions = load_exclusions()?;
    let original_len = exclusions.len();

    exclusions.retain(|entry| entry.path != path);

    if exclusions.len() == original_len {
        return Err("排除项不存在".to_string());
    }

    save_exclusions(&exclusions)?;

    Ok(true)
}

/// 函数名称：add_exclusions_batch
/// 函数作用：批量合并排除项，仅追加当前不存在的路径。
/// Function name: add_exclusions_batch
/// Purpose: Merges exclusion entries in batches and appends only paths that are not already present.
/// 调用方：Tauri invoke 命令 add_exclusions_batch；目录扫描或设置导入流程可间接调用。
/// Called by: Tauri invoke command add_exclusions_batch; directory scanning or settings import flows may call it indirectly.
/// 被调用方：load_exclusions，Iterator::any，save_exclusions。
/// Calls: load_exclusions, Iterator::any, save_exclusions.
/// 参数说明：entries 为待添加排除项列表，可为空；每个 entry 应包含路径、类型和创建时间。
/// Parameters: entries is the list to add and may be empty; each entry should include path, type, and created time.
/// 返回值说明：Result<usize, String>，返回实际新增数量。
/// Returns: Result<usize, String>, returning the number of entries actually added.
/// 内部关键变量：exclusions 为当前运行时列表；added_count 记录实际新增数量。
/// Internal variables: exclusions is the current runtime list; added_count tracks inserted entries.
/// 接入方式：接口层批量命令调用；调用方应负责输入来源可信度。
/// Integration: Called as a presentation-layer batch command; callers should own input trust decisions.
/// 错误处理：运行时文件读写失败返回 String 错误；重复路径被跳过而不是报错。
/// Error handling: Runtime file failures return String errors; duplicate paths are skipped.
/// 副作用：写入 APPDATA runtime exclusions JSON；不写 config/app.json。
/// Side effects: Writes APPDATA runtime exclusions JSON and does not write config/app.json.
/// 事务边界：无 Unit of Work；批量操作以单文件保存为一致性边界。
/// Transaction boundary: No Unit of Work; the batch uses one file save as the consistency boundary.
/// 并发与幂等：重复批量添加同一批数据会新增 0 项；并发写入不是强一致。
/// Concurrency and idempotency: Repeating the same batch adds zero entries; concurrent writes are not strongly consistent.
/// 中文关键词：批量排除项，排除列表，运行时文件，APPDATA，重复跳过，目录扫描，配置拆分，开发重载，用户状态，批量保存
/// English keywords: batch exclusions, exclusion list, runtime file, APPDATA, duplicate skip, directory scan, config split, dev reload, user state, batch save
#[tauri::command]
pub async fn add_exclusions_batch(entries: Vec<ExclusionEntry>) -> Result<usize, String> {
    let mut exclusions = load_exclusions()?;
    let mut added_count = 0;

    for entry in entries {
        if !exclusions
            .iter()
            .any(|existing_entry| existing_entry.path == entry.path)
        {
            exclusions.push(entry);
            added_count += 1;
        }
    }

    save_exclusions(&exclusions)?;

    Ok(added_count)
}

fn load_exclusions() -> Result<Vec<ExclusionEntry>, String> {
    load_exclusion_entries()
}

fn save_exclusions(entries: &[ExclusionEntry]) -> Result<(), String> {
    save_runtime_list(EXCLUSIONS_RUNTIME_FILE, entries)
}
