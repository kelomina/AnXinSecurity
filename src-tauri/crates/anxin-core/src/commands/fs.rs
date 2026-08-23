// 文件系统命令 — 后台目录遍历（流式推送事件）
// File system commands — background directory walk (streaming events)
use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use tauri::Emitter;

/// 遍历任务状态 / Walk task status
struct WalkTask {
    cancel_flag: Arc<AtomicBool>,
}

/// 当前遍历任务 / Current walk task
static WALK_TASK: once_cell::sync::Lazy<Arc<Mutex<Option<WalkTask>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(None)));

/// 函数名称：start_background_walk
/// 函数作用：启动后台目录遍历，通过 Tauri Events 流式推送文件路径。
///   每收集 50 个文件 emit 一次 "walk-file-batch" 事件；
///   遍历完成时 emit "walk-complete" 事件。
///   返回立即，不阻塞前端。
/// Purpose: Starts a background directory walk, streaming file paths via Tauri Events.
///   Emits "walk-file-batch" every 50 files collected;
///   emits "walk-complete" when traversal finishes.
///   Returns immediately without blocking the frontend.
/// 调用方：前端 ScanPage "选择目录" 按钮
/// Called by: Frontend ScanPage "Select Directory" button
/// 参数 path: 根目录路径 / Root directory path
/// 参数 exclusions: 要排除的目录名列表 / Directory names to exclude
/// 参数 extensions: 仅收集指定扩展名的文件（可选） / Only collect files with specified extensions (optional)
/// 副作用：emit("walk-file-batch", Vec<String>) 推送文件批次；emit("walk-complete", {path}) 推送完成信号
/// Side effects: emit("walk-file-batch", Vec<String>) for file batches; emit("walk-complete", {path}) for completion
/// 错误处理：目录不存在时返回错误；遍历中权限不足的目录自动跳过
/// Error handling: Returns error if directory doesn't exist; permission-denied subdirectories are silently skipped
/// 并发与幂等：同一时间仅允许一个遍历任务，通过 cancel_walk 取消
/// Concurrency: Only one walk task allowed at a time, cancellable via cancel_walk
/// 中文关键词：后台遍历，流式推送，事件驱动，目录遍历，边扫边遍历
/// English keywords: background walk, streaming, event-driven, directory traversal, scan-while-walk
#[tauri::command]
pub async fn start_background_walk(
    path: String,
    exclusions: Option<Vec<String>>,
    extensions: Option<Vec<String>>,
    app_handle: tauri::AppHandle,
) -> Result<(), String> {
    let root = PathBuf::from(&path);
    if !root.exists() {
        return Err(format!("目录不存在: {}", path));
    }

    // 设置取消标志 / Set up cancellation flag
    let cancel_flag = Arc::new(AtomicBool::new(false));

    // 注册任务 / Register task
    {
        let mut task = WALK_TASK.lock().map_err(|e| e.to_string())?;
        *task = Some(WalkTask {
            cancel_flag: cancel_flag.clone(),
        });
    }

    // 构建排除集 / Build exclusion set
    let exclusion_set: std::collections::HashSet<String> = exclusions
        .unwrap_or_default()
        .into_iter()
        .map(|s| s.to_lowercase())
        .collect();

    // 构建扩展名过滤器 / Build extension filter
    let ext_set: Option<std::collections::HashSet<String>> = extensions.map(|exts| {
        exts.into_iter()
            .map(|s| s.trim_start_matches('.').to_lowercase())
            .collect()
    });

    // 已访问目录集合，用于防止 junction point 循环
    // Visited directory set to prevent junction point loops
    let mut visited: std::collections::HashSet<PathBuf> = std::collections::HashSet::new();
    if let Ok(canonical_root) = root.canonicalize() {
        visited.insert(canonical_root);
    }

    let path_for_closure = path.clone();
    let flag = cancel_flag.clone();
    let app_clone = app_handle.clone();

    // 在后台线程中执行遍历，通过事件流式推送文件
    // Execute walk in background thread, streaming files via events
    tokio::task::spawn_blocking(move || {
        let mut batch: Vec<String> = Vec::new();

        // 文件回调：收集到 50 个文件时推送一批事件
        // File callback: emit a batch every 50 files
        let mut on_file = |file_path: &str| {
            batch.push(file_path.to_string());
            if batch.len() >= 50 {
                let _ = app_clone.emit("walk-file-batch", &batch);
                batch.clear();
            }
        };

        walk_recursive(
            &root,
            &exclusion_set,
            &ext_set,
            &flag,
            0,
            &mut visited,
            &mut on_file,
        );

        // 刷入剩余文件 / Flush remaining files
        if !batch.is_empty() {
            let _ = app_clone.emit("walk-file-batch", &batch);
        }

        // 通知遍历完成 / Notify walk completion
        let _ = app_clone.emit(
            "walk-complete",
            serde_json::json!({
                "path": path_for_closure,
            }),
        );

        // 清理任务 / Clean up task
        if let Ok(mut task) = WALK_TASK.lock() {
            *task = None;
        }
    });

    Ok(())
}

/// 取消当前遍历任务 / Cancel current walk task
#[tauri::command]
pub async fn cancel_walk() -> Result<bool, String> {
    let task = WALK_TASK.lock().map_err(|e| e.to_string())?;
    if let Some(ref t) = *task {
        t.cancel_flag.store(true, Ordering::SeqCst);
        Ok(true)
    } else {
        Ok(false)
    }
}

/// 递归遍历目录 / Recursively walk directory
/// 参数 on_file: 每发现一个文件时调用的回调函数
/// Parameter on_file: callback invoked for each discovered file
/// 使用规范化路径（canonicalize）跟踪已访问目录，防止 junction/symlink 循环
/// Uses canonicalized paths to track visited directories, preventing junction/symlink loops
fn walk_recursive(
    dir: &PathBuf,
    exclusions: &std::collections::HashSet<String>,
    extensions: &Option<std::collections::HashSet<String>>,
    cancel: &AtomicBool,
    depth: u32,
    visited: &mut std::collections::HashSet<PathBuf>,
    on_file: &mut dyn FnMut(&str),
) {
    // 深度保护 / Depth protection
    if depth > 32 {
        return;
    }

    if cancel.load(Ordering::SeqCst) {
        return;
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries {
        if cancel.load(Ordering::SeqCst) {
            return;
        }

        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let path = entry.path();
        if let Some(name) = path.file_name() {
            let name_lower = name.to_string_lossy().to_lowercase();
            // 跳过排除目录 / Skip excluded directories
            if path.is_dir() && exclusions.contains(&name_lower) {
                continue;
            }
        }

        if path.is_dir() {
            // 用规范化路径检测 junction/symlink 循环
            // Detect junction/symlink loops via canonicalized path
            if let Ok(canonical) = path.canonicalize() {
                if !visited.insert(canonical) {
                    continue; // 已访问过该目录 / Already visited this directory
                }
            }
            walk_recursive(
                &path,
                exclusions,
                extensions,
                cancel,
                depth + 1,
                visited,
                on_file,
            );
        } else if path.is_file() {
            // 扩展名过滤 / Extension filter
            if let Some(ref ext_set) = extensions {
                if let Some(ext) = path.extension() {
                    let ext_lower = ext.to_string_lossy().to_lowercase();
                    if !ext_set.contains(&ext_lower) {
                        continue;
                    }
                } else {
                    continue; // 无扩展名文件跳过 / Skip files without extension
                }
            }
            on_file(&path.to_string_lossy());
        }
    }
}
