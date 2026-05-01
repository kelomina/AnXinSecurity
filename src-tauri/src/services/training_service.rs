// ML 训练服务 — 管理扫描引擎的机器学习训练任务
// ML training service — manages machine learning training tasks for the scan engine
use std::sync::{Arc, Mutex};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::services::engine_service::EngineService;

/// 训练任务状态 / Training task status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TrainingStatus {
    /// 空闲 / Idle
    #[serde(rename = "idle")]
    Idle,
    /// 训练中 / Training
    #[serde(rename = "training")]
    Training,
    /// 已完成 / Completed
    #[serde(rename = "completed")]
    Completed,
    /// 失败 / Failed
    #[serde(rename = "failed")]
    Failed,
}

/// ML 训练服务
/// ML training service
pub struct TrainingService {
    /// 训练状态 / Training status
    status: Arc<Mutex<TrainingStatus>>,
}

impl TrainingService {
    /// 函数名称：new
    /// 函数作用：创建 TrainingService 实例。
    /// Purpose: Creates a TrainingService instance.
    /// Called by: main.rs setup()
    /// 中文关键词：训练服务，机器学习，初始化
    /// English keywords: training service, machine learning, initialization
    pub fn new() -> Self {
        Self {
            status: Arc::new(Mutex::new(TrainingStatus::Idle)),
        }
    }

    /// 函数名称：train_from_path
    /// 函数作用：从指定路径加载样本并提交训练任务。
    /// Purpose: Loads samples from the specified path and submits training task.
    /// Called by: commands::training::train_from_path
    /// 参数 path: 训练样本目录路径 / Training samples directory path
    /// 参数 engine: 扫描引擎服务 / Scan engine service
    /// 参数 app_handle: Tauri 应用句柄 / Tauri app handle
    /// 副作用：向前端 emit("train-progress") 推送训练进度
    /// 中文关键词：训练样本，提交训练，机器学习训练
    /// English keywords: training samples, submit training, machine learning training
    pub async fn train_from_path(
        &self,
        path: &str,
        engine: &EngineService,
        app_handle: &AppHandle,
    ) -> Result<(), String> {
        // 设置状态为训练中 / Set status to training
        {
            let mut status = self.status.lock().map_err(|e| e.to_string())?;
            *status = TrainingStatus::Training;
        }

        // 收集样本文件 / Collect sample files
        let sample_paths = collect_training_samples(path)?;
        let total = sample_paths.len() as u32;

        if total == 0 {
            let mut status = self.status.lock().map_err(|e| e.to_string())?;
            *status = TrainingStatus::Completed;
            return Err("未找到训练样本文件".to_string());
        }

        // 通知前端训练开始 / Notify frontend training started
        let _ = app_handle.emit("train-progress", serde_json::json!({
            "current": 0,
            "total": total,
            "percentage": 0.0,
            "status": "training",
        }));

        // 逐文件提交训练 / Submit training file by file
        let mut success_count: u32 = 0;
        for (i, sample_path) in sample_paths.iter().enumerate() {
            let current = (i + 1) as u32;
            let percentage = (current as f32 / total as f32) * 100.0;

            // 调用扫描引擎的训练命令 / Call scan engine's training command
            let train_result = engine.scan_file(
                sample_path,
                serde_json::json!({"mode": "training"}),
            ).await;

            match train_result {
                Ok(_) => success_count += 1,
                Err(e) => {
                    eprintln!("[TrainingService] Training failed for {}: {}", sample_path, e);
                }
            }

            // 推送进度 / Push progress
            let _ = app_handle.emit("train-progress", serde_json::json!({
                "current": current,
                "total": total,
                "currentFile": sample_path,
                "percentage": percentage,
                "status": "training",
            }));
        }

        // 训练完成 / Training completed
        let (final_status, message) = if success_count == total {
            (TrainingStatus::Completed, format!("训练完成：成功处理 {}/{} 个样本", success_count, total))
        } else if success_count > 0 {
            (TrainingStatus::Completed, format!("训练部分完成：成功 {}/{} 个样本，{} 个失败", success_count, total, total - success_count))
        } else {
            (TrainingStatus::Failed, "训练失败：所有样本处理失败".to_string())
        };

        {
            let mut status = self.status.lock().map_err(|e| e.to_string())?;
            *status = final_status.clone();
        }

        let _ = app_handle.emit("train-progress", serde_json::json!({
            "current": total,
            "total": total,
            "percentage": 100.0,
            "status": final_status,
            "message": message,
        }));

        Ok(())
    }

    /// 函数名称：get_status
    /// 函数作用：获取当前训练状态。
    /// Purpose: Gets the current training status.
    /// Called by: commands::training::get_training_status
    pub fn get_status(&self) -> TrainingStatus {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// 函数名称：reset
    /// 函数作用：重置训练状态为空闲。
    /// Purpose: Resets training status to idle.
    /// Called by: commands::training::cancel_training
    pub fn reset(&self) {
        *self.status.lock().unwrap_or_else(|e| e.into_inner()) = TrainingStatus::Idle;
    }
}

/// 收集训练样本文件 / Collect training sample files
/// Recursively collects executable files from the given directory
fn collect_training_samples(path: &str) -> Result<Vec<String>, String> {
    let mut samples = Vec::new();
    let mut visited = std::collections::HashSet::<std::path::PathBuf>::new();
    if let Ok(canonical) = std::path::Path::new(path).canonicalize() {
        visited.insert(canonical);
    }
    collect_samples_recursive(std::path::Path::new(path), &mut samples, &mut visited, 0)?;
    Ok(samples)
}

/// 递归收集可执行文件 / Recursively collect executable files
fn collect_samples_recursive(
    dir: &std::path::Path,
    samples: &mut Vec<String>,
    visited: &mut std::collections::HashSet<std::path::PathBuf>,
    depth: u32,
) -> Result<(), String> {
    // 深度保护，防止极深目录或 junction 循环导致栈溢出
    // Depth protection against extremely deep directories or junction loops
    const MAX_DEPTH: u32 = 32;
    if depth > MAX_DEPTH {
        return Ok(());
    }

    if !dir.exists() {
        return Ok(());
    }

    let entries = std::fs::read_dir(dir).map_err(|e| format!("读取目录失败: {}", e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("读取条目失败: {}", e))?;
        let path = entry.path();

        if path.is_dir() {
            // 用规范化路径检测 junction 循环
            // Detect junction loops via canonicalized path
            if let Ok(canonical) = path.canonicalize() {
                if !visited.insert(canonical) {
                    continue;
                }
            }
            collect_samples_recursive(&path, samples, visited, depth + 1)?;
        } else if path.is_file() {
            if let Some(ext) = path.extension() {
                let ext_lower = ext.to_string_lossy().to_lowercase();
                if ["exe", "dll", "sys", "bat", "ps1", "vbs", "js"].contains(&ext_lower.as_str()) {
                    samples.push(path.to_string_lossy().to_string());
                }
            }
        }
    }

    Ok(())
}
