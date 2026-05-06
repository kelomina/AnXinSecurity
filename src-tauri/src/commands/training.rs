// 训练命令 — ML 模型训练操作
// Training commands — ML model training operations
use crate::services::engine_service::EngineService;
use crate::services::training_service::TrainingService;
use std::sync::Arc;

/// 函数名称：train_from_path
/// 函数作用：从指定目录加载训练样本并提交训练任务。
/// Purpose: Loads training samples from the specified directory and submits training task.
/// 参数 path: 训练样本目录路径 / Training samples directory path
/// 参数 engine: 扫描引擎服务 / Scan engine service
/// 参数 training: 训练服务 / Training service
/// 参数 app_handle: Tauri 应用句柄 / Tauri app handle
/// 副作用：向前端 emit("train-progress") 推送训练进度
/// 调用方：前端 SettingsPage 训练功能
/// Called by: Frontend SettingsPage training feature
/// 中文关键词：训练模型，机器学习，样本训练，模型训练
/// English keywords: train model, machine learning, sample training, model training
#[tauri::command]
pub async fn train_from_path(
    path: String,
    engine: tauri::State<'_, Arc<EngineService>>,
    training: tauri::State<'_, TrainingService>,
    app_handle: tauri::AppHandle,
) -> Result<bool, String> {
    let eng = engine.clone();
    training
        .train_from_path(&path, eng.as_ref(), &app_handle)
        .await?;
    Ok(true)
}

/// 函数名称：get_training_status
/// 函数作用：获取当前训练任务状态。
/// Purpose: Gets the current training task status.
/// 调用方：前端轮询训练进度
/// Called by: Frontend polling training progress
/// 中文关键词：训练状态，训练进度查询
/// English keywords: training status, training progress query
#[tauri::command]
pub async fn get_training_status(
    training: tauri::State<'_, TrainingService>,
) -> Result<String, String> {
    let status = training.get_status();
    Ok(serde_json::to_string(&status).unwrap_or_else(|_| "\"idle\"".to_string()))
}

/// 函数名称：cancel_training
/// 函数作用：取消当前训练任务，重置状态为空闲。
/// Purpose: Cancels the current training task, resets status to idle.
/// 调用方：前端取消训练按钮
/// Called by: Frontend cancel training button
/// 中文关键词：取消训练，重置训练状态
/// English keywords: cancel training, reset training status
#[tauri::command]
pub async fn cancel_training(training: tauri::State<'_, TrainingService>) -> Result<bool, String> {
    training.reset();
    Ok(true)
}
