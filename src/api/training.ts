/**
 * 训练 API 封装
 * Training API wrapper
 */
import { invoke } from '@tauri-apps/api/core'

export async function trainFromPath(path: string): Promise<boolean> {
  return await invoke('train_from_path', { path })
}

export async function getTrainingStatus(): Promise<string> {
  return await invoke('get_training_status')
}

export async function cancelTraining(): Promise<boolean> {
  return await invoke('cancel_training')
}
