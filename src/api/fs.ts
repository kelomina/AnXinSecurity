/**
 * 文件系统 API 封装
 * File system API wrapper
 *
 * 封装后台目录遍历操作（流式推送事件）。
 * Wraps background directory walk operations (streaming events).
 */
import { invoke } from '@tauri-apps/api/core'
import { listen, UnlistenFn } from '@tauri-apps/api/event'

/**
 * 函数名称：startBackgroundWalk
 * 函数作用：启动后台目录遍历，通过 Tauri Events 流式推送文件路径。
 *   每收集到一批文件会触发 walk-file-batch 事件；
 *   遍历完成时触发 walk-complete 事件。
 * Purpose: Starts a background directory walk, streaming file paths via Tauri Events.
 *   walk-file-batch event fires for each batch of files;
 *   walk-complete event fires when traversal finishes.
 * 调用方：ScanPage handleSelectDirectory
 * Called by: ScanPage handleSelectDirectory
 * 参数 path: 根目录路径
 * 参数 exclusions: 要排除的目录名列表
 * 参数 extensions: 仅收集指定扩展名文件（可选）
 */
export async function startBackgroundWalk(
  path: string,
  exclusions?: string[],
  extensions?: string[]
): Promise<void> {
  return await invoke('start_background_walk', { path, exclusions, extensions })
}

/**
 * 函数名称：cancelWalk
 * 函数作用：取消当前正在进行的后台目录遍历。
 * Purpose: Cancels the currently ongoing background directory walk.
 * 调用方：ScanPage
 * Called by: ScanPage
 */
export async function cancelWalk(): Promise<boolean> {
  return await invoke('cancel_walk')
}

/**
 * 函数名称：onWalkFileBatch
 * 函数作用：监听 walk-file-batch 事件，接收后台遍历推送的文件批次。
 * Purpose: Listens for walk-file-batch events for file batches from background walk.
 * 调用方：ScanPage handleSelectDirectory
 * Called by: ScanPage handleSelectDirectory
 * 参数 callback: 接收文件路径数组的回调函数
 * 返回值：取消监听的清理函数
 */
export function onWalkFileBatch(
  callback: (files: string[]) => void
): () => void {
  let unlisten: UnlistenFn | null = null
  let disposed = false

  listen<string[]>('walk-file-batch', (event) => {
    callback(event.payload)
  }).then((fn) => {
    if (disposed) {
      fn()
    } else {
      unlisten = fn
    }
  })

  return () => {
    disposed = true
    if (unlisten) {
      unlisten()
    }
  }
}

/**
 * 函数名称：onWalkComplete
 * 函数作用：监听 walk-complete 事件，接收后台遍历完成的信号。
 * Purpose: Listens for walk-complete event signaling background walk completion.
 * 调用方：ScanPage handleSelectDirectory
 * Called by: ScanPage handleSelectDirectory
 * 参数 callback: 接收 { path } 的回调函数
 * 返回值：取消监听的清理函数
 */
export function onWalkComplete(
  callback: (payload: { path: string }) => void
): () => void {
  let unlisten: UnlistenFn | null = null
  let disposed = false

  listen('walk-complete', (event) => {
    callback(event.payload as { path: string })
  }).then((fn) => {
    if (disposed) {
      fn()
    } else {
      unlisten = fn
    }
  })

  return () => {
    disposed = true
    if (unlisten) {
      unlisten()
    }
  }
}
