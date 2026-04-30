import { invoke } from '@tauri-apps/api/core'
import { listen, UnlistenFn } from '@tauri-apps/api/event'

export interface EtwEvent {
  type: string
  timestamp: string
  pid: number
  tid: number
  provider: string
  data: any
}

export async function listEvents(query?: { pid?: number; limit?: number }): Promise<EtwEvent[]> {
  return await invoke('list_events', { query })
}

export async function pauseEtw(): Promise<void> {
  return await invoke('pause_etw')
}

export async function resumeEtw(): Promise<void> {
  return await invoke('resume_etw')
}

export async function clearAllEvents(): Promise<boolean> {
  return await invoke('clear_all_events')
}

export function onEtwEvent(
  callback: (event: EtwEvent) => void
): () => void {
  let unlisten: UnlistenFn | null = null

  listen('etw-event', (event) => {
    callback(event.payload as EtwEvent)
  }).then((fn) => {
    unlisten = fn
  })

  return () => {
    if (unlisten) {
      unlisten()
    }
  }
}
