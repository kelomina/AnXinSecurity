/**
 * 元核防护状态仓库
 * Hypervisor protection state store
 *
 * 持有元核防护运行状态，并负责开关切换的「写配置 → 启停驱动 → 回读状态」流程。
 * Holds the hypervisor runtime status and drives the toggle flow:
 * persist config → start/stop driver → read back real status.
 *
 * 按 AGENTS.md 的分层要求，本层只做状态管理，不直接 invoke，全部经 src/api/hypervisor.ts。
 * Per the layering rule in AGENTS.md this layer only manages state; it never
 * calls invoke directly and always goes through src/api/hypervisor.ts.
 *
 * 中文关键词：元核防护仓库，乐观更新，失败回滚，回读校验
 * English keywords: hypervisor store, optimistic update, rollback, read-back
 */
import { create } from 'zustand'
import {
  EMPTY_HYPERVISOR_STATUS,
  getHypervisorStatus,
  setHypervisorEnabled,
  startHypervisor,
  stopHypervisor,
  type HypervisorStatus,
} from '../api/hypervisor'

interface HypervisorState {
  /** 后端真实运行状态 / Real backend runtime status */
  status: HypervisorStatus
  /** 正在进行的写操作，用于禁用按钮 / In-flight write operation, used to disable buttons */
  controlPending: boolean
  /** 最近一次操作的错误信息 / Error from the most recent operation */
  controlError: string | null

  refreshStatus: () => Promise<void>
  setEnabled: (enabled: boolean) => Promise<void>
  clearError: () => void
}

/** 把后端错误统一成可读文案 / Normalizes a backend error into readable text */
function describeError(action: string, error: unknown): string {
  const detail = error instanceof Error ? error.message : String(error)
  return `${action}: ${detail}`
}

export const useHypervisorStore = create<HypervisorState>((set, get) => ({
  status: EMPTY_HYPERVISOR_STATUS,
  controlPending: false,
  controlError: null,

  /**
   * 函数名称：refreshStatus
   * 函数作用：拉取元核防护运行状态。
   * Purpose: Fetches the hypervisor runtime status.
   * 错误处理：失败时回落到全 false 的占位状态而不是抛出 —— 界面需要能显示"未运行"。
   * Error handling: falls back to the all-false placeholder rather than throwing,
   *                 because the UI still needs to render "not running".
   * 中文关键词：状态刷新，降级展示
   * English keywords: status refresh, degraded display
   */
  refreshStatus: async () => {
    try {
      set({ status: await getHypervisorStatus() })
    } catch (e) {
      console.error('[hypervisorStore] Failed to read hypervisor status:', e)
      set({ status: EMPTY_HYPERVISOR_STATUS })
    }
  },

  /**
   * 函数名称：setEnabled
   * 函数作用：切换元核防护总开关，先乐观更新界面，失败时回滚。
   * Purpose: Toggles the master switch with an optimistic UI update and rollback
   *          on failure.
   *
   * 顺序是「写配置 → 拉起/停止驱动 → 回读真实状态」。回读这一步不能省：
   * 配置写成功但驱动没装或环境检查不通过时，开关会停在"已开启"而实际并没有接管，
   * 必须让界面显示驱动未连接。
   * The order is: persist config, start/stop the driver, then read the real
   * status back. That last step is essential — with the config saved but no
   * driver installed or the environment check failing, the switch would sit on
   * "enabled" while nothing is actually virtualized, so the UI must show that
   * the driver is not connected.
   *
   * 调用方：SettingsPage 的元核防护开关
   * Called by: the hypervisor switch in SettingsPage
   * 中文关键词：总开关，乐观更新，失败回滚，回读校验
   * English keywords: master switch, optimistic update, rollback, read-back
   */
  setEnabled: async (enabled: boolean) => {
    const previous = get().status
    set({ controlPending: true, controlError: null })

    try {
      await setHypervisorEnabled(enabled)
      if (enabled) {
        // 启动驱动会做环境检查 → 启动服务 → 连接设备 → 查询状态；
        // 任一步失败都会抛出，由 catch 分支回滚配置并展示错误。
        //  Starting the driver runs env check → start service → connect device
        // → query status; any failure throws and is rolled back in catch.
        const status = await startHypervisor()
        set({ status })
      } else {
        await stopHypervisor()
        set({ status: EMPTY_HYPERVISOR_STATUS })
      }
    } catch (e) {
      console.error('[hypervisorStore] Failed to toggle hypervisor protection:', e)
      // 配置或启动失败时，尝试把配置回滚到之前的状态，避免配置文件写着
      // enabled=true 而驱动实际没拉起，下次启动时 main.rs 会尝试自动启动。
      //  On failure, try to roll the config back so we don't end up with
      // enabled=true persisted while the driver is not up — otherwise main.rs
      // would try to auto-start it next launch.
      try {
        await setHypervisorEnabled(!enabled)
      } catch (rollbackErr) {
        console.error('[hypervisorStore] Failed to roll back hypervisor config:', rollbackErr)
      }
      set({
        status: previous,
        controlError: describeError(enabled ? 'enable' : 'disable', e),
      })
      throw e
    } finally {
      set({ controlPending: false })
    }
  },

  clearError: () => set({ controlError: null }),
}))
