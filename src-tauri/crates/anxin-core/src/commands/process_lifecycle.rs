// 进程生命周期监控命令 — 前端与 ProcessLifecycleService 之间的薄转发层
//  Process lifecycle monitoring commands - a thin forwarding layer between the
//  frontend and ProcessLifecycleService
//
// 按 AGENTS.md 的分层要求，这里只做参数校验和透传，不写任何业务逻辑。
//  Per the layering rule in AGENTS.md this file only validates and forwards;
//  no business logic lives here.
//
// 三个命令都是只读查询（§4.6），与 behavior_v2 的查询类命令一致，不接 IPC
//  methods：独立模式下直接读本进程管理的服务状态；服务进程模式下 UI 进程没有
//  驱动句柄，返回降级默认值而非报错。
//  All three commands are read-only queries (§4.6), consistent with the
//  behavior_v2 query commands, and do not use IPC methods: standalone mode reads
//  the locally managed service; service mode has no driver handle in the UI
//  process and degrades to defaults instead of erroring.
//
// 中文关键词：进程生命周期命令，状态查询，进程树，事件列表
// English keywords: process lifecycle commands, status query, process tree, event list
use std::sync::Arc;

use crate::services::process_lifecycle_service::ProcessLifecycleService;
use serde::Serialize;
use tauri::{AppHandle, Manager, Runtime};

// ============================================================================
// 响应结构 / Response structures
// ============================================================================

/// 健康状态（§4.6 get_proc_monitor_health）
///  Health status (§4.6 get_proc_monitor_health)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcMonitorHealth {
    pub connected: bool,
    pub driver_major: u32,
    pub driver_minor: u32,
    pub driver_patch: u32,
    pub lifecycle_depth: u32,
    pub behavior_depth: u32,
    pub lifecycle_dropped: u64,
    pub behavior_dropped: u64,
    pub last_callback_tick_ms: u64,
    pub probe_total: u32,
    pub probe_reported_ok: u32,
    pub probe_missed_rounds: u32,
    pub tampered_alerts: u32,
    pub last_reconcile_count: u32,
    pub table_size: usize,
}

/// 进程树节点（get_process_tree）
///  Process-tree node (get_process_tree)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessTreeNode {
    pub pid: u32,
    pub parent_pid: u32,
    pub session_id: u32,
    pub create_time: u64,
    pub restored: bool,
    pub image_path: Option<String>,
    pub alive: bool,
    pub children: Vec<ProcessTreeNode>,
}

/// 生命周期事件（list_lifecycle_events）
///  Lifecycle event (list_lifecycle_events)
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleEventDto {
    pub pid: u32,
    pub parent_pid: u32,
    pub event_type: u16,
    pub event_time: u64,
    pub ts_ms: u64,
    pub session_id: u32,
    pub exit_status: u32,
    pub flags: u16,
    pub image_path: Option<String>,
    pub restored: bool,
}

// ============================================================================
// 内部辅助 / Internal helpers
// ============================================================================

/// 取本进程管理的 ProcessLifecycleService。
///  Resolves the ProcessLifecycleService managed by this process.
fn local_service<R: Runtime>(
    app_handle: &AppHandle<R>,
) -> Option<Arc<ProcessLifecycleService>> {
    app_handle
        .try_state::<Arc<ProcessLifecycleService>>()
        .map(|state| state.inner().clone())
}

/// 把状态表条目组装成进程树（以存活进程为根；孤儿进程挂在 pid 0 虚拟根下）。
///  Builds a process tree from the table (live processes as roots; orphans
///  hang under the virtual pid-0 root).
fn build_tree(entries: Vec<crate::services::process_lifecycle_service::ProcessEntry>) -> Vec<ProcessTreeNode> {
    // 先建 pid → 节点映射，再挂接父子关系
    let mut nodes: std::collections::HashMap<u32, ProcessTreeNode> = entries
        .iter()
        .map(|e| {
            (
                e.pid,
                ProcessTreeNode {
                    pid: e.pid,
                    parent_pid: e.parent_pid,
                    session_id: e.session_id,
                    create_time: e.create_time,
                    restored: e.restored,
                    image_path: e.image_path.clone(),
                    alive: e.alive,
                    children: Vec::new(),
                },
            )
        })
        .collect();

    let mut roots: Vec<ProcessTreeNode> = Vec::new();
    let pids: Vec<u32> = nodes.keys().copied().collect();
    for pid in pids {
        let (node, parent) = {
            let n = nodes.get(&pid).unwrap();
            let p = n.parent_pid;
            (n.clone(), p)
        };
        if parent != 0 && nodes.contains_key(&parent) {
            if let Some(pnode) = nodes.get_mut(&parent) {
                pnode.children.push(node);
            }
        } else {
            roots.push(node);
        }
    }

    // 稳定排序：按 PID 升序
    fn sort_tree(node: &mut ProcessTreeNode) {
        node.children.sort_by_key(|c| c.pid);
        for c in &mut node.children {
            sort_tree(c);
        }
    }
    roots.sort_by_key(|r| r.pid);
    for r in &mut roots {
        sort_tree(r);
    }
    roots
}

// ============================================================================
// 命令 / Commands
// ============================================================================

/// 函数名称：get_proc_monitor_health
/// 函数作用：查询进程监控采集模块的健康状态与探针统计（§4.6 get_proc_monitor_health）。
/// Purpose: Queries the process monitor health and probe statistics (§4.6).
/// 调用方：前端 ProcessLifecyclePage
/// Called by: the frontend ProcessLifecyclePage
/// 返回值：ProcMonitorHealth；服务不可用时返回 connected=false 的全零状态
/// Returns: ProcMonitorHealth; a missing service yields an all-zero status
/// 中文关键词：进程监控健康，探针统计，降级展示
/// English keywords: process monitor health, probe stats, degraded display
#[tauri::command]
pub fn get_proc_monitor_health<R: Runtime>(
    app_handle: AppHandle<R>,
) -> Result<ProcMonitorHealth, String> {
    let Some(service) = local_service(&app_handle) else {
        return Ok(ProcMonitorHealth {
            connected: false,
            driver_major: 0,
            driver_minor: 0,
            driver_patch: 0,
            lifecycle_depth: 0,
            behavior_depth: 0,
            lifecycle_dropped: 0,
            behavior_dropped: 0,
            last_callback_tick_ms: 0,
            probe_total: 0,
            probe_reported_ok: 0,
            probe_missed_rounds: 0,
            tampered_alerts: 0,
            last_reconcile_count: 0,
            table_size: 0,
        });
    };

    let stats = service.probe_stats();
    let version = service
        .driver_version()
        .map(|v| (v.driver_major, v.driver_minor, v.driver_patch))
        .unwrap_or((0, 0, 0));
    let health = service.driver_health();

    Ok(ProcMonitorHealth {
        connected: service.is_connected(),
        driver_major: version.0,
        driver_minor: version.1,
        driver_patch: version.2,
        lifecycle_depth: health.map(|h| h.lifecycle_depth).unwrap_or(0),
        behavior_depth: health.map(|h| h.behavior_depth).unwrap_or(0),
        lifecycle_dropped: health.map(|h| h.events_lifecycle_dropped).unwrap_or(0),
        behavior_dropped: health.map(|h| h.events_behavior_dropped).unwrap_or(0),
        last_callback_tick_ms: health.map(|h| h.last_callback_tick_ms).unwrap_or(0),
        probe_total: stats.total_launched,
        probe_reported_ok: stats.reported_ok,
        probe_missed_rounds: stats.missed_rounds,
        tampered_alerts: stats.tampered_alerts,
        last_reconcile_count: stats.last_reconcile_count,
        table_size: service.process_table_snapshot().len(),
    })
}

/// 函数名称：get_process_tree
/// 函数作用：返回当前状态表的进程树（父子链 + 存活/孤儿标记，§4.6 get_process_tree）。
/// Purpose: Returns the process tree from the current table (§4.6 get_process_tree).
/// 调用方：前端 ProcessLifecyclePage
/// Called by: the frontend ProcessLifecyclePage
/// 中文关键词：进程树，父子链，孤儿标记
/// English keywords: process tree, parent-child chain, orphan marking
#[tauri::command]
pub fn get_process_tree<R: Runtime>(
    app_handle: AppHandle<R>,
) -> Result<Vec<ProcessTreeNode>, String> {
    let Some(service) = local_service(&app_handle) else {
        return Ok(Vec::new());
    };
    Ok(build_tree(service.process_table_snapshot()))
}

/// 函数名称：list_lifecycle_events
/// 函数作用：返回最近的进程生命周期事件（§4.6 list_lifecycle_events，前端 500 条上限）。
/// Purpose: Returns the most recent lifecycle events (§4.6; frontend caps at 500).
/// 调用方：前端 ProcessLifecyclePage
/// Called by: the frontend ProcessLifecyclePage
/// 中文关键词：生命周期事件，历史查询
/// English keywords: lifecycle events, history query
#[tauri::command]
pub fn list_lifecycle_events<R: Runtime>(
    app_handle: AppHandle<R>,
    limit: Option<usize>,
) -> Result<Vec<LifecycleEventDto>, String> {
    let Some(service) = local_service(&app_handle) else {
        return Ok(Vec::new());
    };
    let cap = limit.unwrap_or(500).min(500);
    Ok(service
        .recent_events(cap)
        .into_iter()
        .map(|r| LifecycleEventDto {
            pid: r.pid,
            parent_pid: r.parent_pid,
            event_type: r.event_type,
            event_time: r.event_time,
            ts_ms: r.ts_ms,
            session_id: r.session_id,
            exit_status: r.exit_status,
            flags: r.flags,
            image_path: r.image_path,
            restored: r.restored,
        })
        .collect())
}
