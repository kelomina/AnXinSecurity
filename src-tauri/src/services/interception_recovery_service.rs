// 拦截挂起恢复服务 — 记录已挂起 PID，并在应用异常退出后的下次启动尝试自愈恢复。
// Interception recovery service — records suspended PIDs and resumes them after abnormal app exits.
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::services::interception_service::InterceptionEntry;
use crate::services::process_control_service::{
    query_process_identity, resume_process_by_pid, ProcessIdentity,
};
use crate::services::runtime_list_store::{load_runtime_list, save_runtime_list};

const SUSPENDED_PROCESS_LEDGER_FILE: &str = "interception_suspended_processes.json";
const SUSPENDED_PROCESS_LEDGER_LEGACY_FIELD: &str = "__interceptionSuspendedProcesses";
const SUSPENDED_PROCESS_LEDGER_VERSION: u8 = 1;

/// 已挂起进程恢复记录 / Suspended process recovery record
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SuspendedProcessRecord {
    pub version: u8,
    pub pid: u32,
    #[serde(rename = "processName")]
    pub process_name: String,
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "imagePath")]
    pub image_path: String,
    #[serde(rename = "creationTime100ns")]
    pub creation_time_100ns: u64,
    #[serde(rename = "suspendedAtMs")]
    pub suspended_at_ms: u64,
    pub reason: String,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct InterceptionRecoverySummary {
    pub loaded_records: usize,
    pub recovered: usize,
    pub stale_or_exited: usize,
    pub failed: usize,
}

/// 函数名称：record_interception_suspension
/// 函数作用：把已经成功挂起的进程写入 APPDATA 运行期恢复台账，避免本程序崩溃后丢失恢复线索。
/// Function name: record_interception_suspension
/// Purpose: Persists a successfully suspended process to the APPDATA runtime recovery ledger.
pub(crate) fn record_interception_suspension(
    entry: &InterceptionEntry,
    identity: &ProcessIdentity,
) -> Result<(), String> {
    let mut records = load_suspended_records()?;
    let record = SuspendedProcessRecord {
        version: SUSPENDED_PROCESS_LEDGER_VERSION,
        pid: entry.pid,
        process_name: entry.process_name.clone(),
        file_path: entry.file_path.clone(),
        image_path: identity.image_path.clone(),
        creation_time_100ns: identity.creation_time_100ns,
        suspended_at_ms: current_unix_ms(),
        reason: entry.reason.clone(),
    };

    records.retain(|existing| existing.pid != entry.pid);
    records.push(record);
    save_suspended_records(&records)
}

/// 函数名称：remove_interception_suspension
/// 函数作用：拦截决策完成后，从恢复台账移除指定 PID。
/// Function name: remove_interception_suspension
/// Purpose: Removes one PID from the recovery ledger after the interception decision completes.
pub(crate) fn remove_interception_suspension(pid: u32) -> Result<(), String> {
    let mut records = load_suspended_records()?;
    records.retain(|record| record.pid != pid);
    save_suspended_records(&records)
}

/// 函数名称：retain_interception_suspensions
/// 函数作用：仅保留仍需下次启动继续尝试恢复的 PID。
/// Function name: retain_interception_suspensions
/// Purpose: Keeps only PIDs that should be retried during the next startup recovery.
pub(crate) fn retain_interception_suspensions(pids_to_keep: &[u32]) -> Result<(), String> {
    let mut records = load_suspended_records()?;
    records.retain(|record| pids_to_keep.contains(&record.pid));
    save_suspended_records(&records)
}

/// 函数名称：clear_interception_suspensions
/// 函数作用：清空恢复台账。
/// Function name: clear_interception_suspensions
/// Purpose: Clears the recovery ledger.
pub(crate) fn clear_interception_suspensions() -> Result<(), String> {
    save_suspended_records(&[])
}

/// 函数名称：recover_suspended_processes_from_ledger
/// 函数作用：应用启动时读取上次残留的挂起台账，确认 PID 未复用后恢复目标进程。
/// Function name: recover_suspended_processes_from_ledger
/// Purpose: On startup, resumes stale suspended processes after verifying that each PID still identifies the same process.
#[allow(dead_code)]
pub(crate) fn recover_suspended_processes_from_ledger(
) -> Result<InterceptionRecoverySummary, String> {
    let records = load_suspended_records()?;
    let mut summary = InterceptionRecoverySummary {
        loaded_records: records.len(),
        ..InterceptionRecoverySummary::default()
    };
    if records.is_empty() {
        return Ok(summary);
    }

    let mut failed_retry_pids = Vec::new();

    for record in &records {
        match query_process_identity(record.pid) {
            Ok(identity) if is_same_process_record(record, &identity) => {
                match resume_process_by_pid(record.pid) {
                    Ok(_) => summary.recovered += 1,
                    Err(err) => {
                        summary.failed += 1;
                        failed_retry_pids.push(record.pid);
                        eprintln!(
                            "[InterceptionRecovery] Failed to resume stale suspended PID {} ({}): {}",
                            record.pid, record.process_name, err
                        );
                    }
                }
            }
            Ok(_) => {
                summary.stale_or_exited += 1;
                eprintln!(
                    "[InterceptionRecovery] Dropping stale suspension record for reused PID {} ({})",
                    record.pid, record.process_name
                );
            }
            Err(_) => {
                summary.stale_or_exited += 1;
            }
        }
    }

    if failed_retry_pids.is_empty() {
        clear_interception_suspensions()?;
    } else {
        retain_interception_suspensions(&failed_retry_pids)?;
    }

    Ok(summary)
}

fn load_suspended_records() -> Result<Vec<SuspendedProcessRecord>, String> {
    load_runtime_list(
        SUSPENDED_PROCESS_LEDGER_FILE,
        SUSPENDED_PROCESS_LEDGER_LEGACY_FIELD,
    )
}

fn save_suspended_records(records: &[SuspendedProcessRecord]) -> Result<(), String> {
    save_runtime_list(SUSPENDED_PROCESS_LEDGER_FILE, records)
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn is_same_process_record(record: &SuspendedProcessRecord, identity: &ProcessIdentity) -> bool {
    record.pid == identity.pid
        && record.creation_time_100ns == identity.creation_time_100ns
        && normalize_recovery_path(&record.image_path)
            == normalize_recovery_path(&identity.image_path)
}

fn normalize_recovery_path(path: &str) -> String {
    let mut normalized: String = path
        .trim()
        .chars()
        .map(|ch| {
            if ch == '/' {
                '\\'
            } else {
                ch.to_ascii_lowercase()
            }
        })
        .collect();
    if normalized.starts_with("\\\\?\\") {
        normalized = normalized[4..].to_string();
    }
    if normalized.starts_with("\\??\\") {
        normalized = normalized[4..].to_string();
    }
    while normalized.ends_with('\\') && normalized.len() > 3 {
        normalized.pop();
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(pid: u32, image_path: &str, creation_time_100ns: u64) -> SuspendedProcessRecord {
        SuspendedProcessRecord {
            version: SUSPENDED_PROCESS_LEDGER_VERSION,
            pid,
            process_name: "demo.exe".to_string(),
            file_path: image_path.to_string(),
            image_path: image_path.to_string(),
            creation_time_100ns,
            suspended_at_ms: 1000,
            reason: "test".to_string(),
        }
    }

    #[test]
    fn recovery_identity_matches_same_pid_creation_time_and_path() {
        let rec = record(1234, r"\\?\C:\Temp\Demo.exe", 42);
        let identity = ProcessIdentity {
            pid: 1234,
            image_path: r"c:/temp/demo.exe".to_string(),
            creation_time_100ns: 42,
        };

        assert!(is_same_process_record(&rec, &identity));
    }

    #[test]
    fn recovery_identity_rejects_pid_reuse() {
        let rec = record(1234, r"C:\Temp\Demo.exe", 42);
        let identity = ProcessIdentity {
            pid: 1234,
            image_path: r"C:\Temp\Demo.exe".to_string(),
            creation_time_100ns: 43,
        };

        assert!(!is_same_process_record(&rec, &identity));
    }

    #[test]
    fn recovery_path_normalization_strips_nt_prefix_and_trailing_slash() {
        assert_eq!(
            normalize_recovery_path(r"\\?\C:/Temp/Demo.exe\"),
            r"c:\temp\demo.exe"
        );
        assert_eq!(
            normalize_recovery_path(r"\??\C:\Temp\Demo.exe"),
            r"c:\temp\demo.exe"
        );
    }
}
