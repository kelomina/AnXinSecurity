use libloading::{Library, Symbol};
use std::os::windows::ffi::OsStrExt;

type ProcessWatcherStartFn = unsafe extern "C" fn(
    injector_x64: *const u16,
    injector_x86: *const u16,
    dll_x64: *const u16,
    dll_x86: *const u16,
    interval_ms: i32,
) -> i32;
type ProcessWatcherStopFn = unsafe extern "C" fn();
type ProcessWatcherSetSignedListFn = unsafe extern "C" fn(data: *const u16, length: i32) -> i32;
type ProcessWatcherPollNewPidFn = unsafe extern "C" fn() -> i32;

pub struct ProcessWatcher {
    lib: Library,
}

impl ProcessWatcher {
    pub fn new() -> Result<Self, String> {
        let dll_paths = vec![
            "../native/bin/win32-x64/process_watcher.dll",
        ];

        let mut last_error = None;
        for path in dll_paths {
            match unsafe { Library::new(path) } {
                Ok(lib) => return Ok(Self { lib }),
                Err(e) => {
                    last_error = Some(e);
                    continue;
                }
            }
        }

        Err(last_error.map(|e| e.to_string()).unwrap_or_else(|| "No valid process watcher DLL found".to_string()))
    }

    pub fn start(
        &self,
        injector_x64: &str,
        injector_x86: &str,
        dll_x64: &str,
        dll_x86: &str,
        interval_ms: u32,
    ) -> Result<bool, String> {
        unsafe {
            let start_fn: Symbol<ProcessWatcherStartFn> = self.lib.get(b"ProcessWatcher_Start")
                .map_err(|e| format!("Failed to load ProcessWatcher_Start: {}", e))?;

            let result = start_fn(
                wide_string(injector_x64).as_ptr(),
                wide_string(injector_x86).as_ptr(),
                wide_string(dll_x64).as_ptr(),
                wide_string(dll_x86).as_ptr(),
                interval_ms as i32,
            );

            Ok(result == 1)
        }
    }

    pub fn stop(&self) -> Result<(), String> {
        unsafe {
            let stop_fn: Symbol<ProcessWatcherStopFn> = self.lib.get(b"ProcessWatcher_Stop")
                .map_err(|e| format!("Failed to load ProcessWatcher_Stop: {}", e))?;

            stop_fn();
            Ok(())
        }
    }

    pub fn set_signed_list(&self, paths: &[String]) -> Result<u32, String> {
        let data = paths.join("\n");
        let wide_data = wide_string(&data);

        unsafe {
            let set_fn: Symbol<ProcessWatcherSetSignedListFn> = self.lib.get(b"ProcessWatcher_SetSignedList")
                .map_err(|e| format!("Failed to load ProcessWatcher_SetSignedList: {}", e))?;

            let result = set_fn(wide_data.as_ptr(), wide_data.len() as i32);
            Ok(result as u32)
        }
    }

    pub fn poll_new_pid(&self) -> Result<u32, String> {
        unsafe {
            let poll_fn: Symbol<ProcessWatcherPollNewPidFn> = self.lib.get(b"ProcessWatcher_PollNewPid")
                .map_err(|e| format!("Failed to load ProcessWatcher_PollNewPid: {}", e))?;

            let pid = poll_fn();
            Ok(pid as u32)
        }
    }
}

fn wide_string(s: &str) -> Vec<u16> {
    std::ffi::OsString::from(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
