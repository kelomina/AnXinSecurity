use libloading::{Library, Symbol};
use std::os::windows::ffi::OsStrExt;
use crate::models::event::EtwEvent;

// 定义 C 函数指针类型
type EtwBridgeCreateFn = unsafe extern "C" fn(session_name: *const u16) -> *mut std::os::raw::c_void;
type EtwBridgeStartFn = unsafe extern "C" fn(
    handle: *mut std::os::raw::c_void,
    process_any: u64,
    process_all: u64,
    file_any: u64,
    file_all: u64,
    registry_any: u64,
    registry_all: u64,
    network_any: u64,
    network_all: u64,
    network_enabled: i32,
    filter_private_ips: i32,
    skip_loopback: i32,
    user_data_max_bytes: u32,
) -> i32;
type EtwBridgeStopFn = unsafe extern "C" fn(handle: *mut std::os::raw::c_void, timeout_ms: u32) -> i32;
type EtwBridgePollJsonFn = unsafe extern "C" fn(
    handle: *mut std::os::raw::c_void,
    out_json: *mut *mut std::os::raw::c_char,
) -> i32;
type EtwBridgeFreeFn = unsafe extern "C" fn(p: *mut std::os::raw::c_void);
type EtwBridgeDestroyFn = unsafe extern "C" fn(handle: *mut std::os::raw::c_void);

pub struct EtwBridge {
    lib: Library,
    handle: *mut std::os::raw::c_void,
}

unsafe impl Send for EtwBridge {}
unsafe impl Sync for EtwBridge {}

impl EtwBridge {
    pub fn new() -> Result<Self, String> {
        // 尝试多个可能的 DLL 路径
        let dll_paths = vec![
            "../native/bin/win32-x64/etw_bridge.dll",
        ];

        let mut last_error: Option<String> = None;
        for path in dll_paths {
            match unsafe { Library::new(path) } {
                Ok(lib) => {
                    unsafe {
                        let create_fn: Symbol<EtwBridgeCreateFn> = lib.get(b"EtwBridge_Create")
                            .map_err(|e| e.to_string())?;
                        let session_name = wide_string("AnXinETWSession");
                        let handle = create_fn(session_name.as_ptr());

                        if handle.is_null() {
                            return Err("Failed to create ETW bridge".to_string());
                        }

                        return Ok(Self { lib, handle });
                    }
                }
                Err(e) => {
                    last_error = Some(e.to_string());
                    continue;
                }
            }
        }

        Err(last_error.unwrap_or_else(|| "No valid ETW bridge DLL found".to_string()))
    }

    pub fn start(&mut self, keywords: EtwKeywords) -> Result<(), String> {
        unsafe {
            let start_fn: Symbol<EtwBridgeStartFn> = self.lib.get(b"EtwBridge_Start")
                .map_err(|e| format!("Failed to load EtwBridge_Start: {}", e))?;

            let result = start_fn(
                self.handle,
                keywords.process_any,
                keywords.process_all,
                keywords.file_any,
                keywords.file_all,
                keywords.registry_any,
                keywords.registry_all,
                keywords.network_any,
                keywords.network_all,
                keywords.network_enabled,
                keywords.filter_private_ips,
                keywords.skip_loopback,
                keywords.user_data_max_bytes,
            );

            if result != 0 {
                Err(format!("EtwBridge_Start failed with code: {}", result))
            } else {
                Ok(())
            }
        }
    }

    pub fn stop(&self, timeout_ms: u32) -> Result<(), String> {
        unsafe {
            let stop_fn: Symbol<EtwBridgeStopFn> = self.lib.get(b"EtwBridge_Stop")
                .map_err(|e| format!("Failed to load EtwBridge_Stop: {}", e))?;

            let result = stop_fn(self.handle, timeout_ms);

            if result != 0 {
                Err(format!("EtwBridge_Stop failed with code: {}", result))
            } else {
                Ok(())
            }
        }
    }

    pub fn poll_events(&self) -> Result<Vec<EtwEvent>, String> {
        let mut events = Vec::new();

        unsafe {
            let poll_fn: Symbol<EtwBridgePollJsonFn> = self.lib.get(b"EtwBridge_PollJson")
                .map_err(|e| format!("Failed to load EtwBridge_PollJson: {}", e))?;

            let free_fn: Symbol<EtwBridgeFreeFn> = self.lib.get(b"EtwBridge_Free")
                .map_err(|e| format!("Failed to load EtwBridge_Free: {}", e))?;

            // 最多轮询 200 条事件
            for _ in 0..200 {
                let mut out_ptr: *mut std::os::raw::c_char = std::ptr::null_mut();
                let rc = poll_fn(self.handle, &mut out_ptr);

                if rc != 1 || out_ptr.is_null() {
                    break;
                }

                // 读取 JSON 字符串
                let json_str = std::ffi::CStr::from_ptr(out_ptr)
                    .to_str()
                    .map_err(|e| format!("Invalid UTF-8 in ETW event: {}", e))?
                    .to_string();

                // 释放 C 内存
                free_fn(out_ptr as *mut std::os::raw::c_void);

                // 解析 JSON 为 EtwEvent
                match serde_json::from_str::<EtwEvent>(&json_str) {
                    Ok(event) => events.push(event),
                    Err(e) => {
                        eprintln!("Failed to parse ETW event JSON: {}", e);
                    }
                }
            }
        }

        Ok(events)
    }
}

impl Drop for EtwBridge {
    fn drop(&mut self) {
        unsafe {
            if !self.handle.is_null() {
                if let Ok(stop_fn) = self.lib.get::<EtwBridgeStopFn>(b"EtwBridge_Stop") {
                    stop_fn(self.handle, 2500);
                }
                if let Ok(destroy_fn) = self.lib.get::<EtwBridgeDestroyFn>(b"EtwBridge_Destroy") {
                    destroy_fn(self.handle);
                }
                self.handle = std::ptr::null_mut();
            }
        }
    }
}

#[derive(Clone, Copy)]
pub struct EtwKeywords {
    pub process_any: u64,
    pub process_all: u64,
    pub file_any: u64,
    pub file_all: u64,
    pub registry_any: u64,
    pub registry_all: u64,
    pub network_any: u64,
    pub network_all: u64,
    pub network_enabled: i32,
    pub filter_private_ips: i32,
    pub skip_loopback: i32,
    pub user_data_max_bytes: u32,
}

impl Default for EtwKeywords {
    fn default() -> Self {
        Self {
            process_any: 0x00000001,
            process_all: 0x00000000,
            file_any: 0x00000010,
            file_all: 0x00000000,
            registry_any: 0x00000100,
            registry_all: 0x00000000,
            network_any: 0x00001000,
            network_all: 0x00000000,
            network_enabled: 1,
            filter_private_ips: 0,
            skip_loopback: 0,
            user_data_max_bytes: 65536,
        }
    }
}

fn wide_string(s: &str) -> Vec<u16> {
    std::ffi::OsString::from(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}
