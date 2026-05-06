// Library root for Tauri
pub mod commands;
pub mod models;
pub mod services;
pub mod utils;

pub fn _test_etw_api() {
    let _ = windows::Win32::System::Diagnostics::Etw::EVENT_TRACE_CONTROL_STOP;
}
