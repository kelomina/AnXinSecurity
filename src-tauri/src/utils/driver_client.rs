//! Driver client — safe Rust wrapper for AnXinProcProtect.sys IOCTL interface.
//!
//! 驱动客户端 — AnXinProcProtect.sys 的 IOCTL 互操作层，以及
//!                AnXinFileProtect.sys 的 FilterConnectCommunicationPort 通信层。
//!
//! This module communicates with:
//! - AnXinProcProtect.sys via CreateFileW + DeviceIoControl (PID + WinSta protection)
//! - AnXinFileProtect.sys via FilterConnectCommunicationPort (file path protection)
//!
//! Used by the Windows service process (running as SYSTEM) to register AnXin
//! processes, window stations, and file paths for kernel-level protection.

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::sync::Mutex;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
use windows::Win32::System::IO::DeviceIoControl;

// ===========================================================================
// AnXinFileProtect minifilter communication
// ===========================================================================

/// FilterConnectCommunicationPort from fltlib.dll
///
/// Connects to the AnXinFileProtect minifilter driver's communication port
/// and registers a list of NT-format directory paths for file protection.
pub fn register_file_protection_paths(paths: &[&str]) -> Result<(), String> {
    let port_name: Vec<u16> = "\\AnXinFileProtectPort\0".encode_utf16().collect();

    let mut port_handle = HANDLE::default();

    // SAFETY: FilterConnectCommunicationPort opens a connection to a registered
    // minifilter communication port. AnXinFileProtect.sys must be loaded and running.
    let result = unsafe {
        FilterConnectCommunicationPort(
            windows::core::PCWSTR(port_name.as_ptr()),
            0,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            &mut port_handle as *mut _,
        )
    };

    if result.is_err() {
        return Err(format!(
            "Failed to connect to AnXinFileProtect port: {}",
            io::Error::last_os_error()
        ));
    }

    // Send each path to the driver
    for path in paths {
        let msg = build_fpm_message(path, 1); // FpmAddPath = 1
        let msg_bytes = &msg;

        // SAFETY: FilterSendMessage sends data to the minifilter via the communication port.
        let send_result = unsafe {
            FilterSendMessage(
                port_handle,
                msg_bytes.as_ptr() as *const _,
                msg_bytes.len() as u32,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
            )
        };

        if send_result.is_err() {
            let err = io::Error::last_os_error();
            let _ = unsafe { CloseHandle(port_handle) };
            return Err(format!(
                "Failed to register protected path '{}': {}",
                path, err
            ));
        }
    }

    // Close the communication port handle
    unsafe {
        let _ = CloseHandle(port_handle);
    }

    Ok(())
}

/// Query the list of protected paths from the AnXinFileProtect driver.
///
/// Connects to the minifilter's communication port and sends a query message
/// (FpmQueryPaths = 4) to retrieve the currently registered protected paths.
/// Returns a vector of NT-format path strings, or an empty vector if the
/// query fails or the driver is not available.
pub fn query_file_protection_paths() -> Vec<String> {
    let port_name: Vec<u16> = "\\AnXinFileProtectPort\0".encode_utf16().collect();

    let mut port_handle = HANDLE::default();

    // Connect to the minifilter communication port
    let result = unsafe {
        FilterConnectCommunicationPort(
            windows::core::PCWSTR(port_name.as_ptr()),
            0,
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
            &mut port_handle as *mut _,
        )
    };

    if result.is_err() {
        eprintln!(
            "[FileProtect] Failed to connect to AnXinFileProtect port: {}",
            io::Error::last_os_error()
        );
        return Vec::new();
    }

    // Send FpmQueryPaths message (type=4) with empty path
    let mut msg_buf = [0u8; 4 + 520 * 2];
    msg_buf[..4].copy_from_slice(&4u32.to_ne_bytes()); // FpmQueryPaths = 4

    // Response buffer: ULONG count + 128 paths * 520 WCHARs each
    const MAX_QUERY_PATHS: usize = 128;
    let mut resp_buf = vec![0u8; 4 + MAX_QUERY_PATHS * 520 * 2];
    let mut bytes_returned = 0u32;

    // Single send+receive call
    let send_result = unsafe {
        FilterSendMessage(
            port_handle,
            msg_buf.as_ptr() as *const _,
            msg_buf.len() as u32,
            resp_buf.as_mut_ptr() as *mut _,
            resp_buf.len() as u32,
            &mut bytes_returned as *mut u32,
        )
    };

    unsafe { let _ = CloseHandle(port_handle); }

    if send_result.is_err() {
        eprintln!(
            "[FileProtect] Failed to send query: {}",
            io::Error::last_os_error()
        );
        return Vec::new();
    }

    if bytes_returned < 4 {
        eprintln!("[FileProtect] Query response too small: {} bytes", bytes_returned);
        return Vec::new();
    }

    // Parse response: ULONG count + WCHAR paths
    let count = u32::from_ne_bytes([resp_buf[0], resp_buf[1], resp_buf[2], resp_buf[3]]) as usize;
    eprintln!(
        "[FileProtect] Query returned {} protected path(s)",
        count
    );

    let mut paths = Vec::new();
    for i in 0..count.min(MAX_QUERY_PATHS) {
        let base = 4 + i * 520 * 2;
        // Find null terminator in this path slot
        let mut chars = 0;
        while chars < 520 {
            let bo = base + chars * 2;
            if bo + 1 >= resp_buf.len() { break; }
            if resp_buf[bo] == 0 && resp_buf[bo + 1] == 0 { break; }
            chars += 1;
        }
        if chars > 0 {
            let chars_utf16 = &resp_buf[base..base + chars * 2];
            let utf16: Vec<u16> = chars_utf16
                .chunks_exact(2)
                .map(|c| u16::from_ne_bytes(c.try_into().unwrap()))
                .collect();
            if let Ok(path) = String::from_utf16(&utf16) {
                paths.push(path.clone());
                eprintln!("[FileProtect]   [{}] {}", i, path);
            }
        }
    }

    paths
}

/// Builds a FPM_MESSAGE struct for the minifilter driver.
fn build_fpm_message(path: &str, msg_type: u32) -> Vec<u8> {
    // FPM_MESSAGE: message_type (u32) + path (WCHAR[520])
    let mut buf = vec![0u8; 4 + 520 * 2]; // u32 + WCHAR[520]
    buf[..4].copy_from_slice(&msg_type.to_ne_bytes());

    let path_utf16: Vec<u16> = OsStr::new(path).encode_wide().collect();
    let copy_len = std::cmp::min(path_utf16.len(), 519);
    for (i, &ch) in path_utf16[..copy_len].iter().enumerate() {
        let offset = 4 + i * 2;
        buf[offset..offset + 2].copy_from_slice(&ch.to_ne_bytes());
    }
    buf
}

// Import from fltlib.dll
#[link(name = "fltlib")]
extern "system" {
    fn FilterConnectCommunicationPort(
        lp_port_name: windows::core::PCWSTR,
        dw_options: u32,
        lp_context: *const std::ffi::c_void,
        dw_size_of_context: u32,
        lp_security_attributes: *mut std::ffi::c_void,
        h_port: *mut HANDLE,
    ) -> windows::core::HRESULT;

    fn FilterSendMessage(
        h_port: HANDLE,
        lp_in_buffer: *const std::ffi::c_void,
        dw_in_buffer_size: u32,
        lp_out_buffer: *mut std::ffi::c_void,
        dw_out_buffer_size: u32,
        lp_bytes_returned: *mut u32,
    ) -> windows::core::HRESULT;
}

/// Driver device path
const DEVICE_PATH: &str = r"\\.\AnXinProcProtect";

/// 驱动侧的设备类型与 IOCTL 参数常量，取自 native/driver/src/driver.c 使用的 WDK 宏。
///  Device type and IOCTL parameter constants, matching the WDK macros used by
///  native/driver/src/driver.c.
const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const METHOD_BUFFERED: u32 = 0;
const METHOD_NEITHER: u32 = 3;
const FILE_READ_DATA: u32 = 1;
const FILE_WRITE_DATA: u32 = 2;

/// WDK 的 `CTL_CODE` 宏在 Rust 侧的等价实现。
///  Rust-side equivalent of the WDK `CTL_CODE` macro.
///
/// `CTL_CODE(DeviceType, Function, Method, Access)
///   = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method`
///
/// 必须按公式推导而不是硬编码字面量：此前 9 个 IOCTL 全部被写成 `0x8000_00xx` 一族
/// （相当于 DeviceType=0x8000、Function=9），与驱动的 `0x0022_xxxx` 毫无关系，
/// 导致 `DriverDeviceControl` 的 switch 全部落到 default 返回 STATUS_INVALID_DEVICE_REQUEST，
/// 进程保护 / WinSta 保护 / 注册表保护 100% 静默失效。
///  Derived from the formula rather than hardcoded: all nine codes previously used the
///  `0x8000_00xx` family (DeviceType=0x8000, Function=9), unrelated to the driver's
///  `0x0022_xxxx`, so every request fell through to the switch default and silently failed.
const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

/// IOCTL codes (must match driver/src/driver.c)
/// 0x0022A000
const IOCTL_ANXIN_ADD_PID: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA);
/// 0x0022A004
const IOCTL_ANXIN_REMOVE_PID: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA);
/// 0x0022A00B
const IOCTL_ANXIN_CLEAR_PIDS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x802, METHOD_NEITHER, FILE_WRITE_DATA);
/// 0x0022600C
const IOCTL_ANXIN_QUERY_PIDS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_READ_DATA);
/// 0x0022A010
const IOCTL_ANXIN_ADD_WINSTA: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA);
/// 0x0022A017
const IOCTL_ANXIN_REMOVE_WINSTA: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x805, METHOD_NEITHER, FILE_WRITE_DATA);
// 注意：REG_KEY IOCTL 族（0x806-0x808）已随注册表保护整体迁移到 AnXinFileProtect.sys
// 而删除（见 driver.c「Boot reinit callback」注释）。本驱动只做进程自保，不再提供
// 注册表键保护 IOCTL；Rust 侧不得再定义/调用这些死常量。
//  Note: the REG_KEY IOCTL family (0x806-0x808) was removed when registry self-protection
//  moved entirely to AnXinFileProtect.sys (see the "Boot reinit callback" comment in driver.c).
//  This driver only does process self-protection now; Rust must not define/call those dead IOCTLs.

/// 驱动的受保护 PID 上限，见 driver.c 的 `MAX_PROTECTED_PIDS`。
///  Driver-side protected PID capacity, see `MAX_PROTECTED_PIDS` in driver.c.
const MAX_PROTECTED_PIDS: usize = 64;

/// Thread-safe wrapper around the driver device handle.
pub struct DriverClient {
    handle: Mutex<Option<HANDLE>>,
}

impl DriverClient {
    /// Creates a new unconnected client.
    pub const fn new() -> Self {
        Self {
            handle: Mutex::new(None),
        }
    }

    /// Opens a handle to the AnXinProcProtect driver device.
    ///
    /// Returns `Ok(())` if the device was opened successfully.
    pub fn connect(&self) -> io::Result<()> {
        let path = OsStr::new(DEVICE_PATH);
        let path_wide: Vec<u16> = path.encode_wide().chain(std::iter::once(0)).collect();

        // SAFETY: CreateFileW with a well-known kernel device path.
        // std::os::windows::ffi::OsStrExt provides encode_wide.
        let desired_access = windows::Win32::Storage::FileSystem::FILE_GENERIC_READ.0
            | windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0;
        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(path_wide.as_ptr()),
                desired_access,
                // 必须允许共享读写：进程保护与注册表保护各自创建一个 DriverClient，
                // 而 init_driver_protection 用 std::mem::forget 常驻持有第一个句柄。
                // 用 FILE_SHARE_NONE 时第二个 connect 必然 ERROR_SHARING_VIOLATION，
                // 导致注册表保护注册永远失败，且失败只被 eprintln 吞掉。
                //  Sharing must be allowed: process protection and registry protection each
                //  create their own DriverClient while init_driver_protection keeps the first
                //  handle alive via std::mem::forget. With FILE_SHARE_NONE the second connect
                //  always fails with ERROR_SHARING_VIOLATION, silently disabling registry
                //  protection.
                windows::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
                None,
            )
        };

        match handle {
            Ok(h) => {
                let mut guard = self.handle.lock().unwrap();
                *guard = Some(h);
                Ok(())
            }
            Err(e) => Err(io::Error::from_raw_os_error(e.code().0)),
        }
    }

    /// Closes the driver device handle.
    pub fn disconnect(&self) {
        let mut guard = self.handle.lock().unwrap();
        if let Some(handle) = guard.take() {
            // SAFETY: Closing a valid handle obtained from CreateFileW.
            unsafe {
                let _ = CloseHandle(handle);
            }
        }
    }

    /// Returns whether the driver is currently connected.
    pub fn is_connected(&self) -> bool {
        self.handle.lock().unwrap().is_some()
    }

    /// Adds a PID to the driver's protected process list.
    ///
    /// 驱动按 `InputBufferLength >= sizeof(HANDLE)` 校验并以 `*(PHANDLE)` 读取，
    /// x64 上是 8 字节；发 4 字节会被判 STATUS_BUFFER_TOO_SMALL 直接失败。
    ///  The driver checks `InputBufferLength >= sizeof(HANDLE)` and reads via `*(PHANDLE)`,
    ///  which is 8 bytes on x64; sending 4 bytes fails with STATUS_BUFFER_TOO_SMALL.
    pub fn add_pid(&self, pid: u32) -> io::Result<()> {
        self.ioctl_write(IOCTL_ANXIN_ADD_PID, &(pid as usize).to_ne_bytes())
    }

    /// Removes a PID from the driver's protected process list.
    pub fn remove_pid(&self, pid: u32) -> io::Result<()> {
        self.ioctl_write(IOCTL_ANXIN_REMOVE_PID, &(pid as usize).to_ne_bytes())
    }

    /// Clears all PIDs from the driver's protected process list.
    pub fn clear_pids(&self) -> io::Result<()> {
        self.ioctl_write(IOCTL_ANXIN_CLEAR_PIDS, &[])
    }

    /// Queries the list of currently protected PIDs from the driver.
    ///
    /// 驱动的输出布局是 `ULONG count` 紧跟 `HANDLE[count]`：
    /// `outBuf` 声明为 `PULONG`，`&outBuf[1]` 是偏移 4 字节，之后按 `sizeof(HANDLE)`（x64=8）逐个拷贝。
    /// 因此缓冲区需要 `4 + MAX_PROTECTED_PIDS * 8` 字节，读取步长是 8 而不是 4。
    /// 原实现按 4 字节步长读 260 字节缓冲区：PID 数超过 32 时驱动直接返回 STATUS_BUFFER_OVERFLOW，
    /// 未超时读出的也全是错位的半个 HANDLE。
    ///  The driver writes `ULONG count` followed by `HANDLE[count]`: `outBuf` is a `PULONG`,
    ///  so `&outBuf[1]` is at byte offset 4, and entries are `sizeof(HANDLE)` (8 on x64) apart.
    ///  The buffer therefore needs `4 + MAX_PROTECTED_PIDS * 8` bytes and a stride of 8.
    pub fn query_pids(&self) -> io::Result<Vec<u32>> {
        // ULONG count + HANDLE[MAX_PROTECTED_PIDS]
        let mut output = vec![0u8; 4 + MAX_PROTECTED_PIDS * std::mem::size_of::<usize>()];
        let mut bytes_returned = 0u32;

        let handle = self.get_handle()?;

        // SAFETY: output buffer is properly sized for the driver's response.
        unsafe {
            let result = DeviceIoControl(
                handle,
                IOCTL_ANXIN_QUERY_PIDS,
                None,
                0,
                Some(output.as_mut_ptr() as *mut _),
                output.len() as u32,
                Some(&mut bytes_returned as *mut u32),
                None,
            );

            if let Err(e) = result {
                return Err(io::Error::from_raw_os_error(e.code().0));
            }
            if bytes_returned < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "driver returned empty PID list",
                ));
            }
        }

        let count = u32::from_ne_bytes([output[0], output[1], output[2], output[3]]) as usize;
        // count 由驱动填写，仍按缓冲区容量夹取，避免异常值导致越界读
        //  count comes from the driver; clamp to the buffer capacity anyway
        let count = count.min(MAX_PROTECTED_PIDS);
        let handle_size = std::mem::size_of::<usize>();
        let mut pids = Vec::with_capacity(count);

        for i in 0..count {
            let offset = 4 + i * handle_size;
            if offset + handle_size <= output.len() {
                let raw = usize::from_ne_bytes(
                    output[offset..offset + handle_size]
                        .try_into()
                        .expect("slice length equals size_of::<usize>()"),
                );
                pids.push(raw as u32);
            }
        }

        Ok(pids)
    }

    // ------------------------------------------------------------------
    // WindowStation protection
    // ------------------------------------------------------------------

    /// Registers a WindowStation handle with the driver for protection.
    ///
    /// The caller should pass its own `OpenWindowStationW` handle.
    /// After registration, other processes opening this WindowStation will
    /// have dangerous rights stripped (enumerate desktops, read screen, etc.).
    pub fn add_winsta(&self, winsta_handle: u64) -> io::Result<()> {
        self.ioctl_write(IOCTL_ANXIN_ADD_WINSTA, &winsta_handle.to_ne_bytes())
    }

    /// Removes all protected WindowStation registrations from the driver.
    pub fn remove_winsta(&self) -> io::Result<()> {
        self.ioctl_write(IOCTL_ANXIN_REMOVE_WINSTA, &[])
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn get_handle(&self) -> io::Result<HANDLE> {
        self.handle
            .lock()
            .unwrap()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "driver not connected"))
    }

    fn ioctl_write(&self, code: u32, input: &[u8]) -> io::Result<()> {
        let handle = self.get_handle()?;
        let mut bytes_returned = 0u32;

        // SAFETY: input buffer is readable; no output buffer needed for write-only IOCTLs.
        unsafe {
            let result = DeviceIoControl(
                handle,
                code,
                Some(input.as_ptr() as *const _),
                input.len() as u32,
                None,
                0,
                Some(&mut bytes_returned as *mut u32),
                None,
            );

            if let Err(e) = result {
                return Err(io::Error::from_raw_os_error(e.code().0));
            }
        }

        Ok(())
    }
}

impl Drop for DriverClient {
    fn drop(&mut self) {
        self.disconnect();
    }
}

// SAFETY: DriverClient only wraps a Win32 HANDLE which is safe to send/access
// across threads when protected by a Mutex.
unsafe impl Send for DriverClient {}
unsafe impl Sync for DriverClient {}

#[cfg(test)]
mod tests {
    use super::*;

    /// IOCTL 常量的期望值，由 native/driver/src/driver.c 的 CTL_CODE 宏手工展开得到。
    ///  Expected IOCTL values, hand-expanded from the CTL_CODE macros in driver.c.
    const EXPECTED_IOCTLS: &[(&str, u32, u32)] = &[
        ("IOCTL_ANXIN_ADD_PID", IOCTL_ANXIN_ADD_PID, 0x0022_A000),
        (
            "IOCTL_ANXIN_REMOVE_PID",
            IOCTL_ANXIN_REMOVE_PID,
            0x0022_A004,
        ),
        (
            "IOCTL_ANXIN_CLEAR_PIDS",
            IOCTL_ANXIN_CLEAR_PIDS,
            0x0022_A00B,
        ),
        (
            "IOCTL_ANXIN_QUERY_PIDS",
            IOCTL_ANXIN_QUERY_PIDS,
            0x0022_600C,
        ),
        (
            "IOCTL_ANXIN_ADD_WINSTA",
            IOCTL_ANXIN_ADD_WINSTA,
            0x0022_A010,
        ),
        (
            "IOCTL_ANXIN_REMOVE_WINSTA",
            IOCTL_ANXIN_REMOVE_WINSTA,
            0x0022_A017,
        ),
    ];

    /// Verifies that IOCTL codes match the C driver definitions.
    ///
    /// 旧版本把 `0x8000_00xx` 这一族错误值直接断言了一遍，等于把 bug 固化成"已验证"——
    /// 常量和断言来自同一个错误来源，测试永远绿，而实际每个 DeviceIoControl 都落到
    /// 驱动 switch 的 default 分支。现在断言的是从 driver.c 宏独立展开的真值。
    ///  The old version asserted the same wrong `0x8000_00xx` family it was validating, so the
    ///  bug was locked in as "verified": constant and assertion shared one wrong source while
    ///  every DeviceIoControl actually hit the driver's switch default. These values are
    ///  independently expanded from the driver.c macros.
    #[test]
    fn test_ioctl_constants_match_c_driver() {
        for (name, actual, expected) in EXPECTED_IOCTLS {
            assert_eq!(
                actual, expected,
                "{} 与 driver.c 的 CTL_CODE 展开值不一致：0x{:08X} != 0x{:08X}",
                name, actual, expected
            );
        }
    }

    /// 逐位校验 IOCTL 的字段构成，防止有人改了 `ctl_code` 公式却顺手改字面量掩盖问题。
    ///  Field-level check so nobody can change the `ctl_code` formula and paper over it by
    ///  editing the literals to match.
    #[test]
    fn test_ioctl_field_decomposition() {
        for (name, code, _) in EXPECTED_IOCTLS {
            assert_eq!(
                code >> 16,
                FILE_DEVICE_UNKNOWN,
                "{} 的设备类型必须是 FILE_DEVICE_UNKNOWN(0x22)",
                name
            );
        }
        // METHOD_NEITHER 的两条 / the two METHOD_NEITHER codes
        assert_eq!(IOCTL_ANXIN_CLEAR_PIDS & 3, METHOD_NEITHER);
        assert_eq!(IOCTL_ANXIN_REMOVE_WINSTA & 3, METHOD_NEITHER);
        // 唯一的读取型 / the only read-access code
        assert_eq!(IOCTL_ANXIN_QUERY_PIDS & 3, METHOD_BUFFERED);
        assert_eq!((IOCTL_ANXIN_QUERY_PIDS >> 14) & 3, FILE_READ_DATA);
        assert_eq!((IOCTL_ANXIN_ADD_PID >> 14) & 3, FILE_WRITE_DATA);
    }

    /// 直接读 driver.c，把每个 IOCTL 的 CTL_CODE 实参解析出来重新计算，
    /// 确保 Rust 侧常量与驱动源码不会再各自漂移。
    ///  Parses the CTL_CODE arguments straight out of driver.c and recomputes each value, so the
    ///  Rust constants and the driver source can never drift apart again.
    #[test]
    fn test_ioctl_constants_derived_from_driver_source() {
        let source = [
            "../native/driver/src/driver.c",
            "native/driver/src/driver.c",
        ]
        .into_iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .expect("native/driver/src/driver.c 应可读取，用于校验 IOCTL 定义未漂移");

        for (name, actual, _) in EXPECTED_IOCTLS {
            let define = format!("#define {}", name);
            let line = source
                .lines()
                .find(|line| line.trim_start().starts_with(&define))
                .unwrap_or_else(|| panic!("driver.c 中找不到 {} 的定义", name));

            let args = line
                .split_once("CTL_CODE(")
                .and_then(|(_, rest)| rest.split_once(')'))
                .map(|(args, _)| args)
                .unwrap_or_else(|| panic!("{} 不是 CTL_CODE 形式: {}", name, line));

            let parts: Vec<&str> = args.split(',').map(|part| part.trim()).collect();
            assert_eq!(parts.len(), 4, "{} 的 CTL_CODE 参数应为 4 个", name);
            assert_eq!(parts[0], "FILE_DEVICE_UNKNOWN", "{} 设备类型不符", name);

            let function = u32::from_str_radix(parts[1].trim_start_matches("0x"), 16)
                .unwrap_or_else(|_| panic!("{} 的 function 无法解析: {}", name, parts[1]));
            let method = match parts[2] {
                "METHOD_BUFFERED" => METHOD_BUFFERED,
                "METHOD_NEITHER" => METHOD_NEITHER,
                other => panic!("{} 使用了未覆盖的 method: {}", name, other),
            };
            let access = match parts[3] {
                "FILE_READ_DATA" => FILE_READ_DATA,
                "FILE_WRITE_DATA" => FILE_WRITE_DATA,
                other => panic!("{} 使用了未覆盖的 access: {}", name, other),
            };

            let derived = ctl_code(FILE_DEVICE_UNKNOWN, function, method, access);
            assert_eq!(
                *actual, derived,
                "{} 与 driver.c 定义不一致：Rust=0x{:08X}, driver.c 推导=0x{:08X}",
                name, actual, derived
            );
        }
    }

    /// 驱动按 sizeof(HANDLE) 校验输入长度，x64 上必须是 8 字节。
    ///  The driver validates the input length against sizeof(HANDLE): 8 bytes on x64.
    #[test]
    fn test_pid_payload_matches_driver_handle_width() {
        assert_eq!(
            std::mem::size_of::<usize>(),
            std::mem::size_of::<*const std::ffi::c_void>(),
            "usize 必须与 HANDLE 同宽，add_pid 依赖这一点"
        );
        let payload = (4242u32 as usize).to_ne_bytes();
        assert_eq!(
            payload.len(),
            std::mem::size_of::<usize>(),
            "add_pid 发送的负载长度必须等于 sizeof(HANDLE)"
        );
    }

    #[test]
    fn test_new_client_not_connected() {
        let client = DriverClient::new();
        assert!(!client.is_connected());
        assert!(client.add_pid(1234).is_err());
    }

    #[test]
    fn test_query_pids_empty_on_unconnected() {
        let client = DriverClient::new();
        assert!(client.query_pids().is_err());
    }

    #[test]
    fn test_ioctl_write_empty_input() {
        // This tests the IOCTL path with an empty input (CLEAR_PIDS).
        // When not connected, it should return NotConnected error.
        let client = DriverClient::new();
        let result = client.clear_pids();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotConnected);
    }
}
