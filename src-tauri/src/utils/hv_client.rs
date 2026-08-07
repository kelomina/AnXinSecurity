//! Hypervisor client — queries AnXinHypervisor.sys status via IOCTL.
//!
//! 通过 DeviceIoControl 查询 AnXinHypervisor.sys 的运行状态、统计和违规事件。
//! 降级模式下驱动仍然加载并创建设备对象，因此状态查询始终可用。

use std::ffi::OsStr;
use std::io;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};
use windows::Win32::System::IO::DeviceIoControl;

const HV_DEVICE_PATH: &str = r"\\.\AnXinHypervisor";

const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const fn ctl_code(device_type: u32, function: u32, method: u32, access: u32) -> u32 {
    (device_type << 16) | (access << 14) | (function << 2) | method
}

const IOCTL_GET_STATUS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8001, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_GET_STATS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8002, METHOD_BUFFERED, FILE_ANY_ACCESS);
const IOCTL_GET_VIOLATIONS: u32 =
    ctl_code(FILE_DEVICE_UNKNOWN, 0x8003, METHOD_BUFFERED, FILE_ANY_ACCESS);

#[repr(C)]
#[derive(Debug, Clone)]
pub struct HvStatusInfo {
    pub version_major: u32,
    pub version_minor: u32,
    pub version_patch: u32,
    pub operating_mode: u32,
    pub cpu_vendor: u32,
    pub cpu_count: u32,
    pub page_tables_active: u32,
    pub reserved: [u32; 2],
    pub platform_name: [u8; 64],
    pub degrad_reason: [u8; 128],
}

impl Default for HvStatusInfo {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Default, Copy)]
pub struct HvStats {
    pub total_vm_exits: u64,
    pub page_fault_exits: u64,
    pub cpuid_exits: u64,
    pub hypercall_count: u64,
    pub msr_exits: u64,
    pub cr_access_exits: u64,
    pub violations_blocked: u64,
    pub violations_allowed: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Default, Copy)]
pub struct HvViolationEvent {
    pub timestamp: u64,
    pub guest_rip: u64,
    pub guest_cr3: u64,
    pub target_gpa: u64,
    pub access_type: u32,
    pub region_index: u32,
    pub owner_pid: u32,
    pub cpu_number: u32,
    pub module_base: u64,
    pub sequence_id: u32,
}

impl HvStatusInfo {
    pub fn mode_name(&self) -> &'static str {
        match self.operating_mode {
            0 => "full",
            1 => "degraded_hyperv",
            2 => "degraded_cpu",
            3 => "degraded_vtx_off",
            4 => "degraded_svm_off",
            5 => "degraded_no_nx",
            6 => "degraded_no_npt",
            7 => "degraded_init_fail",
            8 => "degraded_no_ept",
            _ => "unknown",
        }
    }

    pub fn vendor_name(&self) -> &'static str {
        match self.cpu_vendor {
            1 => "Intel",
            2 => "AMD",
            _ => "Unknown",
        }
    }

    pub fn platform_string(&self) -> String {
        let end = self
            .platform_name
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.platform_name.len());
        String::from_utf8_lossy(&self.platform_name[..end]).to_string()
    }

    pub fn reason_string(&self) -> String {
        let end = self
            .degrad_reason
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.degrad_reason.len());
        String::from_utf8_lossy(&self.degrad_reason[..end]).to_string()
    }

    pub fn is_full_mode(&self) -> bool {
        self.operating_mode == 0
    }
}

pub struct HvClient {
    handle: HANDLE,
}

// SAFETY: HvClient 拥有唯一的设备句柄，且只通过 &self 的同步 IOCTL 访问。
// 句柄本身是进程级别的内核对象句柄，可以在线程间传递；访问由调用方使用
// Mutex/HypervisorService 内部锁保证不并发。
//  SAFETY: HvClient owns the device handle exclusively and only accesses it via
//  synchronous &self IOCTLs. The handle is a process-wide kernel object handle
//  that may be passed between threads; concurrent access is prevented by the
//  enclosing Mutex in HypervisorService.
unsafe impl Send for HvClient {}
unsafe impl Sync for HvClient {}

impl HvClient {
    pub fn connect() -> io::Result<Self> {
        let path_wide: Vec<u16> = OsStr::new(HV_DEVICE_PATH)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let desired_access = windows::Win32::Storage::FileSystem::FILE_GENERIC_READ.0
            | windows::Win32::Storage::FileSystem::FILE_GENERIC_WRITE.0;

        let handle = unsafe {
            CreateFileW(
                windows::core::PCWSTR(path_wide.as_ptr()),
                desired_access,
                windows::Win32::Storage::FileSystem::FILE_SHARE_READ
                    | windows::Win32::Storage::FileSystem::FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES(0),
                None,
            )
        };

        match handle {
            Ok(h) => Ok(Self { handle: h }),
            Err(e) => Err(io::Error::from_raw_os_error(e.code().0)),
        }
    }

    pub fn get_status(&self) -> io::Result<HvStatusInfo> {
        let mut info = HvStatusInfo::default();
        let mut returned: u32 = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_GET_STATUS,
                None,
                0,
                Some(&mut info as *mut HvStatusInfo as *mut _),
                std::mem::size_of::<HvStatusInfo>() as u32,
                Some(&mut returned as *mut u32),
                None,
            )
        };

        result.map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(info)
    }

    pub fn get_stats(&self) -> io::Result<HvStats> {
        let mut stats = HvStats::default();
        let mut returned: u32 = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_GET_STATS,
                None,
                0,
                Some(&mut stats as *mut HvStats as *mut _),
                std::mem::size_of::<HvStats>() as u32,
                Some(&mut returned as *mut u32),
                None,
            )
        };

        result.map_err(|e| io::Error::from_raw_os_error(e.code().0))?;
        Ok(stats)
    }

    pub fn get_violations(&self, max_events: usize) -> io::Result<Vec<HvViolationEvent>> {
        let buf_size = max_events * std::mem::size_of::<HvViolationEvent>();
        let mut buffer: Vec<u8> = vec![0u8; buf_size];
        let mut returned: u32 = 0;

        let result = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_GET_VIOLATIONS,
                None,
                0,
                Some(buffer.as_mut_ptr() as *mut _),
                buf_size as u32,
                Some(&mut returned as *mut u32),
                None,
            )
        };

        result.map_err(|e| io::Error::from_raw_os_error(e.code().0))?;

        let count = returned as usize / std::mem::size_of::<HvViolationEvent>();
        let events: Vec<HvViolationEvent> = buffer[..count * std::mem::size_of::<HvViolationEvent>()]
            .chunks_exact(std::mem::size_of::<HvViolationEvent>())
            .map(|chunk| unsafe { std::ptr::read(chunk.as_ptr() as *const HvViolationEvent) })
            .collect();

        Ok(events)
    }
}

impl Drop for HvClient {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}
