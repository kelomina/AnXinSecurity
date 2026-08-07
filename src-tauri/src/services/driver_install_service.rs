// 内核驱动安装服务 — 创建/启动/卸载两个内核驱动服务
//  Kernel driver install service - creates, starts and removes the two kernel driver services
//
// 职责：
//  Responsibilities:
// - 把随安装包释放的 .sys 复制到 %SystemRoot%\System32\drivers\
// - 创建并启动进程保护驱动（AnXinProcProtect，SERVICE_KERNEL_DRIVER）
// - 创建并启动文件保护 minifilter（AnXinFileProtect，SERVICE_FILE_SYSTEM_DRIVER + Instances 注册表）
// - 卸载时解除自保护、停止并删除服务、必要时安排重启删除
//
// 为什么这些逻辑在 Rust 而不是 NSIS：
//  Why this lives in Rust rather than NSIS:
// - NSIS 安装程序是 32 位，写 System32 会被 WoW64 重定向到 SysWOW64；本程序是 x64，不受重定向影响
// - 服务创建/启动的错误码需要分类处理并给出可读原因，sc.exe 的退出码做不到
// - minifilter 必须额外写 Instances 注册表子键，sc.exe 无法完成
//
// 调用方：main.rs 的命令行分派（--install-driver / --uninstall-drivers / --protect-pid / --protect-dir）
// Called by: the CLI dispatch in main.rs
//
// 中文关键词：内核驱动，驱动安装，minifilter，服务创建，自保护，卸载
// English keywords: kernel driver, driver install, minifilter, service creation, self-protection, uninstall
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

// ============================================================================
// 驱动定义 / Driver definitions
// ============================================================================

/// 进程保护驱动服务名 / Process protection driver service name
pub const PROC_DRIVER_SERVICE: &str = "AnXinProcProtect";
/// 文件保护 minifilter 服务名 / File protection minifilter service name
pub const FILE_DRIVER_SERVICE: &str = "AnXinFileProtect";
/// Hypervisor 驱动服务名 / Hypervisor driver service name
pub const HV_DRIVER_SERVICE: &str = "AnXinHypervisor";
/// 网络过滤驱动服务名 / Network filter driver service name
pub const NET_DRIVER_SERVICE: &str = "AnXinNetFilter";

/// 进程保护驱动文件名 / Process protection driver file name
const PROC_DRIVER_FILE: &str = "AnXinProcProtect.sys";
/// 文件保护驱动文件名 / File protection driver file name
const FILE_DRIVER_FILE: &str = "AnXinFileProtect.sys";
/// Hypervisor 驱动文件名 / Hypervisor driver file name
const HV_DRIVER_FILE: &str = "AnXinHypervisor.sys";
/// 网络过滤驱动文件名 / Network filter driver file name
const NET_DRIVER_FILE: &str = "AnXinNetFilter.sys";

/// minifilter 高度值，必须与 native/file_protect/AnXinFileProtect.inf 保持一致。
///  Minifilter altitude; must match native/file_protect/AnXinFileProtect.inf.
///
/// 高度决定过滤器在 I/O 栈中的位置，属于微软分配的命名空间；
/// 与 INF 不一致会导致 INF 安装与手工安装行为分叉。
///  The altitude decides the filter's position in the I/O stack and lives in a
///  Microsoft-allocated namespace; diverging from the INF makes INF-based and manual
///  installs behave differently.
const FILE_DRIVER_ALTITUDE: &str = "328800";

/// minifilter 实例名，必须与 INF 的 DefaultInstance 一致。
///  Minifilter instance name; must match DefaultInstance in the INF.
const FILE_DRIVER_INSTANCE: &str = "AnXinFileProtect Instance";

/// 要安装的驱动 / Driver to install
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverKind {
    /// 进程保护（普通内核驱动） / Process protection (plain kernel driver)
    ProcessProtection,
    /// 文件保护（minifilter） / File protection (minifilter)
    FileProtection,
    /// Hypervisor（Ring -1 虚拟化保护） / Hypervisor (Ring -1 virtualization protection)
    Hypervisor,
    /// 网络过滤（WFP callout） / Network filter (WFP callout)
    NetworkFilter,
}

impl DriverKind {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "proc" | "process" => Some(Self::ProcessProtection),
            "file" | "filter" => Some(Self::FileProtection),
            "hv" | "hypervisor" => Some(Self::Hypervisor),
            "net" | "network" | "netfilter" => Some(Self::NetworkFilter),
            _ => None,
        }
    }

    pub fn service_name(self) -> &'static str {
        match self {
            Self::ProcessProtection => PROC_DRIVER_SERVICE,
            Self::FileProtection => FILE_DRIVER_SERVICE,
            Self::Hypervisor => HV_DRIVER_SERVICE,
            Self::NetworkFilter => NET_DRIVER_SERVICE,
        }
    }

    fn file_name(self) -> &'static str {
        match self {
            Self::ProcessProtection => PROC_DRIVER_FILE,
            Self::FileProtection => FILE_DRIVER_FILE,
            Self::Hypervisor => HV_DRIVER_FILE,
            Self::NetworkFilter => NET_DRIVER_FILE,
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::ProcessProtection => "AnXin Security Process Protection",
            Self::FileProtection => "AnXin Security File Protection",
            Self::Hypervisor => "AnXin Security Hypervisor",
            Self::NetworkFilter => "AnXin Security Network Filter",
        }
    }
}

// ============================================================================
// 路径解析 / Path resolution
// ============================================================================

/// 系统驱动目录 %SystemRoot%\System32\drivers。
///  The system driver directory %SystemRoot%\System32\drivers.
///
/// 本进程是 x64，不受 WoW64 文件系统重定向影响；32 位的 NSIS 安装程序直接写这里
/// 会被重定向到 SysWOW64\drivers，驱动将无法加载——这正是复制动作放在 Rust 侧的原因。
///  This process is x64 and therefore not subject to WoW64 redirection; the 32-bit NSIS
///  installer writing here would land in SysWOW64\drivers and the driver would never load.
fn system_drivers_dir() -> Result<PathBuf, String> {
    let system_root = std::env::var("SystemRoot")
        .map_err(|_| "SystemRoot environment variable is not set".to_string())?;
    Ok(PathBuf::from(system_root).join("System32").join("drivers"))
}

/// 已安装的驱动文件目标路径 / Destination path of an installed driver file
fn installed_driver_path(kind: DriverKind) -> Result<PathBuf, String> {
    Ok(system_drivers_dir()?.join(kind.file_name()))
}

/// 在候选目录里定位随安装包释放的 .sys。
///  Locates the .sys shipped by the installer among candidate directories.
///
/// 安装程序把驱动释放到 `<staging>\drivers\`；开发环境下直接用仓库里的构建产物，
/// 这样 `--install-driver` 在 `cargo run` 下也能工作，不必先打包。
///  The installer drops drivers into `<staging>\drivers\`; in a development tree the build
///  outputs are used directly so `--install-driver` also works under `cargo run`.
fn locate_source_driver(kind: DriverKind, staging: Option<&Path>) -> Result<PathBuf, String> {
    let file_name = kind.file_name();
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Some(dir) = staging {
        candidates.push(dir.join(file_name));
        candidates.push(dir.join("drivers").join(file_name));
    }

    // Tauri 的 bundle.resources 用数组形式时，源路径里的 `../` 会被映射成 `_up_` 目录，
    // 因此打包后 .sys 落在 $INSTDIR\_up_\native\...\Release\ 下。
    // 这里保留数组形式（改成 map 形式会同时改变 Engine 的资源路径，
    // 而 main.rs 已经按 `_up_/Engine/...` 取引擎 DLL），代价是候选路径要照抄这个深路径。
    //  With the array form of bundle.resources, Tauri maps `../` in source paths to an `_up_`
    //  directory, so the packaged .sys lands under $INSTDIR\_up_\native\...\Release\. The array
    //  form is kept deliberately - switching to the map form would also move the Engine resources,
    //  which main.rs resolves as `_up_/Engine/...` - so these deep paths are listed as candidates.
    let packaged_relative = match kind {
        DriverKind::ProcessProtection => "_up_/native/driver/build/x64/Release",
        DriverKind::FileProtection => "_up_/native/file_protect/build/x64/Release",
        DriverKind::Hypervisor => "_up_/native/hypervisor/x64/Release",
        DriverKind::NetworkFilter => "_up_/native/net_filter/build/x64/Release",
    };

    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join("drivers").join(file_name));
            candidates.push(exe_dir.join(packaged_relative).join(file_name));
            candidates.push(exe_dir.join(file_name));
        }
    }

    // 开发树里的构建产物 / build outputs inside the development tree
    let repo_relative = match kind {
        DriverKind::ProcessProtection => "native/driver/build/x64/Release",
        DriverKind::FileProtection => "native/file_protect/build/x64/Release",
        DriverKind::Hypervisor => "native/hypervisor/x64/Release",
        DriverKind::NetworkFilter => "native/net_filter/build/x64/Release",
    };
    candidates.push(PathBuf::from(repo_relative).join(file_name));
    candidates.push(PathBuf::from("..").join(repo_relative).join(file_name));

    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            format!(
                "Driver payload {} not found in any candidate location",
                file_name
            )
        })
}

// ============================================================================
// 服务安装 / Service installation
// ============================================================================

/// 安装并启动一个内核驱动。
///  Installs and starts one kernel driver.
///
/// 返回 Ok 表示驱动已加载；返回 Err 时**调用方必须继续安装流程**——
/// 内核驱动只是纵深防御的一层，加载失败不能阻断产品安装，用户态防护仍然可用。
///  Ok means the driver is loaded. On Err the caller MUST continue the installation: the kernel
///  driver is one layer of defence in depth, and a load failure must never block the product
///  install while user-mode protection remains available.
pub fn install_driver(kind: DriverKind, staging: Option<&Path>) -> Result<(), String> {
    let source = locate_source_driver(kind, staging)?;
    let destination = installed_driver_path(kind)?;

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {}", parent.display(), e))?;
    }

    // 驱动已加载时目标文件被占用，复制会失败。此时保留现有文件继续走服务启动流程，
    // 因为同名服务多半已经在跑；强行替换只会得到 ERROR_SHARING_VIOLATION。
    //  A loaded driver holds its file open, so the copy fails. Keep the existing file and carry on
    //  to the service start: the service is most likely already running, and forcing a replace
    //  would only produce ERROR_SHARING_VIOLATION.
    match std::fs::copy(&source, &destination) {
        Ok(_) => eprintln!(
            "[DriverInstall] Copied {} -> {}",
            source.display(),
            destination.display()
        ),
        Err(err) => {
            if !destination.is_file() {
                return Err(format!(
                    "Failed to copy {} to {}: {}",
                    source.display(),
                    destination.display(),
                    err
                ));
            }
            eprintln!(
                "[DriverInstall] Keeping existing {} (copy failed: {})",
                destination.display(),
                err
            );
        }
    }

    create_driver_service(kind, &destination)?;

    if kind == DriverKind::FileProtection {
        // minifilter 光有服务是不够的：过滤管理器要读服务键下的 Instances 子键
        // 才知道该以什么高度挂载，缺了它 FltRegisterFilter 会失败。
        //  A service alone is not enough for a minifilter: the filter manager reads the Instances
        //  subkey to learn the altitude, and FltRegisterFilter fails without it.
        write_minifilter_instances(kind.service_name())?;
    }

    // Hypervisor 改为按需启动：安装时不自动 start，由 HypervisorService 在用户
    // 通过设置页开启元核防护后再启动。其他驱动仍然安装即启动。
    //  Hypervisor is now on-demand: do not auto-start on install; it is
    //  started by HypervisorService after the user enables hypervisor
    //  protection in the settings page. Other drivers still start on install.
    // NetworkFilter 也例外：改为 SYSTEM_START 后由系统在下次重启时加载，安装时不
    // 自动 start（此时驱动文件刚复制过去，但服务还未被 PnP 枚举，立即 start 可能
    // 失败）。安装后提示用户重启，重启后驱动随系统加载。
    //  NetworkFilter is also an exception: with SYSTEM_START the driver loads on
    //  next reboot; do not auto-start on install (the file was just copied and the
    //  service may not be startable immediately). The user is prompted to reboot.
    if matches!(kind, DriverKind::Hypervisor | DriverKind::NetworkFilter) {
        eprintln!(
            "[DriverInstall] {} installed, will load on next boot / on-demand",
            kind.service_name()
        );
    } else {
        start_driver_service(kind)?;
    }
    Ok(())
}

/// 创建内核驱动服务；已存在时视为成功。
///  Creates the kernel driver service; an existing service counts as success.
fn create_driver_service(kind: DriverKind, binary: &Path) -> Result<(), String> {
    use windows_service::service::{
        ServiceAccess, ServiceDependency, ServiceErrorControl, ServiceInfo, ServiceStartType,
        ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(|e| format!("Failed to open service manager: {}", e))?;

    // 已存在则不重复创建，避免覆盖用户或上一版安装留下的配置
    //  Do not recreate an existing service; that would clobber configuration left by a previous install
    if manager
        .open_service(kind.service_name(), ServiceAccess::QUERY_STATUS)
        .is_ok()
    {
        eprintln!(
            "[DriverInstall] Service {} already exists, skipping creation",
            kind.service_name()
        );
        return Ok(());
    }

    let service_type = match kind {
        DriverKind::ProcessProtection => ServiceType::KERNEL_DRIVER,
        DriverKind::FileProtection => ServiceType::FILE_SYSTEM_DRIVER,
        DriverKind::Hypervisor => ServiceType::KERNEL_DRIVER,
        DriverKind::NetworkFilter => ServiceType::KERNEL_DRIVER,
    };

    let info = ServiceInfo {
        name: OsStr::new(kind.service_name()).to_os_string(),
        display_name: OsStr::new(kind.display_name()).to_os_string(),
        service_type,
        // SERVICE_SYSTEM_START：内核初始化阶段随系统加载，早于普通应用，
        // 否则开机到服务启动之间存在无保护窗口。
        // 同样重要的是，SYSTEM_START 的驱动**默认不在安全模式加载**——
        // 这是用户的兜底逃生路径：万一自保护出问题，进安全模式即可正常删除。
        //  SERVICE_SYSTEM_START loads during kernel init, ahead of ordinary applications; otherwise
        //  there is an unprotected window between boot and service start. Just as importantly, a
        //  SYSTEM_START driver is not loaded in Safe Mode by default, which is the user's escape
        //  hatch: if self-protection ever misbehaves, Safe Mode allows normal removal.
        //
        // Hypervisor 例外：改为 SERVICE_DEMAND_START，只在用户通过设置页显式开启
        // 元核防护后才由 HypervisorService 启动。这是 fail-closed 设计——升级到
        // 带这个模块的版本绝不能默默改变系统虚拟化姿态。
        //  Hypervisor is the exception: it uses SERVICE_DEMAND_START and is only
        //  started by HypervisorService after the user explicitly turns on
        //  hypervisor protection in the settings page. This is fail-closed:
        //  upgrading to a build containing this module must never silently alter
        //  the system's virtualization posture.
        //
        // NetworkFilter 同样用 SYSTEM_START：用户在防火墙标签页首次点击时安装驱动，
        // 安装后提示重启，重启后驱动随系统加载。驱动加载后默认 fail-open（全放行），
        // 等应用启动握手后才开始过滤。enabled 开关控制应用是否握手接管。
        //  NetworkFilter also uses SYSTEM_START: the driver is installed when the
        //  user first clicks the firewall tab, followed by a restart prompt. After
        //  reboot the driver loads with the system. It defaults to fail-open
        //  (permit all) until the app handshake; the enabled switch controls whether
        //  the app takes over filtering.
        start_type: match kind {
            DriverKind::Hypervisor => ServiceStartType::OnDemand,
            _ => ServiceStartType::SystemStart,
        },
        error_control: ServiceErrorControl::Normal,
        executable_path: binary.to_path_buf(),
        launch_arguments: vec![],
        // minifilter 必须在 FltMgr 之后加载，否则 FltRegisterFilter 找不到
        // filter manager。进程保护驱动无此约束。
        //  A minifilter must load after FltMgr or FltRegisterFilter cannot
        //  find the filter manager. The process-protection driver has no
        //  such constraint.
        // Hypervisor 必须最先加载（Early-Launch 组），无依赖。
        //  The hypervisor must load first (Early-Launch group), no dependencies.
        // NetworkFilter 依赖 TCP/IP 协议栈，WFP callout 在网络栈就绪后注册。
        //  NetworkFilter depends on the TCP/IP stack; the WFP callout registers
        //  after the network stack is ready.
        dependencies: match kind {
            DriverKind::FileProtection => vec![ServiceDependency::Service("FltMgr".into())],
            DriverKind::NetworkFilter => vec![ServiceDependency::Service("Tcpip".into())],
            DriverKind::ProcessProtection => vec![],
            DriverKind::Hypervisor => vec![],
        },
        account_name: None,
        account_password: None,
    };

    manager
        .create_service(&info, ServiceAccess::QUERY_STATUS)
        .map_err(|e| {
            format!(
                "Failed to create {} service: {}",
                kind.service_name(),
                describe_service_error(&e)
            )
        })?;

    eprintln!("[DriverInstall] Created service {}", kind.service_name());
    Ok(())
}

/// 启动指定类型的驱动服务（公开接口，供 HypervisorService 按需调用）。
///  Starts the driver service of the given kind (public API for on-demand use
///  by HypervisorService).
///
/// 已在运行时视为成功；服务不存在或启动失败返回 Err。
///  Already-running counts as success; a missing service or a start failure
/// returns Err.
pub fn start_driver_service_by_kind(kind: DriverKind) -> Result<(), String> {
    start_driver_service(kind)
}

/// 检查指定类型的驱动服务是否已安装（服务键存在）。
///  Checks whether the driver service of the given kind is installed (service key exists).
///
/// 仅检查服务是否存在，不检查当前是否在运行——SYSTEM_START 驱动在重启后才加载，
/// 安装后、重启前服务已存在但状态为 Stopped，这是预期状态。
///  Only checks service existence, not whether it is currently running. A
///  SYSTEM_START driver loads after reboot; between install and reboot the
///  service exists but is Stopped, which is the expected state.
///
/// 调用方：commands::firewall::is_netfilter_installed（前端首次点击防火墙标签时检测）。
///  Called by: commands::firewall::is_netfilter_installed (checked when the user
///  first clicks the firewall tab).
pub fn is_driver_installed(kind: DriverKind) -> bool {
    use windows_service::service::ServiceAccess;
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = match ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        Ok(m) => m,
        Err(_) => return false,
    };
    manager
        .open_service(kind.service_name(), ServiceAccess::QUERY_STATUS)
        .is_ok()
}

/// 停止指定类型的驱动服务（公开接口，供 HypervisorService 按需调用）。
///  Stops the driver service of the given kind (public API for on-demand use
///  by HypervisorService).
///
/// 服务不存在或已停止时视为成功；停止失败返回 Err。注意：此函数只停止服务，
/// 不删除服务或驱动文件。
///  A missing or already-stopped service counts as success; a stop failure
///  returns Err. Note: this only stops the service, it does not delete the
///  service or the driver file.
pub fn stop_driver_service_by_kind(kind: DriverKind) -> Result<(), String> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("failed to open service manager: {}", e))?;

    let service = manager
        .open_service(
            kind.service_name(),
            ServiceAccess::QUERY_STATUS | ServiceAccess::STOP,
        )
        .map_err(|e| format!("failed to open {}: {}", kind.service_name(), e))?;

    let status = service
        .query_status()
        .map_err(|e| format!("failed to query {}: {}", kind.service_name(), e))?;

    if status.current_state == ServiceState::Stopped {
        eprintln!(
            "[DriverInstall] Service {} already stopped",
            kind.service_name()
        );
        return Ok(());
    }

    service
        .stop()
        .map_err(|e| format!("failed to stop {}: {}", kind.service_name(), e))?;

    // 给驱动的 DriverUnload 留出执行时间
    //  Give DriverUnload time to run
    std::thread::sleep(std::time::Duration::from_millis(1500));

    eprintln!("[DriverInstall] Stopped service {}", kind.service_name());
    Ok(())
}

/// 启动驱动服务；已在运行时视为成功。
///  Starts the driver service; already-running counts as success.
fn start_driver_service(kind: DriverKind) -> Result<(), String> {
    use windows_service::service::{ServiceAccess, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("Failed to open service manager: {}", e))?;

    let service = manager
        .open_service(
            kind.service_name(),
            ServiceAccess::QUERY_STATUS | ServiceAccess::START,
        )
        .map_err(|e| format!("Failed to open {}: {}", kind.service_name(), e))?;

    let status = service
        .query_status()
        .map_err(|e| format!("Failed to query {}: {}", kind.service_name(), e))?;
    if status.current_state == ServiceState::Running {
        eprintln!(
            "[DriverInstall] Service {} already running",
            kind.service_name()
        );
        return Ok(());
    }

    service.start(&[] as &[&OsStr]).map_err(|e| {
        format!(
            "Failed to start {}: {}",
            kind.service_name(),
            describe_service_error(&e)
        )
    })?;

    eprintln!("[DriverInstall] Started service {}", kind.service_name());
    Ok(())
}

/// 把 Windows 服务错误翻译成可操作的原因说明。
///  Translates a Windows service error into an actionable explanation.
///
/// 内核驱动加载失败的原因高度集中在签名与策略上，直接抛原始错误码用户无法自助。
///  Kernel driver load failures cluster around signing and policy; a bare error code leaves the
///  user with nothing to act on.
fn describe_service_error(error: &windows_service::Error) -> String {
    let text = error.to_string();
    let code = extract_os_error_code(&text);
    let hint = match code {
        // ERROR_INVALID_IMAGE_HASH
        Some(577) => Some(
            "驱动签名不被系统接受（内核驱动需要 EV 证书 + 微软 attestation 签名，\
             或在测试环境开启 testsigning）",
        ),
        // ERROR_ACCESS_DENIED
        Some(5) => Some("权限不足：加载内核驱动需要管理员权限与 SeLoadDriverPrivilege"),
        // ERROR_FILE_NOT_FOUND
        Some(2) => Some("驱动文件不存在或服务 binPath 指向的路径无效"),
        // ERROR_SERVICE_DISABLED
        Some(1058) => Some("驱动服务已被禁用"),
        // ERROR_DRIVER_BLOCKED
        Some(1275) => Some("驱动被系统策略阻止加载"),
        // ERROR_SERVICE_ALREADY_RUNNING
        Some(1056) => Some("服务已在运行"),
        _ => None,
    };

    match hint {
        Some(hint) => format!("{}（{}）", text, hint),
        None => text,
    }
}

fn extract_os_error_code(text: &str) -> Option<u32> {
    // windows-service 的错误串里带有底层 os error 码，例如 "os error 577"
    //  windows-service embeds the underlying OS error, e.g. "os error 577"
    let marker = "os error ";
    let start = text.find(marker)? + marker.len();
    let digits: String = text[start..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

// ============================================================================
// minifilter Instances 注册表 / Minifilter Instances registry
// ============================================================================

/// 写 minifilter 的 Instances 注册表结构。
///  Writes the minifilter Instances registry structure.
///
/// 结构（与 AnXinFileProtect.inf 的 AddReg 段等价）：
///  Structure (equivalent to the AddReg section in AnXinFileProtect.inf):
/// ```text
/// HKLM\SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Parameters\Instances
///     DefaultInstance = "AnXinFileProtect Instance"
///   \AnXinFileProtect Instance
///     Altitude = "328800"
///     Flags    = 0
/// ```
///
/// Instances 必须位于 Parameters\Instances 下，与 INF2Cat 验证要求一致。
/// 过滤管理器运行时查找 <Service>\Parameters\Instances。
///
/// Instances MUST live under Parameters\Instances, matching the INF2Cat
/// validation requirement. The filter manager looks up <Service>\Parameters\Instances.
fn minifilter_instances_key(service_name: &str) -> String {
    format!(
        r"SYSTEM\CurrentControlSet\Services\{}\Parameters\Instances",
        service_name
    )
}

fn write_minifilter_instances(service_name: &str) -> Result<(), String> {
    // 写入 Parameters\Instances（INF2Cat 要求）
    let param_base = format!(r"SYSTEM\CurrentControlSet\Services\{}\Parameters\Instances", service_name);
    let param_instance = format!(r"{}\{}", param_base, FILE_DRIVER_INSTANCE);
    registry_set_string(&param_base, "DefaultInstance", FILE_DRIVER_INSTANCE)?;
    registry_set_string(&param_instance, "Altitude", FILE_DRIVER_ALTITUDE)?;
    registry_set_u32(&param_instance, "Flags", 0)?;

    // 写入 Instances 直接根节点（FltMgr 开机 Boot-Start 查找路径）
    let root_base = format!(r"SYSTEM\CurrentControlSet\Services\{}\Instances", service_name);
    let root_instance = format!(r"{}\{}", root_base, FILE_DRIVER_INSTANCE);
    registry_set_string(&root_base, "DefaultInstance", FILE_DRIVER_INSTANCE)?;
    registry_set_string(&root_instance, "Altitude", FILE_DRIVER_ALTITUDE)?;
    registry_set_u32(&root_instance, "Flags", 0)?;

    // 设置 LoadOrderGroup，确保 minifilter 在正确的 FSFilter 组中加载。
    let service_key = format!(r"SYSTEM\CurrentControlSet\Services\{}", service_name);
    registry_set_string(&service_key, "Group", "FSFilter Anti-Virus")?;

    eprintln!(
        "[DriverInstall] Registered minifilter instance (altitude {}, group FSFilter Anti-Virus)",
        FILE_DRIVER_ALTITUDE
    );
    Ok(())
}

fn to_wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// 在 HKLM 下创建子键并写入字符串值 / Creates a subkey under HKLM and writes a string value
fn registry_set_string(subkey: &str, name: &str, value: &str) -> Result<(), String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_OPTION_NON_VOLATILE, REG_SZ,
    };

    let data = to_wide(value);
    // 不含结尾 NUL 的字节数由 RegSetValueExW 要求包含终止符，因此整段一起写
    //  RegSetValueExW expects the terminator to be included, so the whole buffer is written
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(data.as_ptr() as *const u8, std::mem::size_of_val(&data[..]))
    };

    unsafe {
        let mut key = HKEY::default();
        let status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(to_wide(subkey).as_ptr()),
            0,
            windows::core::PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        );
        if status.is_err() {
            return Err(format!(
                "Failed to create registry key {}: {:?}",
                subkey, status
            ));
        }

        let status = RegSetValueExW(
            key,
            windows::core::PCWSTR(to_wide(name).as_ptr()),
            0,
            REG_SZ,
            Some(bytes),
        );
        let _ = RegCloseKey(key);

        if status.is_err() {
            return Err(format!(
                "Failed to write registry value {}\\{}: {:?}",
                subkey, name, status
            ));
        }
    }
    Ok(())
}

/// 在 HKLM 下创建子键并写入 DWORD 值 / Creates a subkey under HKLM and writes a DWORD value
fn registry_set_u32(subkey: &str, name: &str, value: u32) -> Result<(), String> {
    use windows::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE,
        REG_DWORD, REG_OPTION_NON_VOLATILE,
    };

    let bytes = value.to_ne_bytes();

    unsafe {
        let mut key = HKEY::default();
        let status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            windows::core::PCWSTR(to_wide(subkey).as_ptr()),
            0,
            windows::core::PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            None,
            &mut key,
            None,
        );
        if status.is_err() {
            return Err(format!(
                "Failed to create registry key {}: {:?}",
                subkey, status
            ));
        }

        let status = RegSetValueExW(
            key,
            windows::core::PCWSTR(to_wide(name).as_ptr()),
            0,
            REG_DWORD,
            Some(&bytes),
        );
        let _ = RegCloseKey(key);

        if status.is_err() {
            return Err(format!(
                "Failed to write registry value {}\\{}: {:?}",
                subkey, name, status
            ));
        }
    }
    Ok(())
}

// ============================================================================
// 卸载 / Uninstall
// ============================================================================

/// 卸载两个内核驱动：解除自保护 → 停止 → 删除服务 → 删除文件（必要时重启删除）。
///  Removes both kernel drivers: release self-protection, stop, delete the service, delete the
///  file (scheduling a reboot deletion when required).
///
/// **只应由用户主动触发的卸载流程调用。** 自保护的设计目标是挡住外部篡改，
/// 而不是把软件变成删不掉的东西——因此这条路径必须始终可用且尽力完成。
///  **Only the user-initiated uninstall flow may call this.** Self-protection exists to stop
///  external tampering, not to make the product unremovable, so this path must always work and
///  make a best effort to finish.
///
/// 返回每一步的结果说明，即使部分失败也继续后续步骤——卸载不能因为一步失败就半途而废。
///  Returns a description of each step; later steps continue even if earlier ones fail, because an
///  uninstall must never abort halfway.
pub fn uninstall_drivers() -> Vec<String> {
    let mut report = Vec::new();

    // 1. 先解除驱动内部的保护列表，否则驱动会挡住对自身服务键与文件的删除
    //     Release the in-driver protection lists first, otherwise the driver blocks deletion of its
    //     own service keys and files
    match release_self_protection() {
        Ok(()) => report.push("已解除驱动自保护".to_string()),
        Err(err) => report.push(format!("解除驱动自保护失败（继续卸载）：{}", err)),
    }

    for kind in [
        DriverKind::FileProtection,
        DriverKind::ProcessProtection,
        DriverKind::Hypervisor,
        DriverKind::NetworkFilter,
    ] {
        match stop_and_delete_service(kind) {
            Ok(msg) => report.push(msg),
            Err(err) => report.push(format!("{} 停止/删除失败：{}", kind.service_name(), err)),
        }

        match remove_driver_file(kind) {
            Ok(msg) => report.push(msg),
            Err(err) => report.push(format!("{} 文件删除失败：{}", kind.file_name(), err)),
        }
    }

    report
}

/// 清空驱动内部的 PID 保护列表。
///  Clears the driver's in-memory PID protection list.
///
/// 注册表键保护已整体迁移到 AnXinFileProtect.sys（见 driver.c「Boot reinit callback」
/// 注释），AnXinProcProtect 不再提供 REG_KEY IOCTL；注册表保护随 FileProtect 服务停止
/// 而释放（CmCallback 注销），因此这里只清 PIDs。
///  Registry-key protection moved entirely to AnXinFileProtect.sys (see the "Boot reinit
///  callback" comment in driver.c); AnXinProcProtect no longer offers REG_KEY IOCTLs, and the
///  registry protection is released when the FileProtect service stops (CmCallback unregisters),
///  so only PIDs are cleared here.
///
/// 能打开 `\\.\AnXinProcProtect` 就意味着调用方已是管理员——而卸载本身也需要管理员，
/// 所以这条解锁通道不会降低安全边界：非管理员既解不开保护，也无法卸载。
///  Being able to open `\\.\AnXinProcProtect` already implies the caller is an administrator, and
///  uninstalling requires administrator anyway, so this unlock channel does not weaken the
///  boundary: a non-administrator can neither unlock nor uninstall.
fn release_self_protection() -> Result<(), String> {
    use crate::utils::driver_client::DriverClient;

    let client = DriverClient::new();
    client
        .connect()
        .map_err(|e| format!("driver device unavailable: {}", e))?;

    client
        .clear_pids()
        .map_err(|e| format!("failed to clear protected PIDs: {}", e))?;

    Ok(())
}

fn stop_and_delete_service(kind: DriverKind) -> Result<String, String> {
    use windows_service::service::{ServiceAccess, ServiceControl, ServiceState};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(|e| format!("failed to open service manager: {}", e))?;

    let service = match manager.open_service(
        kind.service_name(),
        ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE,
    ) {
        Ok(service) => service,
        // 服务不存在就是已经卸载干净，属于成功
        //  A missing service means it is already gone, which counts as success
        Err(_) => return Ok(format!("{} 服务不存在，无需删除", kind.service_name())),
    };

    if let Ok(status) = service.query_status() {
        if status.current_state != ServiceState::Stopped {
            if let Err(err) = service.stop() {
                eprintln!(
                    "[DriverInstall] Failed to stop {}: {} (will still delete)",
                    kind.service_name(),
                    err
                );
            } else {
                // 给驱动的 DriverUnload 留出执行时间，否则紧接着的删除必然被占用挡住
                //  Give DriverUnload time to run, otherwise the delete right after is blocked
                std::thread::sleep(std::time::Duration::from_millis(1500));
            }
        }
    }

    let _ = ServiceControl::Stop;

    service
        .delete()
        .map_err(|e| format!("failed to delete service: {}", e))?;

    Ok(format!("{} 服务已删除", kind.service_name()))
}

/// 删除驱动文件；被占用时安排重启后删除。
///  Deletes the driver file, scheduling a reboot deletion when it is still in use.
fn remove_driver_file(kind: DriverKind) -> Result<String, String> {
    let path = installed_driver_path(kind)?;
    if !path.exists() {
        return Ok(format!("{} 文件不存在", kind.file_name()));
    }

    match std::fs::remove_file(&path) {
        Ok(()) => Ok(format!("{} 已删除", kind.file_name())),
        Err(err) => {
            // 驱动尚未真正卸载时文件仍被内核占用，只能交给重启删除
            //  While the driver is still loaded the kernel holds the file open; defer to reboot
            schedule_delete_on_reboot(&path)?;
            Ok(format!(
                "{} 正在使用中（{}），已安排重启后删除",
                kind.file_name(),
                err
            ))
        }
    }
}

/// 用 MoveFileExW + MOVEFILE_DELAY_UNTIL_REBOOT 安排重启删除。
///  Schedules a reboot deletion via MoveFileExW + MOVEFILE_DELAY_UNTIL_REBOOT.
///
/// 该调用把条目写进 HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations，
/// 由会话管理器在下次启动的早期执行，需要管理员权限。
///  This writes an entry into PendingFileRenameOperations, executed early during the next boot by
///  the session manager. Administrator rights are required.
fn schedule_delete_on_reboot(path: &Path) -> Result<(), String> {
    use windows::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_DELAY_UNTIL_REBOOT};

    let wide = to_wide(&path.to_string_lossy());
    let result = unsafe {
        MoveFileExW(
            windows::core::PCWSTR(wide.as_ptr()),
            windows::core::PCWSTR::null(),
            MOVEFILE_DELAY_UNTIL_REBOOT,
        )
    };

    result.map_err(|e| {
        format!(
            "failed to schedule reboot deletion for {}: {}",
            path.display(),
            e
        )
    })
}

// ============================================================================
// 运行期保护登记 / Runtime protection registration
// ============================================================================

/// 把指定 PID 登记为受保护进程（安装程序用来保护自己）。
///  Registers a PID as protected (used by the installer to protect itself).
pub fn protect_pid(pid: u32) -> Result<(), String> {
    use crate::utils::driver_client::DriverClient;

    let client = DriverClient::new();
    client
        .connect()
        .map_err(|e| format!("driver device unavailable: {}", e))?;
    client
        .add_pid(pid)
        .map_err(|e| format!("failed to protect PID {}: {}", pid, e))
}

/// 把目录登记到文件保护 minifilter（安装程序用来保护安装目录）。
///  Registers a directory with the file protection minifilter (used to protect the install dir).
pub fn protect_directory(path: &Path) -> Result<(), String> {
    let nt_path = crate::services::windows_service::resolve_nt_path(path)?;
    crate::utils::driver_client::register_file_protection_paths(&[nt_path.as_str()])
}

// 注意：驱动服务键的注册表保护已从 AnXinProcProtect 的 REG_KEY IOCTL 迁移到
// AnXinFileProtect.sys 的硬编码 CmCallback 列表（SVC_KEY_*_STR），驱动加载即保护，
// 不再需要安装期用 add_reg_key 逐键登记；原先的 protect_driver_services() 因依赖
// 已删除的 IOCTL 而删除。见 driver.c「Boot reinit callback」注释。
//  Note: driver service-key registry protection moved from AnXinProcProtect's REG_KEY IOCTLs to
//  AnXinFileProtect.sys's hardcoded CmCallback list (SVC_KEY_*_STR), applied at driver load, so the
//  per-key add_reg_key registration at install time is no longer needed; the former
//  protect_driver_services() was removed because it depended on the deleted IOCTL. See the "Boot
//  reinit callback" comment in driver.c.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_kind_parses_expected_aliases() {
        assert_eq!(
            DriverKind::parse("proc"),
            Some(DriverKind::ProcessProtection)
        );
        assert_eq!(
            DriverKind::parse("PROCESS"),
            Some(DriverKind::ProcessProtection)
        );
        assert_eq!(DriverKind::parse("file"), Some(DriverKind::FileProtection));
        assert_eq!(
            DriverKind::parse(" filter "),
            Some(DriverKind::FileProtection)
        );
        assert_eq!(DriverKind::parse("hv"), Some(DriverKind::Hypervisor));
        assert_eq!(
            DriverKind::parse("HYPERVISOR"),
            Some(DriverKind::Hypervisor)
        );
        assert_eq!(DriverKind::parse("net"), Some(DriverKind::NetworkFilter));
        assert_eq!(
            DriverKind::parse("NETFILTER"),
            Some(DriverKind::NetworkFilter)
        );
        assert_eq!(DriverKind::parse("bogus"), None);
    }

    #[test]
    fn driver_kinds_map_to_distinct_services_and_files() {
        assert_ne!(
            DriverKind::ProcessProtection.service_name(),
            DriverKind::FileProtection.service_name()
        );
        assert_ne!(
            DriverKind::ProcessProtection.file_name(),
            DriverKind::FileProtection.file_name()
        );
        assert_ne!(
            DriverKind::Hypervisor.service_name(),
            DriverKind::ProcessProtection.service_name()
        );
        assert_ne!(
            DriverKind::Hypervisor.file_name(),
            DriverKind::ProcessProtection.file_name()
        );
        assert_ne!(
            DriverKind::NetworkFilter.service_name(),
            DriverKind::ProcessProtection.service_name()
        );
        assert_ne!(
            DriverKind::NetworkFilter.file_name(),
            DriverKind::ProcessProtection.file_name()
        );
        assert!(DriverKind::ProcessProtection.file_name().ends_with(".sys"));
        assert!(DriverKind::FileProtection.file_name().ends_with(".sys"));
        assert!(DriverKind::Hypervisor.file_name().ends_with(".sys"));
        assert!(DriverKind::NetworkFilter.file_name().ends_with(".sys"));
    }

    /// 高度值必须与 INF 一致，否则 INF 安装与手工安装会挂在不同位置。
    /// The altitude must match the INF, or INF-based and manual installs attach at different spots.
    #[test]
    fn minifilter_altitude_matches_inf() {
        let inf = [
            "native/file_protect/AnXinFileProtect.inf",
            "../native/file_protect/AnXinFileProtect.inf",
        ]
        .into_iter()
        .find_map(|path| std::fs::read_to_string(path).ok())
        .expect("AnXinFileProtect.inf should be readable");

        assert!(
            inf.contains(FILE_DRIVER_ALTITUDE),
            "INF 中的 Altitude 与代码常量 {} 不一致",
            FILE_DRIVER_ALTITUDE
        );
        assert!(
            inf.contains(FILE_DRIVER_INSTANCE),
            "INF 中的 DefaultInstance 与代码常量 {} 不一致",
            FILE_DRIVER_INSTANCE
        );
        assert!(
            inf.contains(r#"HKR, "Parameters\Instances""#),
            "INF 必须把 Instances 放在 Parameters\\Instances 下（HKR,\"Parameters\\Instances\"）"
        );
        assert_eq!(
            minifilter_instances_key(FILE_DRIVER_SERVICE),
            r"SYSTEM\CurrentControlSet\Services\AnXinFileProtect\Parameters\Instances"
        );
    }

    /// 错误码翻译必须覆盖内核驱动最常见的失败原因。
    /// The error translation must cover the most common kernel driver failure causes.
    #[test]
    fn os_error_code_is_extracted_from_error_text() {
        assert_eq!(extract_os_error_code("something (os error 577)"), Some(577));
        assert_eq!(extract_os_error_code("access denied (os error 5)"), Some(5));
        assert_eq!(extract_os_error_code("no code here"), None);
    }
}
