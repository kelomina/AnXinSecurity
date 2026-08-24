// 托盘图标与菜单服务
//  Tray icon and menu service
//
// 拆分架构下的双模式：
// - 进程内存在 "main" 窗口（旧单 exe UI）：保持历史行为——聚焦主窗口、
//   经 tray-exit-requested 事件让主窗口前端弹退出确认。
// - 进程内没有 "main" 窗口（独立 Tray 进程）：左键/菜单「显示主窗口」改为拉起
//   同目录的 Main 程序（已运行时由 single-instance 插件激活）；「退出」按配置
//   弹出独立的 exit-confirm 小窗口或直接执行完整退出。
//  Dual mode under the split architecture:
//  - With an in-process "main" window (legacy single-exe UI): keep the historical
//    behavior — focus the main window and let its frontend prompt exit confirmation
//    via the tray-exit-requested event.
//  - Without a "main" window (standalone Tray process): left click / "show main"
//    spawns the sibling Main executable (single-instance plugin activates it when
//    already running); "exit" opens the standalone exit-confirm window or exits
//    directly, per configuration.
use std::sync::{Arc, Mutex};

use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    webview::WebviewWindowBuilder,
    AppHandle, Emitter, Manager, WebviewUrl, WebviewWindow,
};

use crate::commands::i18n::lookup_rust_side_text;
use crate::models::config::AppConfig;

pub struct TrayService;

impl TrayService {
    /// 创建系统托盘配置
    pub fn create_tray(app: &AppHandle) -> Result<(), String> {
        let labels = Self::menu_labels(app);
        let show_main = MenuItem::with_id(app, "show_main", &labels.show_main, true, None::<&str>)
            .map_err(|e| e.to_string())?;
        let separator = MenuItem::new(app, "", false, None::<&str>).map_err(|e| e.to_string())?;
        let exit = MenuItem::with_id(app, "exit", &labels.exit, true, None::<&str>)
            .map_err(|e| e.to_string())?;

        let menu =
            Menu::with_items(app, &[&show_main, &separator, &exit]).map_err(|e| e.to_string())?;

        // 在编译时嵌入托盘图标
        let icon = Image::from_bytes(include_bytes!("../../../../icons/icon.ico"))
            .map_err(|e| format!("Failed to load tray icon: {}", e))?;

        let _tray = TrayIconBuilder::new()
            .icon(icon)
            .tooltip("AnXin Security")
            .menu(&menu)
            .on_menu_event(|app, event| {
                Self::handle_menu_event(event.id.as_ref(), &app);
            })
            .on_tray_icon_event(|tray, event| {
                // 仅左键点击打开主界面；右键由 Tauri 自动弹出上下文菜单
                if let TrayIconEvent::Click {
                    button: MouseButton::Left,
                    ..
                } = event
                {
                    let app = tray.app_handle();
                    Self::open_main_ui(app);
                }
            })
            .build(app)
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// 处理菜单事件
    fn handle_menu_event(id: &str, app: &AppHandle) {
        match id {
            "show_main" => {
                Self::open_main_ui(app);
            }
            "exit" => {
                Self::request_exit(app);
            }
            _ => {}
        }
    }

    /// 打开主界面：进程内有 main 窗口则聚焦（旧 UI 兼容），否则拉起同目录的
    /// Main 程序——已运行实例由 single-instance 插件负责激活。
    ///  Open the main UI: focus the in-process main window when present (legacy UI),
    ///  otherwise spawn the sibling Main executable — an already-running instance is
    ///  activated by the single-instance plugin.
    fn open_main_ui(app: &AppHandle) {
        if app.get_webview_window("main").is_some() {
            Self::focus_in_process_main_window(app);
            return;
        }
        if let Err(e) = launch_main_ui_process() {
            eprintln!("[Tray] Failed to launch main UI process: {}", e);
        }
    }

    /// 聚焦进程内主窗口（旧单 exe 行为）。
    ///  Focus the in-process main window (legacy single-exe behavior).
    fn focus_in_process_main_window(app: &AppHandle) {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.set_focus();
            // 通知前端退出内存节省模式，恢复定时刷新
            //  Notify frontend to exit memory-saving mode and resume periodic refresh
            let _ = app.emit("memory-mode-changed", false);
        }
    }

    /// 托盘「退出」入口：
    /// - 有 main 窗口（旧 UI）：显示窗口并 emit tray-exit-requested，由主窗口前端确认。
    /// - 无 main 窗口（Tray 进程）：按配置决定是否弹独立 exit-confirm 窗口；
    ///   未启用确认时直接执行退出。
    ///  Tray "exit" entry:
    ///  - With a main window (legacy UI): show it and emit tray-exit-requested so its
    ///    frontend prompts for confirmation.
    ///  - Without one (Tray process): open the standalone exit-confirm window per config,
    ///    or execute the exit directly when confirmation is disabled.
    fn request_exit(app: &AppHandle) {
        if app.get_webview_window("main").is_some() {
            // 先显示窗口，确保用户能看到退出确认弹窗
            Self::focus_in_process_main_window(app);
            if let Err(e) = app.emit("tray-exit-requested", ()) {
                eprintln!("Failed to emit tray exit event: {}", e);
            }
            return;
        }

        match read_exit_confirmation_config(app) {
            Some(cfg) if cfg.prompt_enabled => {
                match ensure_exit_confirm_window(app) {
                    Ok(window) => {
                        let _ = window.show();
                        let _ = window.set_focus();
                        // 让前端把确认对话框置为打开状态（幂等）
                        //  Ask the frontend to open the confirm dialog (idempotent)
                        if let Err(e) = app.emit_to("exit-confirm", "tray-exit-requested", ()) {
                            eprintln!("[Tray] Failed to emit exit-confirm event: {}", e);
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "[Tray] Failed to create exit-confirm window, exiting directly: {}",
                            e
                        );
                        Self::spawn_direct_exit(app);
                    }
                }
            }
            _ => Self::spawn_direct_exit(app),
        }
    }

    /// 从托盘直接退出（无确认路径）：复用统一退出命令，keepService 取配置默认值。
    ///  Direct exit from tray (no confirmation): reuse the unified exit command with the
    ///  configured keepService default.
    fn spawn_direct_exit(app: &AppHandle) {
        let keep_service = read_exit_confirmation_config(app)
            .map(|cfg| cfg.keep_service)
            .unwrap_or(true);
        let app = app.clone();
        tauri::async_runtime::spawn(async move {
            if let Err(e) =
                crate::commands::tray::execute_exit_after_invoke_response(app, keep_service).await
            {
                eprintln!("[Tray] Exit failed: {}", e);
            }
        });
    }

    /// 隐藏主窗口到托盘
    pub fn hide_to_tray(app: &AppHandle) {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.hide();
            // 通知前端进入内存节省模式，停止定时刷新（后台防护保持运行）
            //  Notify frontend to enter memory-saving mode, stop periodic refresh (background protection continues)
            let _ = app.emit("memory-mode-changed", true);
        }
    }

    /// 读取托盘菜单文案：优先当前 locale 的语言包，缺失时回退中文默认。
    ///  Resolve tray menu labels: prefer the current locale's language pack, fall back to
    ///  Chinese defaults when missing.
    fn menu_labels(app: &AppHandle) -> MenuLabels {
        let locale = read_locale(app);
        MenuLabels {
            show_main: lookup_rust_side_text(&locale, "tray_show_main")
                .unwrap_or_else(|| "显示主窗口".to_string()),
            exit: lookup_rust_side_text(&locale, "tray_exit")
                .unwrap_or_else(|| "退出".to_string()),
        }
    }
}

/// 托盘菜单文案集。
///  Tray menu label set.
struct MenuLabels {
    show_main: String,
    exit: String,
}

/// 从 managed 配置读当前 locale；读取失败回退 zh-CN。
///  Read the current locale from managed config; fall back to zh-CN on failure.
fn read_locale(app: &AppHandle) -> String {
    if let Some(config) = app.try_state::<Arc<Mutex<AppConfig>>>() {
        let guard = config.lock().unwrap_or_else(|e| e.into_inner());
        return guard.locale.clone();
    }
    "zh-CN".to_string()
}

/// 读取托盘退出确认配置；配置不可用时返回 None（调用方走直接退出/默认值）。
///  Read the tray exit-confirmation config; returns None when unavailable (caller uses
///  direct exit / defaults).
pub fn read_exit_confirmation_config(app: &AppHandle) -> Option<crate::commands::tray::ExitConfirmation> {
    let config = app.try_state::<Arc<Mutex<AppConfig>>>()?;
    let guard = config.lock().ok()?;
    let tray_cfg = &guard.tray;
    Some(crate::commands::tray::ExitConfirmation {
        keep_service: tray_cfg.exit_keep_scanner_service_default.unwrap_or(true),
        prompt_enabled: tray_cfg.exit_keep_scanner_service_prompt.unwrap_or(true),
    })
}

/// 确保 exit-confirm 窗口存在（创建或复用）并返回它。
///  Ensure the exit-confirm window exists (create or reuse) and return it.
fn ensure_exit_confirm_window(app: &AppHandle) -> Result<WebviewWindow, String> {
    if let Some(window) = app.get_webview_window("exit-confirm") {
        return Ok(window);
    }

    let window = WebviewWindowBuilder::new(
        app,
        "exit-confirm",
        WebviewUrl::App("index.html".into()),
    )
    .title("AnXin Security")
    .inner_size(420.0, 240.0)
    .decorations(false)
    .resizable(false)
    .maximizable(false)
    .minimizable(false)
    .skip_taskbar(true)
    .always_on_top(true)
    .center()
    .visible(false)
    .additional_browser_args(
        "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection \
         --disable-gpu --disable-background-networking --disable-component-update",
    )
    .build()
    .map_err(|e| format!("Failed to build exit-confirm window: {}", e))?;

    Ok(window)
}

/// 拉起同目录的 Main 主界面程序（AnXinSecurity.exe / anxin-security.exe）；
/// 找不到拆分后的 Main 时回退自身（单 exe 兼容期，自身即旧全功能 UI）。
///  Spawn the sibling Main UI executable (AnXinSecurity.exe / anxin-security.exe);
///  falls back to self during the single-exe compatibility window.
///
/// 中文关键词：拉起主程序，托盘，打开主界面，进程启动
/// English keywords: launch main executable, tray, open main UI, process start
pub fn launch_main_ui_process() -> Result<(), String> {
    // Main 已运行时重复 spawn 由 Main 自身的单实例互斥体兜底（新进程立即退出）。
    //  Duplicate spawns when Main already runs are handled by Main's own
    //  singleton mutex (the duplicate exits immediately).
    let self_exe = std::env::current_exe().map_err(|e| format!("current_exe failed: {}", e))?;
    let dir = self_exe
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(std::path::PathBuf::new);

    let mut target = self_exe.clone();
    for name in ["AnXinSecurity.exe", "anxin-security.exe"] {
        let candidate = dir.join(name);
        if candidate.exists() && candidate != self_exe {
            target = candidate;
            break;
        }
    }

    eprintln!("[Tray] Launching main UI: {}", target.display());
    std::process::Command::new(target)
        .spawn()
        .map_err(|e| format!("failed to spawn main UI process: {}", e))?;
    Ok(())
}
