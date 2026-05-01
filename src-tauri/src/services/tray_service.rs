// 托盘图标与菜单服务
use tauri::{
    image::Image,
    menu::{Menu, MenuItem},
    tray::{MouseButton, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager,
};

pub struct TrayService;

impl TrayService {
    /// 创建系统托盘配置
    pub fn create_tray(app: &AppHandle) -> Result<(), String> {
        let show_main = MenuItem::with_id(app, "show_main", "显示主窗口", true, None::<&str>)
            .map_err(|e| e.to_string())?;
        let separator = MenuItem::new(app, "", false, None::<&str>)
            .map_err(|e| e.to_string())?;
        let exit = MenuItem::with_id(app, "exit", "退出", true, None::<&str>)
            .map_err(|e| e.to_string())?;

        let menu = Menu::with_items(app, &[&show_main, &separator, &exit])
            .map_err(|e| e.to_string())?;

        // 在编译时嵌入托盘图标
        let icon = Image::from_bytes(include_bytes!("../../icons/icon.ico"))
            .map_err(|e| format!("Failed to load tray icon: {}", e))?;

        let _tray = TrayIconBuilder::new()
            .icon(icon)
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
                    Self::show_main_window(app);
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
                Self::show_main_window(app);
            }
            "exit" => {
                // 先显示窗口，确保用户能看到退出确认弹窗
                Self::show_main_window(app);
                // 触发前端退出确认流程
                if let Err(e) = app.emit("tray-exit-requested", ()) {
                    eprintln!("Failed to emit tray exit event: {}", e);
                }
            }
            _ => {}
        }
    }

    /// 显示主窗口
    fn show_main_window(app: &AppHandle) {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }

    /// 隐藏主窗口到托盘
    pub fn hide_to_tray(app: &AppHandle) {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.hide();
        }
    }
}
