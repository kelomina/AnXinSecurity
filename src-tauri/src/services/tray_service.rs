// 托盘图标与菜单服务
use tauri::{
    menu::{Menu, MenuItem},
    tray::{TrayIconBuilder, TrayIconEvent},
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

        let _tray = TrayIconBuilder::new()
            .menu(&menu)
            .on_menu_event(|app, event| {
                Self::handle_menu_event(event.id.as_ref(), &app);
            })
            .on_tray_icon_event(|tray, event| {
                if let TrayIconEvent::Click { .. } = event {
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
