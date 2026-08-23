// 独立拦截窗口服务 — 确保安全拦截提示不依赖主窗口可见性
// Independent interception window service — keeps security prompts visible even when the main window is hidden.
use crate::services::app_lifecycle_service::app_is_exiting;
use crate::services::interception_diagnostics_service::append_interception_diagnostic;
use tauri::{
    AppHandle, Manager, Runtime, WebviewUrl, WebviewWindow, WebviewWindowBuilder, WindowEvent,
};

const INTERCEPTION_WINDOW_LABEL: &str = "interception";

/// 函数名称：prepare_interception_window
/// 函数作用：创建或复用独立拦截窗口，但不显示它。
/// Purpose: Creates or reuses the independent interception window without showing it.
pub fn prepare_interception_window<R: Runtime>(
    app_handle: &AppHandle<R>,
) -> Result<WebviewWindow<R>, String> {
    let window = match app_handle.get_webview_window(INTERCEPTION_WINDOW_LABEL) {
        Some(window) => window,
        None => build_interception_window(app_handle)?,
    };
    Ok(window)
}

/// 函数名称：show_interception_window
/// 函数作用：创建或复用独立拦截窗口，并确保窗口显示、置顶和获得焦点。
/// Purpose: Creates or reuses the independent interception window, then makes it visible and focused.
pub fn show_interception_window<R: Runtime>(
    app_handle: &AppHandle<R>,
) -> Result<WebviewWindow<R>, String> {
    append_interception_diagnostic(
        "show_interception_window_enter",
        serde_json::json!({
            "label": INTERCEPTION_WINDOW_LABEL,
            "existing": app_handle.get_webview_window(INTERCEPTION_WINDOW_LABEL).is_some(),
        }),
    );
    let window = prepare_interception_window(app_handle)?;
    window.show().map_err(|err| {
        let message = format!("Failed to show interception window: {}", err);
        append_interception_diagnostic(
            "show_interception_window_error",
            serde_json::json!({
                "label": INTERCEPTION_WINDOW_LABEL,
                "step": "show",
                "error": message,
            }),
        );
        message
    })?;
    let always_on_top_result = window
        .set_always_on_top(true)
        .map_err(|err| err.to_string());
    let focus_result = window.set_focus().map_err(|err| err.to_string());
    append_interception_diagnostic(
        "show_interception_window_ok",
        serde_json::json!({
            "label": INTERCEPTION_WINDOW_LABEL,
            "alwaysOnTop": always_on_top_result,
            "focus": focus_result,
        }),
    );
    Ok(window)
}

/// 函数名称：hide_interception_window
/// 函数作用：隐藏独立拦截窗口，通常在用户完成允许/阻止后调用。
/// Purpose: Hides the independent interception window, usually after allow/block is handled.
pub fn hide_interception_window<R: Runtime>(app_handle: &AppHandle<R>) {
    if let Some(window) = app_handle.get_webview_window(INTERCEPTION_WINDOW_LABEL) {
        let _ = window.hide();
    }
}

fn build_interception_window<R: Runtime>(
    app_handle: &AppHandle<R>,
) -> Result<WebviewWindow<R>, String> {
    append_interception_diagnostic(
        "build_interception_window_enter",
        serde_json::json!({
            "label": INTERCEPTION_WINDOW_LABEL,
        }),
    );
    let window = WebviewWindowBuilder::new(
        app_handle,
        INTERCEPTION_WINDOW_LABEL,
        WebviewUrl::App("index.html".into()),
    )
    .title("AnXin Security - Threat Interception")
    .inner_size(640.0, 480.0)
    .min_inner_size(640.0, 480.0)
    .resizable(false)
    .decorations(false)
    .transparent(false)
    .always_on_top(true)
    .focused(true)
    .visible(false)
    .skip_taskbar(false)
    .content_protected(true)
    .center()
    // 与主窗口保持一致的 WebView2 浏览器参数：不同的 CoreWebView2EnvironmentOptions
    // 在同一 user data folder 下会导致 WebView2 启动独立的浏览器进程（内存翻倍）或创建失败，
    // 因此拦截窗口必须逐字节复用主窗口的 additionalBrowserArgs（见 tauri.conf.json）。
    // Keep the same WebView2 browser arguments as the main window: different
    // CoreWebView2EnvironmentOptions under the same user data folder make WebView2 spin up a
    // separate browser process (doubling memory) or fail, so this must byte-for-byte match
    // the main window's additionalBrowserArgs (see tauri.conf.json).
    .additional_browser_args("--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --disable-gpu --disable-background-networking --disable-component-update")
    .build()
    .map_err(|err| {
        let message = format!("Failed to create interception window: {}", err);
        append_interception_diagnostic(
            "build_interception_window_error",
            serde_json::json!({
                "label": INTERCEPTION_WINDOW_LABEL,
                "error": message,
            }),
        );
        message
    })?;
    append_interception_diagnostic(
        "build_interception_window_ok",
        serde_json::json!({
            "label": INTERCEPTION_WINDOW_LABEL,
        }),
    );

    let app_handle_for_close = app_handle.clone();
    let window_for_close = window.clone();
    window.on_window_event(move |event| {
        if let WindowEvent::CloseRequested { api, .. } = event {
            // 正常运行时，用户点拦截窗口关闭按钮只隐藏窗口；
            // 但应用整体退出时不能再 prevent_close，否则隐藏窗口会拦住 Tauri 的退出清理。
            if app_is_exiting(&app_handle_for_close) {
                return;
            }
            api.prevent_close();
            let _ = window_for_close.hide();
        }
    });

    Ok(window)
}
