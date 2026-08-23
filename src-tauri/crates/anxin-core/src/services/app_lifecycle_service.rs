// 应用生命周期服务 — 记录退出阶段，避免后台任务继续操作正在销毁的窗口
// App lifecycle service — tracks shutdown state so background tasks do not touch destroying windows.
use std::sync::atomic::{AtomicBool, Ordering};
use tauri::{AppHandle, Manager, Runtime};

/// 函数名称：AppLifecycleService
/// 函数作用：保存应用是否已经进入退出流程。
/// 可以把它理解成“打烊牌”：一旦挂出打烊牌，后台服务就知道不要再打开或拦截窗口。
/// Purpose: Stores whether the app has entered shutdown.
pub struct AppLifecycleService {
    exiting: AtomicBool,
}

impl AppLifecycleService {
    /// 创建生命周期状态，默认表示应用仍在正常运行。
    pub fn new() -> Self {
        Self {
            exiting: AtomicBool::new(false),
        }
    }

    /// 标记应用开始退出。
    /// 返回 true 表示本次调用是第一次进入退出流程；返回 false 表示已经在退出中。
    pub fn begin_exit(&self) -> bool {
        !self.exiting.swap(true, Ordering::SeqCst)
    }

    /// 查询应用是否正在退出。
    pub fn is_exiting(&self) -> bool {
        self.exiting.load(Ordering::SeqCst)
    }
}

/// 函数名称：app_is_exiting
/// 函数作用：给窗口事件处理器和后台任务使用的安全查询入口。
/// 如果生命周期服务尚未注册，保守返回 false，避免影响测试或早期初始化路径。
pub fn app_is_exiting<R: Runtime>(app_handle: &AppHandle<R>) -> bool {
    app_handle
        .try_state::<AppLifecycleService>()
        .map(|state| state.is_exiting())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn begin_exit_is_idempotent() {
        let lifecycle = AppLifecycleService::new();

        assert!(!lifecycle.is_exiting());
        assert!(lifecycle.begin_exit());
        assert!(lifecycle.is_exiting());
        assert!(!lifecycle.begin_exit());
    }
}
