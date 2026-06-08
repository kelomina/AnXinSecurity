fn main() {
    emit_windows_manifest_link_args();
    run_tauri_build();
}

/// 函数名称：emit_windows_manifest_link_args
/// 函数作用：为 Windows Rust 链接目标嵌入应用 manifest，确保库测试和主程序启动前使用 Common Controls v6。
/// Purpose: Embeds the application manifest for Windows Rust link targets so lib tests and the app use Common Controls v6 before startup.
/// 调用方：build.rs main。
/// Called by: build.rs main.
/// 被调用方：std::env::var，std::path::PathBuf::join，println!。
/// Calls: std::env::var, std::path::PathBuf::join, println!.
/// 错误处理：CARGO_MANIFEST_DIR 由 Cargo 为 build script 提供；缺失时用明确 expect 信息终止构建。
/// Error handling: CARGO_MANIFEST_DIR is provided by Cargo for build scripts; a clear expect message stops the build if it is missing.
/// 中文关键词：Windows manifest，Common Controls v6，Rust 测试，入口点错误，TaskDialogIndirect
/// English keywords: Windows manifest, Common Controls v6, Rust tests, entry point error, TaskDialogIndirect
#[cfg(windows)]
fn emit_windows_manifest_link_args() {
    let manifest_path = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is set by Cargo for build scripts"),
    )
    .join("windows-app-manifest.xml");

    println!("cargo:rerun-if-changed={}", manifest_path.display());
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg=/MANIFESTINPUT:{}",
        manifest_path.display()
    );
    println!("cargo:rustc-link-arg=/WX");
}

/// 函数名称：emit_windows_manifest_link_args
/// 函数作用：非 Windows 平台无需为 Rust 链接目标嵌入 Windows manifest。
/// Purpose: Non-Windows platforms do not need a Windows manifest for Rust link targets.
/// 调用方：build.rs main。
/// Called by: build.rs main.
/// 中文关键词：非 Windows，构建脚本，空实现
/// English keywords: non-Windows, build script, no-op
#[cfg(not(windows))]
fn emit_windows_manifest_link_args() {}

/// 函数名称：run_tauri_build
/// 函数作用：运行 Tauri 构建脚本；Windows 下关闭 tauri-build 默认 manifest，避免和统一链接 manifest 重复。
/// Purpose: Runs the Tauri build script; on Windows disables tauri-build's default manifest to avoid duplicating the unified link manifest.
/// 调用方：build.rs main。
/// Called by: build.rs main.
/// 被调用方：tauri_build::try_build，tauri_build::Attributes::new，tauri_build::WindowsAttributes::new_without_app_manifest。
/// Calls: tauri_build::try_build, tauri_build::Attributes::new, tauri_build::WindowsAttributes::new_without_app_manifest.
/// 错误处理：tauri-build 失败时用明确 expect 信息终止构建。
/// Error handling: a clear expect message stops the build when tauri-build fails.
/// 中文关键词：Tauri 构建，manifest 去重，Windows 资源，构建脚本
/// English keywords: Tauri build, manifest deduplication, Windows resource, build script
#[cfg(windows)]
fn run_tauri_build() {
    let windows = tauri_build::WindowsAttributes::new_without_app_manifest();
    let attributes = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attributes).expect("failed to run tauri build script");
}

/// 函数名称：run_tauri_build
/// 函数作用：非 Windows 平台按 Tauri 默认方式运行构建脚本。
/// Purpose: Runs the Tauri build script with defaults on non-Windows platforms.
/// 调用方：build.rs main。
/// Called by: build.rs main.
/// 被调用方：tauri_build::build。
/// Calls: tauri_build::build.
/// 中文关键词：Tauri 构建，非 Windows，默认构建
/// English keywords: Tauri build, non-Windows, default build
#[cfg(not(windows))]
fn run_tauri_build() {
    tauri_build::build()
}
