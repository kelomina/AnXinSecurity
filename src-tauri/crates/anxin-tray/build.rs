fn main() {
    emit_windows_manifest_link_args();
    run_tauri_build();
}

/// 函数名称：emit_windows_manifest_link_args
/// 函数作用：为 Windows 链接目标嵌入统一 manifest（Common Controls v6），与主程序保持一致。
/// Purpose: Embeds the unified Windows manifest (Common Controls v6), consistent with the main app.
#[cfg(windows)]
fn emit_windows_manifest_link_args() {
    let manifest_path = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR")
            .expect("CARGO_MANIFEST_DIR is set by Cargo for build scripts"),
    )
    .join("../../windows-app-manifest.xml")
    .canonicalize()
    .expect("windows-app-manifest.xml must exist next to the workspace root");

    println!("cargo:rerun-if-changed={}", manifest_path.display());
    println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
    println!(
        "cargo:rustc-link-arg=/MANIFESTINPUT:{}",
        manifest_path.display()
    );
    println!("cargo:rustc-link-arg=/WX");
}

#[cfg(not(windows))]
fn emit_windows_manifest_link_args() {}

/// 函数名称：run_tauri_build
/// 函数作用：运行 Tauri 构建脚本；Windows 下关闭 tauri-build 默认 manifest，避免重复。
/// Purpose: Runs the Tauri build script; disables tauri-build's default manifest on Windows.
#[cfg(windows)]
fn run_tauri_build() {
    let windows = tauri_build::WindowsAttributes::new_without_app_manifest();
    let attributes = tauri_build::Attributes::new().windows_attributes(windows);
    tauri_build::try_build(attributes).expect("failed to run tauri build script");
}

#[cfg(not(windows))]
fn run_tauri_build() {
    tauri_build::build()
}
