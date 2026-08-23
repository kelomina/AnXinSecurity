fn main() {
    emit_windows_manifest_link_args();
}

/// 函数名称：emit_windows_manifest_link_args
/// 函数作用：为 Windows Rust 链接目标嵌入统一 manifest（Common Controls v6），
///           使本包的集成测试二进制与 GUI 进程行为一致，避免启动期 ENTRYPOINT_NOT_FOUND。
/// Purpose: Embeds the unified Windows manifest (Common Controls v6) into this package's
///           link targets so integration-test binaries behave like the GUI processes and
///           avoid startup ENTRYPOINT_NOT_FOUND.
/// 调用方：build.rs main。
/// Called by: build.rs main.
/// 说明：manifest 文件保持单一来源（workspace 根 src-tauri/windows-app-manifest.xml），
///       此处以构建期绝对路径引用，避免多份拷贝漂移。
/// Note: the manifest keeps a single source of truth (src-tauri/windows-app-manifest.xml),
///       referenced here via a build-time absolute path so copies cannot drift.
#[cfg(windows)]
fn emit_windows_manifest_link_args() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR is set by Cargo for build scripts");
    let manifest_path = std::path::Path::new(&manifest_dir)
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

/// 非 Windows 平台不需要 Windows manifest。
///  Non-Windows platforms do not need a Windows manifest.
#[cfg(not(windows))]
fn emit_windows_manifest_link_args() {}
