fn main() {
    emit_windows_manifest_link_args();
}

/// 函数名称：emit_windows_manifest_link_args
/// 函数作用：为 Windows 链接目标嵌入统一 manifest（Common Controls v6），与主程序保持一致，
///           避免启动期 ENTRYPOINT_NOT_FOUND。
/// Purpose: Embeds the unified Windows manifest (Common Controls v6), consistent with the
///           main app, avoiding startup ENTRYPOINT_NOT_FOUND.
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
