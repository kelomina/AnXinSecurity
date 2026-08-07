use anxin_security::services::process_monitor_service::{
    process_hook_default_path_candidates, resolve_process_hook_paths,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempProcessHookDir {
    root: PathBuf,
}

impl TempProcessHookDir {
    fn new(test_name: &str) -> Self {
        let unique_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "anxin_process_hook_{}_{}_{}",
            std::process::id(),
            test_name,
            unique_id
        ));

        fs::create_dir_all(&root).expect("test temp directory should be created");
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }

    fn create_resource_file(&self, arch_dir: &str, file_name: &str) -> PathBuf {
        let file_path = self.root.join(arch_dir).join(file_name);
        fs::create_dir_all(file_path.parent().expect("file should have parent"))
            .expect("resource arch directory should be created");
        fs::write(&file_path, b"test binary placeholder")
            .expect("placeholder resource file should be written");
        file_path
    }
}

impl Drop for TempProcessHookDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn resource_path_candidates_include_development_then_resource_locations() {
    let resource_dir = TempProcessHookDir::new("candidate_order");

    let candidates = process_hook_default_path_candidates(
        "win32-x64",
        "file_hook_injector.exe",
        Some(resource_dir.path()),
    );

    assert!(
        candidates.len() >= 2,
        "default candidates should include development and resource locations"
    );
    assert!(
        candidates[0]
            .to_string_lossy()
            .contains(r"native/bin\win32-x64\file_hook_injector.exe")
            || candidates[0]
                .to_string_lossy()
                .contains("native/bin/win32-x64/file_hook_injector.exe"),
        "development native/bin candidate should be checked first: {}",
        candidates[0].display()
    );
    assert_eq!(
        candidates[1],
        resource_dir
            .path()
            .join("native/bin")
            .join("win32-x64")
            .join("file_hook_injector.exe")
    );
}

#[test]
fn resolve_process_hook_paths_selects_matching_architecture_files_from_resource_dir() {
    let resource_dir = TempProcessHookDir::new("resolve_resource");
    resource_dir.create_resource_file("native/bin/win32-x64", "file_hook_injector.exe");
    resource_dir.create_resource_file("native/bin/win32-x86", "file_hook_injector.exe");
    resource_dir.create_resource_file("native/bin/win32-x64", "file_hook_detours.dll");
    resource_dir.create_resource_file("native/bin/win32-x86", "file_hook_detours.dll");

    let resolved = resolve_process_hook_paths("", "", "", "", Some(resource_dir.path()))
        .expect("resource files should resolve");

    assert!(
        resolved
            .injector_x64
            .ends_with(Path::new("win32-x64").join("file_hook_injector.exe")),
        "x64 injector should resolve from a win32-x64 path: {}",
        resolved.injector_x64.display()
    );
    assert!(
        resolved
            .injector_x86
            .ends_with(Path::new("win32-x86").join("file_hook_injector.exe")),
        "x86 injector should resolve from a win32-x86 path: {}",
        resolved.injector_x86.display()
    );
    assert!(
        resolved
            .dll_x64
            .ends_with(Path::new("win32-x64").join("file_hook_detours.dll")),
        "x64 DLL should resolve from a win32-x64 path: {}",
        resolved.dll_x64.display()
    );
    assert!(
        resolved
            .dll_x86
            .ends_with(Path::new("win32-x86").join("file_hook_detours.dll")),
        "x86 DLL should resolve from a win32-x86 path: {}",
        resolved.dll_x86.display()
    );
}

#[test]
fn resolve_process_hook_paths_reports_clear_error_when_required_file_is_missing() {
    let resource_dir = TempProcessHookDir::new("missing_error");
    let injector_x64 =
        resource_dir.create_resource_file("native/bin/win32-x64", "file_hook_injector.exe");
    let injector_x86 =
        resource_dir.create_resource_file("native/bin/win32-x86", "file_hook_injector.exe");
    let dll_x64 =
        resource_dir.create_resource_file("native/bin/win32-x64", "file_hook_detours.dll");
    let missing_dll_x86 = resource_dir
        .path()
        .join("native/bin")
        .join("win32-x86")
        .join("file_hook_detours.dll");

    let error = resolve_process_hook_paths(
        &injector_x64.to_string_lossy(),
        &injector_x86.to_string_lossy(),
        &dll_x64.to_string_lossy(),
        &missing_dll_x86.to_string_lossy(),
        Some(resource_dir.path()),
    )
    .expect_err("missing x86 DLL should return an error");

    assert!(
        error.contains("Missing APIHook x86 DLL file 'file_hook_detours.dll'"),
        "error should name the missing x86 DLL: {error}"
    );
    assert!(
        error.contains("win32-x86") && error.contains("file_hook_detours.dll"),
        "error should include checked explicit path: {error}"
    );
}

#[test]
fn explicit_existing_paths_are_accepted_when_they_match_trusted_resources() {
    let resource_dir = TempProcessHookDir::new("explicit_paths");
    let injector_x64 =
        resource_dir.create_resource_file("native/bin/win32-x64", "file_hook_injector.exe");
    let injector_x86 =
        resource_dir.create_resource_file("native/bin/win32-x86", "file_hook_injector.exe");
    let dll_x64 =
        resource_dir.create_resource_file("native/bin/win32-x64", "file_hook_detours.dll");
    let dll_x86 =
        resource_dir.create_resource_file("native/bin/win32-x86", "file_hook_detours.dll");

    let resolved = resolve_process_hook_paths(
        &injector_x64.to_string_lossy(),
        &injector_x86.to_string_lossy(),
        &dll_x64.to_string_lossy(),
        &dll_x86.to_string_lossy(),
        Some(resource_dir.path()),
    )
    .expect("explicit paths that resolve to trusted resources should resolve");

    assert_eq!(
        resolved.injector_x64,
        fs::canonicalize(injector_x64).unwrap()
    );
    assert_eq!(
        resolved.injector_x86,
        fs::canonicalize(injector_x86).unwrap()
    );
    assert_eq!(resolved.dll_x64, fs::canonicalize(dll_x64).unwrap());
    assert_eq!(resolved.dll_x86, fs::canonicalize(dll_x86).unwrap());
}

#[test]
fn explicit_existing_paths_outside_trusted_resources_are_rejected() {
    let resource_dir = TempProcessHookDir::new("trusted_resources");
    resource_dir.create_resource_file("native/bin/win32-x64", "file_hook_injector.exe");
    resource_dir.create_resource_file("native/bin/win32-x86", "file_hook_injector.exe");
    resource_dir.create_resource_file("native/bin/win32-x64", "file_hook_detours.dll");
    resource_dir.create_resource_file("native/bin/win32-x86", "file_hook_detours.dll");

    let untrusted_dir = TempProcessHookDir::new("untrusted_explicit");
    let untrusted_injector =
        untrusted_dir.create_resource_file("manual-x64", "file_hook_injector.exe");

    let error = resolve_process_hook_paths(
        &untrusted_injector.to_string_lossy(),
        "",
        "",
        "",
        Some(resource_dir.path()),
    )
    .expect_err("arbitrary explicit injector paths must be rejected");

    assert!(
        error.contains("Rejected APIHook x64 injector file 'file_hook_injector.exe'"),
        "error should explain that arbitrary explicit paths are rejected: {error}"
    );
}
