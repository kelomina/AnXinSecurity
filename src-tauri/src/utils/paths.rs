// 路径处理工具
use std::path::PathBuf;

pub fn normalize_path(path: &str) -> String {
    let path = PathBuf::from(path);
    path.to_string_lossy().to_string()
}

pub fn resolve_relative_path(base: &str, relative: &str) -> String {
    let base_path = PathBuf::from(base);
    let full_path = base_path.join(relative);
    full_path.to_string_lossy().to_string()
}

pub fn get_file_extension(path: &str) -> Option<String> {
    let path = PathBuf::from(path);
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_lowercase())
}
