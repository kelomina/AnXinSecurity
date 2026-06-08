use std::sync::{Arc, Mutex};

pub struct TestSharedState {
    pub value: u32,
}

impl TestSharedState {
    pub fn new() -> Self {
        Self { value: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shared_state_new_creates_with_zero() {
        let state = TestSharedState::new();
        assert_eq!(state.value, 0);
    }

    #[test]
    fn test_arc_mutex_state_access() {
        let state = Arc::new(Mutex::new(TestSharedState::new()));
        
        {
            let mut guard = state.lock().unwrap();
            guard.value = 42;
        }
        
        let guard = state.lock().unwrap();
        assert_eq!(guard.value, 42);
    }

    #[test]
    fn test_arc_mutex_allows_concurrent_access() {
        let state = Arc::new(Mutex::new(TestSharedState::new()));
        let mut handles = vec![];

        for i in 0..10 {
            let s = state.clone();
            let handle = std::thread::spawn(move || {
                let mut guard = s.lock().unwrap();
                guard.value = i;
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("thread should complete");
        }

        let guard = state.lock().unwrap();
        assert!(guard.value < 10);
    }

    #[test]
    fn test_option_none_handling() {
        let option: Option<u32> = None;
        assert!(option.is_none());
        
        let value = option.unwrap_or(100);
        assert_eq!(value, 100);
    }

    #[test]
    fn test_option_some_handling() {
        let option: Option<u32> = Some(50);
        assert!(option.is_some());
        
        let value = option.unwrap_or(100);
        assert_eq!(value, 50);
    }

    #[test]
    fn test_string_empty_check() {
        let empty = String::new();
        let not_empty = "test".to_string();
        
        assert!(empty.is_empty());
        assert!(!not_empty.is_empty());
    }

    #[test]
    fn test_path_normalization_logic() {
        fn normalize_path(path: &str) -> String {
            let mut normalized: String = path
                .chars()
                .map(|ch| {
                    if ch == '/' {
                        '\\'
                    } else {
                        ch.to_ascii_lowercase()
                    }
                })
                .collect();
            if normalized.starts_with("\\\\?\\") {
                normalized = normalized[4..].to_string();
            }
            if normalized.starts_with("\\??\\") {
                normalized = normalized[4..].to_string();
            }
            normalized
        }

        assert_eq!(normalize_path("C:/Windows/System32"), r"c:\windows\system32");
        assert_eq!(normalize_path(r"\\?\C:\Test"), r"c:\test");
        assert_eq!(normalize_path(r"\??\D:\App"), r"d:\app");
        assert_eq!(normalize_path(r"C:\Normal\Path"), r"c:\normal\path");
    }

    #[test]
    fn test_process_arch_enum() {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        enum ProcArch {
            Unknown,
            X86,
            X64,
        }

        assert_eq!(ProcArch::Unknown as u32, 0);
        assert_eq!(ProcArch::X86 as u32, 1);
        assert_eq!(ProcArch::X64 as u32, 2);
    }

    #[test]
    fn test_inject_task_struct() {
        #[derive(Debug)]
        struct InjectTask {
            pid: u32,
            arch: &'static str,
        }

        let task = InjectTask { pid: 1234, arch: "x64" };
        assert_eq!(task.pid, 1234);
        assert_eq!(task.arch, "x64");
    }

    #[test]
    fn test_interval_validation() {
        fn validate_interval(interval_ms: u32) -> u32 {
            std::cmp::max(interval_ms, 100)
        }

        assert_eq!(validate_interval(50), 100);
        assert_eq!(validate_interval(100), 100);
        assert_eq!(validate_interval(500), 500);
        assert_eq!(validate_interval(0), 100);
    }

    #[test]
    fn test_sign_cache_hashmap_operations() {
        use std::collections::HashMap;
        
        let mut cache: HashMap<String, bool> = HashMap::new();
        
        cache.insert(r"C:\Windows\notepad.exe".to_string(), true);
        cache.insert(r"C:\Test\unknown.exe".to_string(), false);
        
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.get(r"C:\Windows\notepad.exe"), Some(&true));
        assert_eq!(cache.get(r"C:\Test\unknown.exe"), Some(&false));
        assert_eq!(cache.get(r"C:\NonExistent\app.exe"), None);
        
        cache.remove(r"C:\Windows\notepad.exe");
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_pid_set_operations() {
        use std::collections::HashSet;
        
        let mut seen: HashSet<u32> = HashSet::new();
        
        assert!(seen.insert(100));
        assert!(!seen.insert(100));
        
        assert!(seen.contains(&100));
        assert!(!seen.contains(&200));
        
        seen.insert(200);
        seen.insert(300);
        assert_eq!(seen.len(), 3);
    }

    #[test]
    fn test_retain_logic() {
        use std::collections::HashSet;

        let current: Vec<u32> = vec![100, 200, 300];
        let mut seen: HashSet<u32> = HashSet::from([100, 200, 400]);
        
        seen.retain(|p| current.contains(p));
        
        assert!(seen.contains(&100));
        assert!(seen.contains(&200));
        assert!(!seen.contains(&400));
    }
}
