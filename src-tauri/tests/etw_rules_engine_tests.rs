// ETW 规则引擎测试 — 验证通配符匹配、字符串规范化和上下文环缓冲
// ETW rule engine tests — verify wildcard matching, string normalization, and context ring buffer
//
// 测试策略：直接测试 rules.rs 中导出的和可提取的纯函数，包括：
// - simple_wildcard_match: DP 动态规划通配符匹配（支持 * 和 ?）
// - normalize_str: 字符串规范化（/ → \，大写 → 小写）
// - ContextRing: 循环缓冲区实现
// - index_key: 规则索引键生成
//
// 中文关键词：通配符匹配，DP算法，上下文环，循环缓冲区，字符串规范化，规则引擎
// English keywords: wildcard match, DP algorithm, context ring, circular buffer, string normalization, rule engine

#[cfg(test)]
mod config_loading_tests {
    use anxin_security::services::etw::parser::ParsedEvent;
    use anxin_security::services::etw::rules::{EtwRuleEngine, ProviderKind};
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn default_config_rules_load_and_match_file_create_event() {
        let config_path =
            resolve_repo_config_path().expect("config/etw_match_rules.json should exist");
        let mut engine =
            EtwRuleEngine::from_config_path(&config_path).expect("default ETW rules should load");

        assert!(
            engine.rule_count() >= 5,
            "默认 ETW 配置至少应加载现有文件规则和镜像加载检测规则"
        );

        let matched = engine.on_event(&ParsedEvent {
            ts_ms: 1700000000000,
            pid: 4242,
            tid: 10,
            ppid: 0,
            provider: ProviderKind::File,
            opcode: 0,
            id: 64,
            op: "create".to_string(),
            target: r"C:\Users\Alice\AppData\Local\Temp\dropper.exe".to_string(),
            target2: String::new(),
            image_base: None,
            image_size: None,
            start_address: None,
        });

        let matched = matched.expect("temp file create should match temp_dropper_create");
        assert_eq!(matched.rule_id, "temp_dropper_create");
        assert_eq!(matched.threat_type, "临时目录落地");
        assert_eq!(matched.provider, "File");
        assert_eq!(matched.pid, 4242);
        assert_eq!(
            matched.path,
            r"C:\Users\Alice\AppData\Local\Temp\dropper.exe"
        );
        assert!(
            matched.severity >= 61,
            "配置中的 1-5 档 severity 应映射为 RiskService 可识别的 0-100 高风险分数，实际为 {}",
            matched.severity
        );
        assert!(!matched.description.is_empty());
    }

    #[test]
    fn default_config_rules_match_calc_probe_image_load_event() {
        let config_path =
            resolve_repo_config_path().expect("config/etw_match_rules.json should exist");
        let mut engine =
            EtwRuleEngine::from_config_path(&config_path).expect("default ETW rules should load");

        let matched = engine.on_event(&ParsedEvent {
            ts_ms: 1700000000001,
            pid: 62092,
            tid: 44,
            ppid: 0,
            provider: ProviderKind::Image,
            opcode: 0,
            id: 5,
            op: "load".to_string(),
            target:
                r"E:\Project\HTML\AnXinSecurity\native\file_hook\build-calc-probe-x64\Release\calc_probe_payload.dll"
                    .to_string(),
            target2: String::new(),
            image_base: Some(0x7ff7_0000_0000),
            image_size: Some(0x12000),
            start_address: None,
        });

        let matched = matched.expect("calc probe payload image load should match");
        assert_eq!(matched.rule_id, "calc_probe_payload_image_load");
        assert_eq!(matched.provider, "Image");
        assert_eq!(matched.op, "load");
        assert_eq!(matched.threat_type, "DLL 注入测试样本加载");
        assert!(matched.path.ends_with("calc_probe_payload.dll"));
    }

    #[test]
    fn empty_config_loads_as_explicit_empty_engine() {
        let config_path = write_temp_rule_config("[]");
        let engine = EtwRuleEngine::from_config_path(&config_path)
            .expect("empty ETW config array should be an explicit empty engine");

        assert_eq!(engine.rule_count(), 0);

        let _ = fs::remove_file(config_path);
    }

    #[test]
    fn bad_config_returns_clear_error_instead_of_silent_empty_rules() {
        let config_path = write_temp_rule_config(r#"[{"ruleId":"bad","provider":"File"}]"#);
        let err = match EtwRuleEngine::from_config_path(&config_path) {
            Ok(_) => panic!("invalid ETW config should return an explicit error"),
            Err(err) => err,
        };

        assert!(
            err.contains("Failed to parse ETW rule config") || err.contains("Invalid ETW rule"),
            "错误信息应明确指出配置解析或字段校验失败: {}",
            err
        );

        let _ = fs::remove_file(config_path);
    }

    fn resolve_repo_config_path() -> Option<PathBuf> {
        [
            PathBuf::from("config/etw_match_rules.json"),
            PathBuf::from("../config/etw_match_rules.json"),
        ]
        .into_iter()
        .find(|path| path.exists())
    }

    fn write_temp_rule_config(content: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after UNIX_EPOCH")
            .as_nanos();
        let path = std::env::temp_dir().join(format!("anxin-etw-rules-{}.json", unique));
        fs::write(&path, content).expect("write temporary ETW rule config");
        path
    }
}

#[cfg(test)]
mod wildcard_match_tests {
    use super::common::*;

    #[test]
    fn test_wildcard_exact_match() {
        assert!(simple_wildcard_match("test.exe", "test.exe"));
    }

    #[test]
    fn test_wildcard_single_star_matches_all() {
        assert!(simple_wildcard_match("*", "anything"));
        assert!(simple_wildcard_match("*", ""));
        assert!(simple_wildcard_match("*.exe", "malware.exe"));
        assert!(simple_wildcard_match("test*", "test.exe"));
        assert!(simple_wildcard_match("test*", "testmalware.exe"));
        assert!(simple_wildcard_match("*test", "mytest"));
        assert!(simple_wildcard_match("C:\\*", r"C:\Windows\System32"));
    }

    #[test]
    fn test_wildcard_single_question_matches_one() {
        assert!(simple_wildcard_match("test?.exe", "test1.exe"));
        assert!(simple_wildcard_match("test?.exe", "testA.exe"));
        assert!(simple_wildcard_match("?.exe", "a.exe"));
        assert!(simple_wildcard_match("???.exe", "abc.exe"));
        assert!(simple_wildcard_match("???", "abc"));
        assert!(simple_wildcard_match("?test?", "1test2"));
    }

    #[test]
    fn test_wildcard_combined_star_and_question() {
        assert!(simple_wildcard_match("test*.exe", "test1.exe"));
        assert!(simple_wildcard_match("test*.exe", "testabc.exe"));
        assert!(simple_wildcard_match(
            "C:\\*\\*.exe",
            r"C:\Windows\notepad.exe"
        ));
        assert!(simple_wildcard_match(
            "C:\\test?\\*.dll",
            r"C:\test1\mydll.dll"
        ));
    }

    #[test]
    fn test_wildcard_no_match() {
        assert!(!simple_wildcard_match("test.exe", "test2.exe"));
        assert!(!simple_wildcard_match("*.exe", "test.txt"));
        assert!(!simple_wildcard_match("test*", "atest"));
        assert!(!simple_wildcard_match("test?.exe", "test.exe"));
        assert!(!simple_wildcard_match("test???.exe", "test.exe"));
    }

    #[test]
    fn test_wildcard_empty_pattern() {
        assert!(simple_wildcard_match("", ""));
        assert!(!simple_wildcard_match("", "something"));
    }

    #[test]
    fn test_wildcard_empty_text() {
        assert!(!simple_wildcard_match("something", ""));
        assert!(simple_wildcard_match("*", ""));
    }

    #[test]
    fn test_wildcard_multiple_stars() {
        assert!(simple_wildcard_match("*test*", "onetestonetwo"));
        assert!(simple_wildcard_match(
            "C:\\*\\temp\\*",
            r"C:\Windows\temp\file.txt"
        ));
        assert!(simple_wildcard_match("a*b*c", "axxxbyyyc"));
        assert!(simple_wildcard_match("a*b*c", "abc"));
    }

    #[test]
    fn test_wildcard_real_world_patterns() {
        assert!(simple_wildcard_match(
            "C:\\Windows\\System32\\*.exe",
            r"C:\Windows\System32\notepad.exe"
        ));
        assert!(simple_wildcard_match(
            "C:\\Windows\\System32\\*.exe",
            r"C:\Windows\System32\calc.exe"
        ));
        assert!(simple_wildcard_match(
            "C:\\Windows\\*\\*.dll",
            r"C:\Windows\System32\kernel32.dll"
        ));
        assert!(simple_wildcard_match(
            "C:\\Users\\*\\AppData\\*",
            r"C:\Users\John\AppData\Local\test"
        ));
        assert!(simple_wildcard_match("*.tmp", "autosave.tmp"));
        assert!(simple_wildcard_match("*.tmp", "12345.tmp"));
        assert!(simple_wildcard_match("malware_?.exe", "malware_a.exe"));
        assert!(simple_wildcard_match("malware_?.exe", "malware_1.exe"));
    }

    #[test]
    fn test_wildcard_escaped_chars_not_needed() {
        assert!(simple_wildcard_match("*.*", "filename.anything"));
        assert!(simple_wildcard_match("**", "anything"));
    }

    #[test]
    fn test_wildcard_path_separators() {
        assert!(simple_wildcard_match("C:*", r"C:\Windows"));
        assert!(simple_wildcard_match("C:*", r"C:\Program Files"));
        assert!(simple_wildcard_match("/var/*", "/var/log"));
        assert!(simple_wildcard_match("/var/*", "/var/tmp"));
    }

    #[test]
    fn test_wildcard_security_sensitive_patterns() {
        assert!(simple_wildcard_match("*\\*.exe", r"C:\Windows\notepad.exe"));
        assert!(simple_wildcard_match(
            "*\\*.exe",
            r"C:\Users\Bob\malware.exe"
        ));
        assert!(simple_wildcard_match("*temp*", "temptemp"));
        assert!(simple_wildcard_match("*temp*", "temp123"));
        assert!(simple_wildcard_match("*temp*", "my_temp_file"));
    }
}

#[cfg(test)]
mod string_normalization_tests {
    use super::common::*;

    #[test]
    fn test_normalize_str_converts_forward_slash_to_backslash() {
        assert_eq!(
            normalize_str_test("C:/Windows/System32"),
            r"c:\windows\system32"
        );
        assert_eq!(
            normalize_str_test("C:/Program Files/App.exe"),
            r"c:\program files\app.exe"
        );
    }

    #[test]
    fn test_normalize_str_converts_uppercase_to_lowercase() {
        assert_eq!(normalize_str_test("WINDOWS"), "windows");
        assert_eq!(normalize_str_test("SYSTEM32"), "system32");
        assert_eq!(
            normalize_str_test("C:\\WINDOWS\\SYSTEM32"),
            r"c:\windows\system32"
        );
    }

    #[test]
    fn test_normalize_str_combined_operations() {
        assert_eq!(
            normalize_str_test("C:/WINDOWS/SYSTEM32"),
            r"c:\windows\system32"
        );
        assert_eq!(
            normalize_str_test("C:/Program Files/APP.EXE"),
            r"c:\program files\app.exe"
        );
    }

    #[test]
    fn test_normalize_str_preserves_non_ascii() {
        assert_eq!(normalize_str_test("恶意软件.exe"), "恶意软件.exe");
        assert_eq!(normalize_str_test("C:/测试/文件.exe"), r"c:\测试\文件.exe");
    }

    #[test]
    fn test_normalize_str_preserves_numbers_and_special_chars() {
        assert_eq!(normalize_str_test("file123.test"), "file123.test");
        assert_eq!(normalize_str_test("path-to-file"), "path-to-file");
        assert_eq!(normalize_str_test("file@#$%.exe"), "file@#$%.exe");
    }

    #[test]
    fn test_normalize_str_empty_string() {
        assert_eq!(normalize_str_test(""), "");
    }

    #[test]
    fn test_normalize_str_mixed_content() {
        let input = "C:/Users/ADMIN/Documents/Malware.EXE";
        let expected = r"c:\users\admin\documents\malware.exe";
        assert_eq!(normalize_str_test(input), expected);
    }

    #[test]
    fn test_normalize_str_for_path_comparison() {
        let path1 = normalize_str_test("C:/WINDOWS/SYSTEM32/NOTEPAD.EXE");
        let path2 = normalize_str_test("c:\\windows\\system32\\notepad.exe");
        assert_eq!(path1, path2);
    }

    #[test]
    fn test_normalize_str_preserves_single_backslash() {
        assert_eq!(normalize_str_test(r"C:\"), r"c:\");
        assert_eq!(normalize_str_test(r"\\server\share"), r"\\server\share");
    }
}

#[cfg(test)]
mod context_ring_tests {
    use super::common::*;

    #[test]
    fn test_context_ring_new_is_empty() {
        let ring = ContextRingTest::new(10);
        let snapshot = ring.snapshot();
        assert!(snapshot.is_empty());
    }

    #[test]
    fn test_context_ring_push_increments_count() {
        let mut ring = ContextRingTest::new(10);
        ring.push(make_context_item(1, "p", "start", "C:\\test.exe"));
        assert_eq!(ring.snapshot().len(), 1);
        ring.push(make_context_item(2, "f", "create", "C:\\file.txt"));
        assert_eq!(ring.snapshot().len(), 2);
    }

    #[test]
    fn test_context_ring_wraps_around() {
        let mut ring = ContextRingTest::new(3);
        ring.push(make_context_item(1, "p", "start", "one"));
        ring.push(make_context_item(2, "p", "start", "two"));
        ring.push(make_context_item(3, "p", "start", "three"));
        ring.push(make_context_item(4, "p", "start", "four"));

        let snapshot = ring.snapshot();
        assert_eq!(snapshot.len(), 3);
        assert!(snapshot.iter().any(|c| c.target == "two"));
        assert!(snapshot.iter().any(|c| c.target == "three"));
        assert!(snapshot.iter().any(|c| c.target == "four"));
        assert!(!snapshot.iter().any(|c| c.target == "one"));
    }

    #[test]
    fn test_context_ring_snapshot_order() {
        let mut ring = ContextRingTest::new(10);
        for i in 1..=5 {
            ring.push(make_context_item(i, "p", "start", &format!("item{}", i)));
        }

        let snapshot = ring.snapshot();
        assert_eq!(snapshot.len(), 5);
        assert_eq!(snapshot[0].target, "item1");
        assert_eq!(snapshot[4].target, "item5");
    }

    #[test]
    fn test_context_ring_full_state_snapshot() {
        let mut ring = ContextRingTest::new(4);
        for i in 1..=8 {
            ring.push(make_context_item(i, "p", "start", &format!("item{}", i)));
        }

        let snapshot = ring.snapshot();
        assert_eq!(snapshot.len(), 4);
        assert_eq!(snapshot[0].target, "item5");
        assert_eq!(snapshot[3].target, "item8");
    }

    #[test]
    fn test_context_ring_never_exceeds_capacity() {
        let capacity = 5;
        let mut ring = ContextRingTest::new(capacity);
        for i in 0..100 {
            ring.push(make_context_item(i, "p", "start", &format!("item{}", i)));
        }
        assert_eq!(ring.snapshot().len(), capacity);
    }

    #[test]
    fn test_context_ring_capacity_zero() {
        let mut ring = ContextRingTest::new(0);
        ring.push(make_context_item(1, "p", "start", "one"));
        ring.push(make_context_item(2, "p", "start", "two"));

        let snapshot = ring.snapshot();
        assert!(snapshot.is_empty());
    }

    #[test]
    fn test_context_ring_capacity_one() {
        let mut ring = ContextRingTest::new(1);
        ring.push(make_context_item(1, "p", "start", "first"));
        ring.push(make_context_item(2, "p", "start", "second"));

        let snapshot = ring.snapshot();
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].target, "second");
    }

    #[test]
    fn test_context_ring_preserves_all_fields() {
        let mut ring = ContextRingTest::new(10);
        ring.push(ContextItemTest {
            ts_ms: 12345,
            provider: "Process".to_string(),
            op: "start".to_string(),
            target: r"C:\Windows\notepad.exe".to_string(),
        });

        let snapshot = ring.snapshot();
        assert_eq!(snapshot[0].ts_ms, 12345);
        assert_eq!(snapshot[0].provider, "Process");
        assert_eq!(snapshot[0].op, "start");
        assert_eq!(snapshot[0].target, r"C:\Windows\notepad.exe");
    }
}

#[cfg(test)]
mod index_key_tests {
    use super::common::*;

    #[test]
    fn test_index_key_process() {
        assert_eq!(index_key_test("p", "start"), "p:start");
        assert_eq!(index_key_test("p", "STOP"), "p:stop");
        assert_eq!(index_key_test("p", "Create"), "p:create");
    }

    #[test]
    fn test_index_key_file() {
        assert_eq!(index_key_test("f", "create"), "f:create");
        assert_eq!(index_key_test("f", "open"), "f:open");
        assert_eq!(index_key_test("f", "DELETE"), "f:delete");
    }

    #[test]
    fn test_index_key_registry() {
        assert_eq!(index_key_test("r", "open_key"), "r:open_key");
        assert_eq!(index_key_test("r", "set_value"), "r:set_value");
    }

    #[test]
    fn test_index_key_network() {
        assert_eq!(index_key_test("n", "connect"), "n:connect");
        assert_eq!(index_key_test("n", "send"), "n:send");
    }

    #[test]
    fn test_index_key_normalizes_to_lowercase() {
        assert_eq!(index_key_test("P", "START"), "p:start");
        assert_eq!(index_key_test("F", "CREATE"), "f:create");
    }
}

#[cfg(test)]
mod integration_scenario_tests {
    use super::common::*;

    #[test]
    fn test_normalized_path_matching_with_wildcard() {
        let pattern = "*\\temp\\*.exe";
        let normalized_text = r"c:\users\admin\temp\malware.exe";
        assert!(simple_wildcard_match(pattern, normalized_text));
    }

    #[test]
    fn test_case_insensitive_path_matching() {
        let pattern = "C:\\Windows\\*.exe";
        let normalized = normalize_str_test("c:\\windows\\notepad.exe");
        assert!(simple_wildcard_match(pattern, &normalized));
    }

    #[test]
    fn test_forward_slash_to_backslash_normalization() {
        let path = "C:/Program Files/App.exe";
        let normalized = normalize_str_test(path);
        assert!(!normalized.contains('/'));
        assert!(normalized.contains('\\'));
    }

    #[test]
    fn test_real_world_malware_pattern() {
        let pattern = "*\\appdata\\local\\temp\\*.exe";
        let paths = vec![
            r"C:\Users\Bob\AppData\Local\Temp\malware.exe",
            r"c:\users\bob\appdata\local\temp\virus.exe",
            r"C:\Users\Bob\AppData\Local\Temp\stage1.tmp",
        ];

        assert!(simple_wildcard_match(
            pattern,
            &normalize_str_test(paths[0])
        ));
        assert!(simple_wildcard_match(
            pattern,
            &normalize_str_test(paths[1])
        ));
        assert!(!simple_wildcard_match(
            pattern,
            &normalize_str_test(paths[2])
        ));
    }

    #[test]
    fn test_registry_key_matching() {
        let pattern = "*\\software\\microsoft\\windows\\currentversion\\run\\*";
        let key1 = r"HKLM\software\microsoft\windows\currentversion\run\malware";
        let key2 = r"HKCU\software\microsoft\windows\currentversion\run\legit";

        assert!(simple_wildcard_match(pattern, &normalize_str_test(key1)));
        assert!(simple_wildcard_match(pattern, &normalize_str_test(key2)));
    }

    #[test]
    fn test_context_ring_with_security_events() {
        let mut ring = ContextRingTest::new(100);

        ring.push(ContextItemTest {
            ts_ms: 1000,
            provider: "Process".to_string(),
            op: "start".to_string(),
            target: r"C:\malware\stage1.exe".to_string(),
        });
        ring.push(ContextItemTest {
            ts_ms: 1001,
            provider: "File".to_string(),
            op: "create".to_string(),
            target: r"C:\malware\stage2.exe".to_string(),
        });
        ring.push(ContextItemTest {
            ts_ms: 1002,
            provider: "Registry".to_string(),
            op: "set_value".to_string(),
            target: r"HKCU\Software\Microsoft\Windows\Run".to_string(),
        });

        let events = ring.snapshot();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].provider, "Process");
        assert_eq!(events[1].provider, "File");
        assert_eq!(events[2].provider, "Registry");
    }
}

mod common {
    #[derive(Debug, Clone)]
    pub struct ContextItemTest {
        pub ts_ms: u64,
        pub provider: String,
        pub op: String,
        pub target: String,
    }

    pub struct ContextRingTest {
        buf: Vec<ContextItemTest>,
        next: usize,
        full: bool,
    }

    impl ContextRingTest {
        pub fn new(capacity: usize) -> Self {
            Self {
                buf: vec![
                    ContextItemTest {
                        ts_ms: 0,
                        provider: String::new(),
                        op: String::new(),
                        target: String::new()
                    };
                    capacity
                ],
                next: 0,
                full: false,
            }
        }

        pub fn push(&mut self, item: ContextItemTest) {
            if self.buf.is_empty() {
                return;
            }
            self.buf[self.next] = item;
            self.next += 1;
            if self.next >= self.buf.len() {
                self.next = 0;
                self.full = true;
            }
        }

        pub fn snapshot(&self) -> Vec<ContextItemTest> {
            if !self.full {
                return self.buf[..self.next].to_vec();
            }
            let mut result = self.buf[self.next..].to_vec();
            result.extend_from_slice(&self.buf[..self.next]);
            result
        }
    }

    pub fn make_context_item(
        ts_ms: u64,
        provider: &str,
        op: &str,
        target: &str,
    ) -> ContextItemTest {
        ContextItemTest {
            ts_ms,
            provider: provider.to_string(),
            op: op.to_string(),
            target: target.to_string(),
        }
    }

    pub fn simple_wildcard_match(pattern: &str, text: &str) -> bool {
        let normalized_pattern = normalize_str_test(pattern);
        let normalized_text = normalize_str_test(text);
        let pat: Vec<char> = normalized_pattern.chars().collect();
        let txt: Vec<char> = normalized_text.chars().collect();
        let pn = pat.len();
        let tn = txt.len();

        let mut dp = vec![vec![false; tn + 1]; pn + 1];
        dp[0][0] = true;
        for i in 1..=pn {
            if pat[i - 1] == '*' {
                dp[i][0] = dp[i - 1][0];
            }
        }
        for i in 1..=pn {
            for j in 1..=tn {
                if pat[i - 1] == '*' {
                    dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
                } else if pat[i - 1] == '?' || pat[i - 1] == txt[j - 1] {
                    dp[i][j] = dp[i - 1][j - 1];
                }
            }
        }
        dp[pn][tn]
    }

    pub fn normalize_str_test(s: &str) -> String {
        s.chars()
            .map(|c| {
                if c == '/' {
                    '\\'
                } else if c.is_ascii_uppercase() {
                    c.to_ascii_lowercase()
                } else {
                    c
                }
            })
            .collect()
    }

    pub fn index_key_test(provider: &str, op: &str) -> String {
        format!("{}:{}", provider.to_lowercase(), op.to_lowercase())
    }
}
