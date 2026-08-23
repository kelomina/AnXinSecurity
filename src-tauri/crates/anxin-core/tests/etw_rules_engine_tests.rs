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
            engine.rule_count() >= 3,
            "默认 ETW 配置至少应加载注册表持久化、临时目录落地和临时模块加载三条规则"
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
            raw_user_data_len: 0,
            raw_user_data_preview: String::new(),
        });

        let matched = matched.expect("temp file create should match temp_dropper_create");
        assert_eq!(matched.rule_id, "temp_dropper_create");
        assert_eq!(matched.threat_type, "临时目录可执行文件落地");
        assert_eq!(matched.provider, "File");
        assert_eq!(matched.pid, 4242);
        assert_eq!(
            matched.path,
            r"C:\Users\Alice\AppData\Local\Temp\dropper.exe"
        );
        // 该规则已从 severity 4 降到 2：临时目录落地在正常软件里极常见，
        // 必须落在 RiskService 的 medium 区间（<=60）以免自动挂起安装器与更新程序。
        //  Lowered from severity 4 to 2: dropping files into temp is extremely common in
        //  legitimate software, so it must stay in RiskService's medium band (<=60) and
        //  never auto-suspend installers or updaters.
        assert_eq!(
            matched.severity, 40,
            "severity 2 应映射为 40 分，落在 medium 区间，实际为 {}",
            matched.severity
        );
        assert_eq!(
            matched.recommend_action, "alert",
            "该规则只应告警，不得建议阻断"
        );
        assert!(!matched.description.is_empty());
    }

    /// 收紧后的注册表规则必须仍能命中真实的 Run 键写入。
    /// target 取 parser 归一化后的形态（值名已被切到 target2），
    /// 这条用例同时守住 parser 的 off-by-one 修复：若首字符再被吞掉，
    /// `*\currentversion\run` 仍能命中，但 `HKLM\SOFTWARE\` 形态会退化，
    /// 因此这里显式断言完整键名。
    /// The tightened registry rule must still catch a real Run-key write. The target is the
    /// parser-normalized key (the value name went to target2). Also guards the parser
    /// off-by-one fix by asserting the full key name.
    #[test]
    fn tightened_registry_rule_still_matches_run_key_write() {
        let config_path =
            resolve_repo_config_path().expect("config/etw_match_rules.json should exist");
        let mut engine =
            EtwRuleEngine::from_config_path(&config_path).expect("default ETW rules should load");

        let key = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
        let matched = engine.on_event(&ParsedEvent {
            ts_ms: 1700000000002,
            pid: 7788,
            tid: 12,
            ppid: 0,
            provider: ProviderKind::Registry,
            opcode: 0,
            id: 22,
            op: "set_value".to_string(),
            target: key.to_string(),
            target2: "Updater".to_string(),
            image_base: None,
            image_size: None,
            start_address: None,
            raw_user_data_len: 0,
            raw_user_data_preview: String::new(),
        });

        let matched = matched.expect("Run key write should still match registry_runkey_setvalue");
        assert_eq!(matched.rule_id, "registry_runkey_setvalue");
        assert_eq!(
            matched.severity, 60,
            "severity 3 应映射为 60 分（medium 上限）"
        );
        assert_eq!(matched.recommend_action, "alert");
    }

    /// 收紧后的注册表规则不得再命中任意 HKLM 写入。
    /// 修复前 targetContains 里的裸 `hklm\` 因组内 OR 语义等价于匹配全部 HKLM SetValue，
    /// Windows Update、驱动安装、MSI 安装会被整片误报并挂起。
    /// The tightened rule must no longer match arbitrary HKLM writes. The bare `hklm\`
    /// entry previously matched every HKLM SetValue thanks to the OR semantics within
    /// targetContains, sweeping up Windows Update, driver installs and MSI installers.
    #[test]
    fn tightened_registry_rule_ignores_unrelated_hklm_write() {
        let config_path =
            resolve_repo_config_path().expect("config/etw_match_rules.json should exist");
        let mut engine =
            EtwRuleEngine::from_config_path(&config_path).expect("default ETW rules should load");

        for key in [
            r"HKLM\SYSTEM\CurrentControlSet\Services\WinDefend",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData",
            r"HKLM\SOFTWARE\Google\Update",
        ] {
            let matched = engine.on_event(&ParsedEvent {
                ts_ms: 1700000000003,
                pid: 7789,
                tid: 13,
                ppid: 0,
                provider: ProviderKind::Registry,
                opcode: 0,
                id: 22,
                op: "set_value".to_string(),
                target: key.to_string(),
                target2: "Value".to_string(),
                image_base: None,
                image_size: None,
                start_address: None,
                raw_user_data_len: 0,
                raw_user_data_preview: String::new(),
            });
            assert!(
                matched.is_none(),
                "普通 HKLM 写入 {} 不应命中启动项持久化规则",
                key
            );
        }
    }

    /// 收紧后的临时目录规则只关心可执行/脚本落地，不再命中任意临时文件。
    /// The tightened temp rule only covers executable/script drops, not arbitrary temp files.
    #[test]
    fn tightened_temp_rule_ignores_non_executable_drops() {
        let config_path =
            resolve_repo_config_path().expect("config/etw_match_rules.json should exist");
        let mut engine =
            EtwRuleEngine::from_config_path(&config_path).expect("default ETW rules should load");

        for path in [
            r"C:\Users\Alice\AppData\Local\Temp\update.log",
            r"C:\Windows\Temp\msi1a2b3.tmp",
            r"C:\Users\Alice\AppData\Local\Temp\chrome_installer.dat",
        ] {
            let matched = engine.on_event(&ParsedEvent {
                ts_ms: 1700000000004,
                pid: 7790,
                tid: 14,
                ppid: 0,
                provider: ProviderKind::File,
                opcode: 0,
                id: 64,
                op: "create".to_string(),
                target: path.to_string(),
                target2: String::new(),
                image_base: None,
                image_size: None,
                start_address: None,
                raw_user_data_len: 0,
                raw_user_data_preview: String::new(),
            });
            assert!(
                matched.is_none(),
                "临时目录的非可执行文件 {} 不应命中落地规则",
                path
            );
        }
    }

    /// 生产配置不得包含测试规则。
    /// calc_probe_payload_image_load 与 test_rule_trigger 的文件名都是公开可知的，
    /// 留在生产配置里等于给任意本地程序留下可控的检测/冻结触发器（buglist VUL-015）。
    /// The production config must not ship test rules: both use publicly known file names,
    /// which would hand any local program a controllable detection/freeze trigger.
    #[test]
    fn production_config_contains_no_test_rules() {
        let config_path =
            resolve_repo_config_path().expect("config/etw_match_rules.json should exist");
        let raw = fs::read_to_string(&config_path).expect("read production ETW rule config");

        for forbidden in [
            "calc_probe_payload",
            "test_rule_trigger",
            "anxin_rule_test_trigger",
        ] {
            assert!(
                !raw.contains(forbidden),
                "生产配置 {:?} 不得包含测试规则 {}",
                config_path,
                forbidden
            );
        }
    }

    /// 生产规则不得建议阻断——自动挂起目前只应由链路级强证据触发，
    /// 单条 ETW 规则命中不构成强证据。
    /// No production rule may recommend blocking: a single ETW rule hit is not the
    /// strong evidence that an automatic suspend requires.
    #[test]
    fn production_rules_do_not_recommend_blocking() {
        let config_path =
            resolve_repo_config_path().expect("config/etw_match_rules.json should exist");
        let raw = fs::read_to_string(&config_path).expect("read production ETW rule config");
        let rules: serde_json::Value =
            serde_json::from_str(&raw).expect("production ETW rule config should be valid JSON");

        for rule in rules.as_array().expect("config should be a JSON array") {
            let rule_id = rule["ruleId"].as_str().unwrap_or("<unknown>");
            assert_ne!(
                rule["recommendAction"].as_str(),
                Some("block"),
                "规则 {} 不得在生产配置中建议阻断",
                rule_id
            );
            let severity = rule["severity"].as_u64().unwrap_or(0);
            assert!(
                severity <= 3,
                "规则 {} 的 severity 为 {}，×20 后会落入 high 区间并触发自动挂起",
                rule_id,
                severity
            );
        }
    }

    #[test]
    fn default_config_rules_match_calc_probe_image_load_event() {
        // 该探针规则已迁出生产配置，只在测试配置里保留
        //  This probe rule moved out of the production config and lives in the test config
        let config_path =
            resolve_test_config_path().expect("config/etw_match_rules.test.json should exist");
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
            raw_user_data_len: 0,
            raw_user_data_preview: String::new(),
        });

        let matched = matched.expect("calc probe payload image load should match");
        assert_eq!(matched.rule_id, "calc_probe_payload_image_load");
        assert_eq!(matched.provider, "Image");
        assert_eq!(matched.op, "load");
        assert_eq!(matched.threat_type, "DLL 注入测试样本加载");
        assert!(matched.path.ends_with("calc_probe_payload.dll"));
    }

    /// 构造一条带时间窗口的规则：临时目录落 exe，且同一 PID 在 5 秒内启动过进程。
    ///  A windowed rule: an exe dropped into temp by a PID that started within the last 5s.
    fn window_rule_config() -> &'static str {
        r#"[{
            "ruleId": "temp_drop_after_process_start",
            "provider": "File",
            "op": "Create",
            "severity": 3,
            "threatType": "启动后立即落地",
            "recommendAction": "alert",
            "targetPatterns": ["*\\temp\\*.exe"],
            "windowMs": 5000,
            "requiredOps": [{ "provider": "Process", "op": "start" }]
        }]"#
    }

    fn file_create_event(pid: u32, ts_ms: u64, target: &str) -> ParsedEvent {
        ParsedEvent {
            ts_ms,
            pid,
            tid: 1,
            ppid: 0,
            provider: ProviderKind::File,
            opcode: 0,
            id: 64,
            op: "create".to_string(),
            target: target.to_string(),
            target2: String::new(),
            image_base: None,
            image_size: None,
            start_address: None,
            raw_user_data_len: 0,
            raw_user_data_preview: String::new(),
        }
    }

    fn process_start_event(pid: u32, ts_ms: u64) -> ParsedEvent {
        ParsedEvent {
            ts_ms,
            pid,
            tid: 1,
            ppid: 0,
            provider: ProviderKind::Process,
            opcode: 1,
            id: 1,
            op: "start".to_string(),
            target: r"C:\Tools\loader.exe".to_string(),
            target2: String::new(),
            image_base: None,
            image_size: None,
            start_address: None,
            raw_user_data_len: 0,
            raw_user_data_preview: String::new(),
        }
    }

    /// 窗口内出现过先决事件时，时间窗口规则必须命中。
    /// 修复前 seen 集合只写常量 "_event"，而判定查 "{provider}:{op}"，任何 requiredOps
    /// 非空的规则恒不命中——这是一个被文档宣传但实际失效的死特性。
    /// A windowed rule must fire when the prerequisite occurred inside the window. Before the
    /// fix the seen set only received the constant "_event" while the check looked for
    /// "{provider}:{op}" keys, so every rule with requiredOps was dead.
    #[test]
    fn window_rule_matches_when_required_op_occurred_in_window() {
        let config_path = write_temp_rule_config(window_rule_config());
        let mut engine =
            EtwRuleEngine::from_config_path(&config_path).expect("window rule config should load");

        // 先决事件：同一 PID 启动 / prerequisite: same PID started
        assert!(engine.on_event(&process_start_event(4321, 1_000)).is_none());

        let matched = engine.on_event(&file_create_event(
            4321,
            3_000,
            r"C:\Users\Alice\AppData\Local\Temp\payload.exe",
        ));

        let matched = matched.expect("窗口内已发生先决事件，规则应命中");
        assert_eq!(matched.rule_id, "temp_drop_after_process_start");
        assert!(
            matched
                .evidence
                .iter()
                .any(|item| item.contains("window match")),
            "命中证据应包含窗口匹配说明，实际为 {:?}",
            matched.evidence
        );

        let _ = fs::remove_file(config_path);
    }

    /// 没有先决事件时不得命中，否则 requiredOps 形同虚设。
    ///  Without the prerequisite the rule must not fire, or requiredOps means nothing.
    #[test]
    fn window_rule_does_not_match_without_required_op() {
        let config_path = write_temp_rule_config(window_rule_config());
        let mut engine =
            EtwRuleEngine::from_config_path(&config_path).expect("window rule config should load");

        let matched = engine.on_event(&file_create_event(
            5555,
            3_000,
            r"C:\Users\Alice\AppData\Local\Temp\payload.exe",
        ));

        assert!(matched.is_none(), "没有先决事件时不应命中时间窗口规则");

        let _ = fs::remove_file(config_path);
    }

    /// 先决事件落在窗口之外时不得命中。
    ///  A prerequisite outside the window must not satisfy the rule.
    #[test]
    fn window_rule_does_not_match_when_required_op_is_too_old() {
        let config_path = write_temp_rule_config(window_rule_config());
        let mut engine =
            EtwRuleEngine::from_config_path(&config_path).expect("window rule config should load");

        assert!(engine.on_event(&process_start_event(6666, 1_000)).is_none());

        // windowMs=5000，先决事件距今 20 秒，已超出窗口
        //  windowMs=5000 and the prerequisite is 20s old, well outside the window
        let matched = engine.on_event(&file_create_event(
            6666,
            21_000,
            r"C:\Users\Alice\AppData\Local\Temp\payload.exe",
        ));

        assert!(matched.is_none(), "先决事件超出时间窗口时不应命中");

        let _ = fs::remove_file(config_path);
    }

    /// 先决事件必须属于同一个 PID，不能被其它进程的事件满足。
    ///  The prerequisite must belong to the same PID; another process must not satisfy it.
    #[test]
    fn window_rule_does_not_match_across_different_pids() {
        let config_path = write_temp_rule_config(window_rule_config());
        let mut engine =
            EtwRuleEngine::from_config_path(&config_path).expect("window rule config should load");

        assert!(engine.on_event(&process_start_event(7777, 1_000)).is_none());

        let matched = engine.on_event(&file_create_event(
            8888,
            3_000,
            r"C:\Users\Alice\AppData\Local\Temp\payload.exe",
        ));

        assert!(
            matched.is_none(),
            "其它 PID 的先决事件不应满足本 PID 的规则"
        );

        let _ = fs::remove_file(config_path);
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
            PathBuf::from("../../../config/etw_match_rules.json"),
            PathBuf::from("config/etw_match_rules.json"),
            PathBuf::from("../config/etw_match_rules.json"),
        ]
        .into_iter()
        .find(|path| path.exists())
    }

    /// 测试专用规则配置。生产配置不加载它，因此不会带来误报与冻结风险。
    ///  Test-only rule config. The production build never loads it, so it carries no
    ///  false-positive or process-freeze risk.
    fn resolve_test_config_path() -> Option<PathBuf> {
        [
            PathBuf::from("../../../config/etw_match_rules.test.json"),
            PathBuf::from("config/etw_match_rules.test.json"),
            PathBuf::from("../config/etw_match_rules.test.json"),
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
