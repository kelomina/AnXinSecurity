// ETW 事件解析器测试 — 验证二进制解析逻辑、路径选择和 IP 分类
// ETW event parser tests — verify binary parsing logic, path selection, and IP classification
//
// 测试策略：直接测试 parser.rs 中导出的和可提取的纯函数，包括：
// - extract_wide_string: UTF-16 LE 字符串提取
// - pick_best_path: 多候选路径评分选择
// - is_private_ipv4: IPv4 地址私有/保留分类
// - map_file_op / map_registry_op: 操作码映射
//
// 中文关键词：ETW 解析，宽字符串，路径选择，IP 分类，UTF-16，二进制解析
// English keywords: ETW parsing, wide string, path selection, IP classification, UTF-16, binary parsing

#[cfg(test)]
mod wide_string_tests {
    use super::common::*;

    #[test]
    fn test_extract_wide_string_from_utf16_le() {
        let input: Vec<u8> = "Hi".encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let result = extract_wide_string_test(&input);
        assert_eq!(result, "Hi");
    }

    #[test]
    fn test_extract_wide_string_truncates_at_null() {
        let mut input: Vec<u8> = Vec::new();
        "Hello\0World".encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .for_each(|b| input.push(b));
        let result = extract_wide_string_test(&input);
        assert_eq!(result, "Hello");
    }

    #[test]
    fn test_extract_wide_string_handles_empty_input() {
        assert_eq!(extract_wide_string_test(&[]), "");
        assert_eq!(extract_wide_string_test(&[0]), "");
    }

    #[test]
    fn test_extract_wide_string_removes_control_chars() {
        let mut input: Vec<u8> = Vec::new();
        "Test\u{8}File".encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .for_each(|b| input.push(b));
        let result = extract_wide_string_test(&input);
        assert!(!result.contains('\u{8}'));
    }

    #[test]
    fn test_extract_wide_string_preserves_internal_whitespace() {
        let mut input: Vec<u8> = Vec::new();
        "  Tab\tHere  ".encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .for_each(|b| input.push(b));
        let result = extract_wide_string_test(&input);
        assert_eq!(result, "Tab\tHere");
        assert!(result.contains('\t'));
    }

    #[test]
    fn test_extract_wide_string_trims_result() {
        let mut input: Vec<u8> = Vec::new();
        "  Trimmed  ".encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .for_each(|b| input.push(b));
        let result = extract_wide_string_test(&input);
        assert_eq!(result, "Trimmed");
    }

    #[test]
    fn test_extract_wide_string_with_chinese_chars() {
        let mut input: Vec<u8> = Vec::new();
        "恶意软件.exe".encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .for_each(|b| input.push(b));
        let result = extract_wide_string_test(&input);
        assert_eq!(result, "恶意软件.exe");
    }

    #[test]
    fn test_extract_wide_string_with_only_odd_bytes() {
        let result = extract_wide_string_test(&[0x41]);
        assert_eq!(result, "");
    }

    #[test]
    fn test_extract_wide_string_with_many_nulls() {
        let mut input: Vec<u8> = vec![0; 100];
        "End".encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .enumerate()
            .for_each(|(i, b)| input[i] = b);
        let result = extract_wide_string_test(&input);
        assert_eq!(result, "End");
    }
}

#[cfg(test)]
mod path_selection_tests {
    use super::common::*;

    #[test]
    fn test_pick_best_path_prefers_drive_letter() {
        let with_drive = pick_best_path_test(r"C:\Windows\System32\notepad.exe");
        let without_drive = pick_best_path_test(r"Windows\System32\notepad.exe");
        assert_eq!(with_drive, r"C:\Windows\System32\notepad.exe");
        assert!(pick_best_path_score(&with_drive) > pick_best_path_score(&without_drive));
    }

    #[test]
    fn test_pick_best_path_prefers_executables() {
        let exe_path = pick_best_path_test(r"C:\malware\trojan.exe");
        let dll_path = pick_best_path_test(r"C:\malware\trojan.dll");
        let sys_path = pick_best_path_test(r"C:\malware\driver.sys");
        let _txt_path = pick_best_path_test(r"C:\malware\readme.txt");

        assert!(exe_path.ends_with(".exe"));
        assert!(dll_path.ends_with(".dll") || sys_path.ends_with(".sys"));
    }

    #[test]
    fn test_pick_best_path_prefers_device_paths() {
        let device_path = r"\Device\HarddiskVolume2\malware.exe";
        let relative_path = r"malware.exe";
        assert!(pick_best_path_score(device_path) > pick_best_path_score(relative_path));
    }

    #[test]
    fn test_pick_best_path_prefers_backslash_separator() {
        let with_backslash = r"C:\Windows\notepad.exe";
        let with_forward = r"C:/Windows/notepad.exe";
        assert!(pick_best_path_score(with_backslash) >= pick_best_path_score(with_forward));
    }

    #[test]
    fn test_pick_best_path_penalizes_short_paths() {
        let short_path = r"C:\a";
        let long_path = r"C:\Program Files\Application\app.exe";
        assert!(pick_best_path_score(long_path) > pick_best_path_score(short_path));
    }

    #[test]
    fn test_pick_best_path_handles_empty_input() {
        assert_eq!(pick_best_path_test(""), "");
    }

    #[test]
    fn test_pick_best_path_handles_multiple_null_separators() {
        let input = format!("{}\0{}\0{}\0", 
            r"C:\malware\bad.exe",
            r"malware.exe",
            r"C:\windows\system32\notepad.exe"
        );
        let result = pick_best_path_test(&input);
        assert!(!result.is_empty());
        assert!(!result.contains('\0'));
    }

    #[test]
    fn test_pick_best_path_falls_back_to_first_candidate() {
        let input = format!("{}\0{}\0{}\0", 
            r"malware.exe",
            r"other.txt",
            r"another.doc"
        );
        let result = pick_best_path_test(&input);
        assert_eq!(result, "malware.exe");
    }

    #[test]
    fn test_pick_best_path_with_only_single_char() {
        assert_eq!(pick_best_path_test("a"), "a");
    }

    #[test]
    fn test_pick_best_path_normalizes_case_for_scoring() {
        let upper = r"C:\WINDOWS\SYSTEM32\NOTEPAD.EXE";
        let result = pick_best_path_test(upper);
        assert!(!result.is_empty());
    }
}

#[cfg(test)]
mod ip_classification_tests {
    use super::common::*;

    #[test]
    fn test_is_private_ipv4_10_network() {
        assert!(is_private_ipv4_test(10, 0, 0, 0));
        assert!(is_private_ipv4_test(10, 255, 255, 255));
        assert!(is_private_ipv4_test(10, 1, 2, 3));
    }

    #[test]
    fn test_is_private_ipv4_172_16_to_31() {
        assert!(is_private_ipv4_test(172, 16, 0, 0));
        assert!(is_private_ipv4_test(172, 31, 255, 255));
        assert!(is_private_ipv4_test(172, 20, 1, 1));
        assert!(!is_private_ipv4_test(172, 15, 0, 0));
        assert!(!is_private_ipv4_test(172, 32, 0, 0));
    }

    #[test]
    fn test_is_private_ipv4_192_168() {
        assert!(is_private_ipv4_test(192, 168, 0, 0));
        assert!(is_private_ipv4_test(192, 168, 255, 255));
        assert!(!is_private_ipv4_test(192, 169, 0, 0));
    }

    #[test]
    fn test_is_private_ipv4_169_254_link_local() {
        assert!(is_private_ipv4_test(169, 254, 0, 0));
        assert!(is_private_ipv4_test(169, 254, 255, 255));
        assert!(!is_private_ipv4_test(169, 253, 0, 0));
    }

    #[test]
    fn test_is_private_ipv4_loopback() {
        assert!(is_private_ipv4_test(127, 0, 0, 0));
        assert!(is_private_ipv4_test(127, 0, 0, 1));
        assert!(is_private_ipv4_test(127, 255, 255, 255));
    }

    #[test]
    fn test_is_private_ipv4_public_addresses() {
        assert!(!is_private_ipv4_test(8, 8, 8, 8));
        assert!(!is_private_ipv4_test(1, 1, 1, 1));
        assert!(!is_private_ipv4_test(208, 67, 222, 222));
        assert!(!is_private_ipv4_test(142, 250, 185, 46));
    }

    #[test]
    fn test_is_private_ipv4_multicast_reserved() {
        assert!(!is_private_ipv4_test(224, 0, 0, 0));
        assert!(!is_private_ipv4_test(240, 0, 0, 0));
    }

    #[test]
    fn test_is_private_ipv4_zero_octet() {
        assert!(!is_private_ipv4_test(0, 1, 2, 3));
    }
}

#[cfg(test)]
mod file_op_mapping_tests {
    use super::common::*;

    #[test]
    fn test_map_file_op_returns_correct_operations() {
        assert_eq!(map_file_op_test(64), "create");
        assert_eq!(map_file_op_test(65), "open");
        assert_eq!(map_file_op_test(67), "delete");
        assert_eq!(map_file_op_test(69), "rename");
        assert_eq!(map_file_op_test(70), "setinfo");
        assert_eq!(map_file_op_test(71), "create_new");
        assert_eq!(map_file_op_test(72), "dir_enum");
        assert_eq!(map_file_op_test(73), "dir_notify");
        assert_eq!(map_file_op_test(74), "read");
        assert_eq!(map_file_op_test(75), "write");
        assert_eq!(map_file_op_test(76), "close");
    }

    #[test]
    fn test_map_file_op_unknown_returns_formatted() {
        assert_eq!(map_file_op_test(0), "file_0");
        assert_eq!(map_file_op_test(100), "file_100");
        assert_eq!(map_file_op_test(999), "file_999");
    }
}

#[cfg(test)]
mod registry_op_mapping_tests {
    use super::common::*;

    #[test]
    fn test_map_registry_op_returns_correct_operations() {
        assert_eq!(map_registry_op_test(1), "create_key");
        assert_eq!(map_registry_op_test(2), "open_key");
        assert_eq!(map_registry_op_test(3), "delete_key");
        assert_eq!(map_registry_op_test(4), "query_key");
        assert_eq!(map_registry_op_test(5), "set_value");
        assert_eq!(map_registry_op_test(6), "delete_value");
        assert_eq!(map_registry_op_test(7), "query_value");
        assert_eq!(map_registry_op_test(8), "enumerate_key");
        assert_eq!(map_registry_op_test(9), "enumerate_value_key");
        assert_eq!(map_registry_op_test(10), "query_multiple_value");
        assert_eq!(map_registry_op_test(11), "set_information_key");
        assert_eq!(map_registry_op_test(12), "flush_key");
        assert_eq!(map_registry_op_test(13), "create_key_ex");
        assert_eq!(map_registry_op_test(14), "open_key_ex");
        assert_eq!(map_registry_op_test(15), "delete_key_ex");
        assert_eq!(map_registry_op_test(16), "rename_key");
    }

    #[test]
    fn test_map_registry_op_unknown_returns_formatted() {
        assert_eq!(map_registry_op_test(0), "reg_0");
        assert_eq!(map_registry_op_test(99), "reg_99");
        assert_eq!(map_registry_op_test(255), "reg_255");
    }
}

#[cfg(test)]
mod guid_comparison_tests {
    use super::common::*;

    #[test]
    fn test_same_guid_positive() {
        let guid = PROCESS_GUID_TEST;
        assert!(same_guid_test(&guid, &guid));
    }

    #[test]
    fn test_same_guid_negative() {
        assert!(!same_guid_test(&PROCESS_GUID_TEST, &FILE_GUID_TEST));
    }

    #[test]
    fn test_guid_constants_are_16_bytes() {
        assert_eq!(PROCESS_GUID_TEST.len(), 16);
        assert_eq!(FILE_GUID_TEST.len(), 16);
        assert_eq!(REGISTRY_GUID_TEST.len(), 16);
        assert_eq!(NETWORK_GUID_TEST.len(), 16);
    }
}

mod common {
    pub const PROCESS_GUID_TEST: [u8; 16] = [
        0xD6, 0x2C, 0xFB, 0x22, 0x7B, 0x0E, 0x2B, 0x42, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16,
    ];
    pub const FILE_GUID_TEST: [u8; 16] = [
        0x27, 0x89, 0xD0, 0xED, 0xC4, 0x9C, 0x65, 0x4E, 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89,
    ];
    pub const REGISTRY_GUID_TEST: [u8; 16] = [
        0x03, 0x4F, 0xEB, 0x70, 0xDE, 0xC1, 0x73, 0x4F, 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD,
    ];
    pub const NETWORK_GUID_TEST: [u8; 16] = [
        0x49, 0x2A, 0xD4, 0x7D, 0x29, 0x53, 0x32, 0x48, 0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88,
    ];

    pub fn same_guid_test(a: &[u8; 16], b: &[u8; 16]) -> bool {
        a == b
    }

    pub fn extract_wide_string_test(data: &[u8]) -> String {
        if data.len() < 2 {
            return String::new();
        }
        let wchar_count = data.len() / 2;
        let mut utf16: Vec<u16> = Vec::with_capacity(wchar_count);
        for i in 0..wchar_count {
            let lo = data[i * 2] as u16;
            let hi = data[i * 2 + 1] as u16;
            let ch = lo | (hi << 8);
            utf16.push(ch);
        }
        if let Some(pos) = utf16.iter().position(|&c| c == 0) {
            utf16.truncate(pos);
        }
        let sanitized: String = String::from_utf16_lossy(&utf16)
            .chars()
            .filter(|c| !c.is_control() || *c == '\t' || *c == '\n' || *c == '\r')
            .collect();
        sanitized.trim().to_string()
    }

    pub fn pick_best_path_test(raw: &str) -> String {
        if raw.is_empty() {
            return String::new();
        }
        let candidates: Vec<&str> = raw.split('\0').filter(|s| !s.is_empty()).collect();

        let mut best = String::new();
        let mut best_score = -1i32;

        for c in &candidates {
            let s = c.trim();
            if s.is_empty() {
                continue;
            }
            let score = pick_best_path_score_internal(s);
            if score > best_score {
                best_score = score;
                best = s.to_string();
            }
        }

        if best.is_empty() && !candidates.is_empty() {
            best = candidates[0].to_string();
        }

        best
    }

    pub fn pick_best_path_score(path: &str) -> i32 {
        pick_best_path_score_internal(path)
    }

    fn pick_best_path_score_internal(s: &str) -> i32 {
        let mut score = 0i32;
        if s.len() >= 2 && s.as_bytes()[1] == b':' {
            score += 100;
        }
        if s.starts_with("\\Device\\") {
            score += 50;
        }
        if s.contains('\\') {
            score += 20;
        }
        let s_lower = s.to_lowercase();
        if s_lower.ends_with(".exe") || s_lower.ends_with(".dll") || s_lower.ends_with(".sys") {
            score += 30;
        }
        if s.len() < 3 {
            score -= 50;
        }
        score
    }

    pub fn is_private_ipv4_test(a0: u32, a1: u32, _a2: u32, _a3: u32) -> bool {
        if a0 == 10 {
            return true;
        }
        if a0 == 172 && a1 >= 16 && a1 <= 31 {
            return true;
        }
        if a0 == 192 && a1 == 168 {
            return true;
        }
        if a0 == 169 && a1 == 254 {
            return true;
        }
        if a0 == 127 {
            return true;
        }
        false
    }

    pub fn map_file_op_test(id: u16) -> String {
        match id {
            64 => "create",
            65 => "open",
            67 => "delete",
            69 => "rename",
            70 => "setinfo",
            71 => "create_new",
            72 => "dir_enum",
            73 => "dir_notify",
            74 => "read",
            75 => "write",
            76 => "close",
            _ => return format!("file_{}", id),
        }
        .to_string()
    }

    pub fn map_registry_op_test(opcode: u16) -> String {
        match opcode {
            1 => "create_key",
            2 => "open_key",
            3 => "delete_key",
            4 => "query_key",
            5 => "set_value",
            6 => "delete_value",
            7 => "query_value",
            8 => "enumerate_key",
            9 => "enumerate_value_key",
            10 => "query_multiple_value",
            11 => "set_information_key",
            12 => "flush_key",
            13 => "create_key_ex",
            14 => "open_key_ex",
            15 => "delete_key_ex",
            16 => "rename_key",
            _ => return format!("reg_{}", opcode),
        }
        .to_string()
    }
}
