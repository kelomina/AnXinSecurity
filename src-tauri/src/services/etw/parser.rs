use super::rules::ProviderKind;

#[derive(Debug, Clone)]
pub struct ParsedEvent {
    pub ts_ms: u64,
    pub pid: u32,
    pub tid: u32,
    pub ppid: u32,
    pub provider: ProviderKind,
    pub opcode: u16,
    pub id: u16,
    pub op: String,
    pub target: String,
    pub target2: String,
    pub image_base: Option<u64>,
    pub image_size: Option<u64>,
    pub start_address: Option<u64>,
    pub raw_user_data_len: usize,
    pub raw_user_data_preview: String,
}

/// 解析 EVENT_RECORD 中的原始 UserData 字节，提取事件字段。
/// Parses raw UserData bytes from EVENT_RECORD to extract event fields.
///
/// 中文关键词：事件解析，二进制解析，UserData，内核事件
/// English keywords: event parsing, binary parsing, UserData, kernel event
pub fn parse_event_record(
    provider_guid: &[u8; 16],
    opcode: u16,
    id: u16,
    pid: u32,
    tid: u32,
    ts_ms: u64,
    user_data: &[u8],
) -> ParsedEvent {
    let (provider, op, target, target2, image_base, image_size, start_address) =
        if same_guid(provider_guid, &PROCESS_GUID) {
            parse_process_event(opcode, id, user_data)
        } else if same_guid(provider_guid, &FILE_GUID) {
            let (provider, op, target, target2) = parse_file_event(id, user_data);
            (provider, op, target, target2, None, None, None)
        } else if same_guid(provider_guid, &REGISTRY_GUID) {
            let (provider, op, target, target2) = parse_registry_event(opcode, user_data);
            (provider, op, target, target2, None, None, None)
        } else if same_guid(provider_guid, &NETWORK_GUID) {
            let (provider, op, target, target2) = parse_network_event(opcode, user_data);
            (provider, op, target, target2, None, None, None)
        } else {
            (
                ProviderKind::Unknown,
                String::new(),
                String::new(),
                String::new(),
                None,
                None,
                None,
            )
        };

    ParsedEvent {
        ts_ms,
        pid,
        tid,
        ppid: 0, // populated later by session if needed
        provider,
        opcode,
        id,
        op,
        target,
        target2,
        image_base,
        image_size,
        start_address,
        raw_user_data_len: user_data.len(),
        raw_user_data_preview: hex_preview(user_data, 96),
    }
}

// Kernel provider GUIDs
pub const PROCESS_GUID: [u8; 16] = [
    0xD6, 0x2C, 0xFB, 0x22, 0x7B, 0x0E, 0x2B, 0x42, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16,
];
pub const FILE_GUID: [u8; 16] = [
    0x27, 0x89, 0xD0, 0xED, 0xC4, 0x9C, 0x65, 0x4E, 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89,
];
pub const REGISTRY_GUID: [u8; 16] = [
    0x03, 0x4F, 0xEB, 0x70, 0xDE, 0xC1, 0x73, 0x4F, 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD,
];
pub const NETWORK_GUID: [u8; 16] = [
    0x49, 0x2A, 0xD4, 0x7D, 0x29, 0x53, 0x32, 0x48, 0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88,
];

fn same_guid(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a == b
}

fn hex_preview(data: &[u8], max_bytes: usize) -> String {
    let mut output = String::new();
    for (index, byte) in data.iter().take(max_bytes).enumerate() {
        if index > 0 {
            output.push(' ');
        }
        output.push_str(&format!("{:02x}", byte));
    }
    if data.len() > max_bytes {
        output.push_str(" …");
    }
    output
}

fn parse_process_event(
    opcode: u16,
    id: u16,
    data: &[u8],
) -> (
    ProviderKind,
    String,
    String,
    String,
    Option<u64>,
    Option<u64>,
    Option<u64>,
) {
    match map_kernel_process_task(id, data) {
        KernelProcessTask::ThreadStart {
            thread_id,
            start_address,
        } => (
            ProviderKind::Thread,
            "start".to_string(),
            format!("thread:{}", thread_id),
            String::new(),
            None,
            None,
            start_address,
        ),
        KernelProcessTask::ThreadStop { thread_id } => (
            ProviderKind::Thread,
            "stop".to_string(),
            format!("thread:{}", thread_id),
            String::new(),
            None,
            None,
            None,
        ),
        KernelProcessTask::ImageLoad {
            image_base,
            image_size,
            path,
        } => (
            ProviderKind::Image,
            "load".to_string(),
            path,
            String::new(),
            image_base,
            image_size,
            None,
        ),
        KernelProcessTask::ImageUnload {
            image_base,
            image_size,
            path,
        } => (
            ProviderKind::Image,
            "unload".to_string(),
            path,
            String::new(),
            image_base,
            image_size,
            None,
        ),
        KernelProcessTask::ProcessLike => {
            let op = match opcode {
                1 => "start",
                2 => "stop",
                _ => "unknown",
            };
            let process_name = pick_best_path_from_bytes(data);
            (
                ProviderKind::Process,
                op.to_string(),
                process_name,
                String::new(),
                None,
                None,
                None,
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum KernelProcessTask {
    ProcessLike,
    ThreadStart {
        thread_id: u32,
        start_address: Option<u64>,
    },
    ThreadStop {
        thread_id: u32,
    },
    ImageLoad {
        image_base: Option<u64>,
        image_size: Option<u64>,
        path: String,
    },
    ImageUnload {
        image_base: Option<u64>,
        image_size: Option<u64>,
        path: String,
    },
}

fn map_kernel_process_task(id: u16, data: &[u8]) -> KernelProcessTask {
    match id {
        3 => {
            let thread_id = read_u32_le(data, 4).unwrap_or_default();
            let start_address = likely_thread_start_address(data);
            return KernelProcessTask::ThreadStart {
                thread_id,
                start_address,
            };
        }
        4 => {
            let thread_id = read_u32_le(data, 4).unwrap_or_default();
            return KernelProcessTask::ThreadStop { thread_id };
        }
        5 | 6 => {
            let mut image_candidates = extract_wide_strings(data)
                .into_iter()
                .filter(|value| looks_like_image_path(value))
                .collect::<Vec<_>>();
            image_candidates.sort_by_key(|candidate| -pick_best_path_score(candidate));

            let path = image_candidates.into_iter().next().unwrap_or_default();
            let image_base = first_non_zero_pointer(data);
            let image_size = likely_image_size(data);
            if id == 5 {
                return KernelProcessTask::ImageLoad {
                    image_base,
                    image_size,
                    path,
                };
            }
            return KernelProcessTask::ImageUnload {
                image_base,
                image_size,
                path,
            };
        }
        _ => {}
    }

    KernelProcessTask::ProcessLike
}

fn pick_best_path_from_bytes(data: &[u8]) -> String {
    let strings = extract_wide_strings(data);
    pick_top_path(strings.into_iter()).unwrap_or_default()
}

fn pick_top_path<I>(values: I) -> Option<String>
where
    I: IntoIterator<Item = String>,
{
    values
        .into_iter()
        .filter(|value| !value.trim().is_empty())
        .max_by_key(|value| pick_best_path_score(value))
}

fn pick_best_path_score(path: &str) -> i32 {
    let s = path.trim();
    let mut score = 0i32;
    if s.len() >= 2 && s.as_bytes()[1] == b':' {
        score += 100;
    }
    if s.starts_with("\\Device\\") {
        score += 80;
    }
    if s.contains('\\') {
        score += 20;
    }
    let lower = s.to_ascii_lowercase();
    if lower.ends_with(".exe") || lower.ends_with(".dll") || lower.ends_with(".sys") {
        score += 40;
    }
    if lower.contains("\\windows\\")
        || lower.contains("\\program files")
        || lower.contains("\\users\\")
    {
        score += 10;
    }
    score
}

fn looks_like_image_path(value: &str) -> bool {
    let lower = value.trim().to_ascii_lowercase();
    (lower.contains('\\') || lower.contains('/'))
        && (lower.ends_with(".dll") || lower.ends_with(".exe") || lower.ends_with(".sys"))
}

fn first_non_zero_pointer(data: &[u8]) -> Option<u64> {
    if data.len() >= 8 {
        for offset in (0..=data.len().saturating_sub(8)).step_by(8) {
            let value = read_u64_le(data, offset)?;
            if looks_like_user_pointer(value) {
                return Some(value);
            }
        }
    }
    None
}

fn likely_thread_start_address(data: &[u8]) -> Option<u64> {
    if data.len() >= 24 {
        for offset in (8..=data.len().saturating_sub(8)).step_by(8) {
            let value = read_u64_le(data, offset)?;
            if looks_like_user_pointer(value) {
                return Some(value);
            }
        }
    }
    None
}

fn likely_image_size(data: &[u8]) -> Option<u64> {
    if data.len() < 12 {
        return None;
    }
    for offset in (4..=data.len().saturating_sub(4)).step_by(4) {
        let value = read_u32_le(data, offset)? as u64;
        if value >= 0x1000 && value <= 0x4000_0000 && value % 0x1000 == 0 {
            return Some(value);
        }
    }
    None
}

fn looks_like_user_pointer(value: u64) -> bool {
    value >= 0x10_000 && value < 0x0000_8000_0000_0000
}

fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_u64_le(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

fn parse_file_event(id: u16, data: &[u8]) -> (ProviderKind, String, String, String) {
    let op = map_file_op(id);
    let path = extract_wide_string(data);
    let file_path = pick_best_path(&path);
    (ProviderKind::File, op, file_path, String::new())
}

fn parse_registry_event(opcode: u16, data: &[u8]) -> (ProviderKind, String, String, String) {
    let op = map_registry_op(opcode);
    let raw = extract_wide_string(data);
    let (mut key_name, val_name) = if let Some(pos) = raw.rfind('\\') {
        let maybe_val = &raw[pos + 1..];
        if !maybe_val.is_empty() && maybe_val.len() < 256 {
            (raw[..pos].to_string(), maybe_val.to_string())
        } else {
            (raw.clone(), String::new())
        }
    } else {
        (raw.clone(), String::new())
    };
    // Normalize registry root
    if key_name.starts_with("\\REGISTRY\\MACHINE\\") {
        key_name = format!("HKLM\\{}", &key_name[19..]);
    } else if key_name.starts_with("\\REGISTRY\\USER\\") {
        key_name = format!("HKU\\{}", &key_name[16..]);
    }
    (ProviderKind::Registry, op, key_name, val_name)
}

fn parse_network_event(opcode: u16, data: &[u8]) -> (ProviderKind, String, String, String) {
    let op = match opcode {
        10 => "connect",
        11 => "accept",
        12 => "disconnect",
        13 => "reconnect",
        14 => "send",
        15 => "recv",
        16 => "tcp_close",
        _ => "unknown",
    };
    let mut addr = String::new();
    let mut port: u16 = 0;

    // Network events: scan UserData for IPv4 + port pairs
    if data.len() >= 12 {
        for i in 0..data.len().saturating_sub(12) {
            let b = &data[i..i + 12];
            // Try to find a valid IPv4 (non-private, non-loopback) + port
            let a0 = b[0] as u32;
            let a1 = b[1] as u32;
            let a2 = b[2] as u32;
            let a3 = b[3] as u32;
            let port_hi = b[4] as u16;
            let port_lo = b[5] as u16;
            let p1 = (port_hi << 8) | port_lo;
            let p2 = (b[6] as u16) << 8 | b[7] as u16;

            let is_private = is_private_ipv4(a0, a1, a2, a3);
            let is_loopback = a0 == 127;
            let reserved = a0 >= 224;

            if !is_private
                && !is_loopback
                && !reserved
                && a0 > 0
                && a1 < 256
                && a2 < 256
                && a3 < 256
            {
                if p1 > 0 && p1 < 65535 {
                    addr = format!("{}.{}.{}.{}", a0, a1, a2, a3);
                    port = p1;
                    break;
                }
                if p2 > 0 && p2 < 65535 {
                    addr = format!("{}.{}.{}.{}", a0, a1, a2, a3);
                    port = p2;
                    break;
                }
            }
        }
    }

    let target = if addr.is_empty() {
        String::new()
    } else {
        format!("{}:{}", addr, port)
    };

    (ProviderKind::Network, op.to_string(), target, String::new())
}

fn map_file_op(id: u16) -> String {
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

fn map_registry_op(opcode: u16) -> String {
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

fn is_private_ipv4(a0: u32, a1: u32, _a2: u32, _a3: u32) -> bool {
    // 10.x.x.x
    if a0 == 10 {
        return true;
    }
    // 172.16-31.x.x
    if a0 == 172 && a1 >= 16 && a1 <= 31 {
        return true;
    }
    // 192.168.x.x
    if a0 == 192 && a1 == 168 {
        return true;
    }
    // 169.254.x.x (link-local)
    if a0 == 169 && a1 == 254 {
        return true;
    }
    false
}

/// 函数名称：extract_wide_string
/// 函数作用：从原始字节中提取第一个 UTF-16 LE null 结尾字符串，过滤非打印字符。
/// Purpose: Extracts first null-terminated UTF-16 LE string from raw bytes, filters non-printable chars.
/// 中文关键词：宽字符串提取，UTF-16，字节解析，字符串清洗
/// English keywords: wide string extraction, UTF-16, byte parsing, string sanitization
fn extract_wide_string(data: &[u8]) -> String {
    extract_wide_strings(data)
        .into_iter()
        .next()
        .unwrap_or_default()
}

fn extract_wide_strings(data: &[u8]) -> Vec<String> {
    if data.len() < 2 {
        return Vec::new();
    }
    let wchar_count = data.len() / 2;
    let mut strings = Vec::new();
    let mut current: Vec<u16> = Vec::new();
    for i in 0..wchar_count {
        let lo = data[i * 2] as u16;
        let hi = data[i * 2 + 1] as u16;
        let ch = lo | (hi << 8);
        if ch == 0 {
            push_sanitized_wide_string(&mut strings, &current);
            current.clear();
        } else {
            current.push(ch);
        }
    }
    push_sanitized_wide_string(&mut strings, &current);

    strings
}

fn push_sanitized_wide_string(strings: &mut Vec<String>, utf16: &[u16]) {
    if utf16.is_empty() {
        return;
    }
    // Sanitize: remove non-printable chars
    let sanitized: String = String::from_utf16_lossy(&utf16)
        .chars()
        .filter(|c| !c.is_control() || *c == '\t' || *c == '\n' || *c == '\r')
        .collect();
    let sanitized = sanitized.trim();
    if sanitized.len() >= 2 {
        strings.push(sanitized.to_string());
    }
}

/// 函数名称：pick_best_path
/// 函数作用：从多个候选路径中选择评分最高的文件路径。优先盘符路径和可执行文件。
/// Purpose: Picks highest-scoring file path from multiple candidates. Prefers drive-letter paths and executables.
/// 中文关键词：路径评分，路径选择，候选路径，启发式，最佳路径
/// English keywords: path scoring, path selection, candidate path, heuristic, best path
fn pick_best_path(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    // Split by null characters (already handled in extract_wide_string)
    // Check multiple path candidates
    let candidates: Vec<&str> = raw.split('\0').filter(|s| !s.is_empty()).collect();

    let mut best = String::new();
    let mut best_score = -1i32;

    for c in &candidates {
        let s = c.trim();
        if s.is_empty() {
            continue;
        }

        let mut score = 0i32;
        // Prefer paths with drive letters
        if s.len() >= 2 && s.as_bytes()[1] == b':' {
            score += 100;
        }
        // Prefer paths starting with \Device\
        if s.starts_with("\\Device\\") {
            score += 50;
        }
        // Prefer paths with \ (file-like)
        if s.contains('\\') {
            score += 20;
        }
        // Prefer .exe / .dll / .sys
        let s_lower = s.to_lowercase();
        if s_lower.ends_with(".exe") || s_lower.ends_with(".dll") || s_lower.ends_with(".sys") {
            score += 30;
        }
        // Penalize too short paths
        if s.len() < 3 {
            score -= 50;
        }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kernel_process_image_load_as_image_provider() {
        let mut data = Vec::new();
        data.extend_from_slice(&0x7ff7_0000_0000_u64.to_le_bytes());
        data.extend_from_slice(&0x12000_u32.to_le_bytes());
        data.extend_from_slice(&0_u32.to_le_bytes());
        data.extend(
            r"E:\Project\HTML\AnXinSecurity\native\file_hook\build-calc-probe-x64\Release\calc_probe_payload.dll"
                .encode_utf16()
                .flat_map(|ch| ch.to_le_bytes()),
        );
        data.extend_from_slice(&0_u16.to_le_bytes());

        let event = parse_event_record(&PROCESS_GUID, 0, 5, 30056, 991, 1780000000000, &data);

        assert_eq!(event.provider, ProviderKind::Image);
        assert_eq!(event.op, "load");
        assert!(event.target.ends_with("calc_probe_payload.dll"));
        assert_eq!(event.image_base, Some(0x7ff7_0000_0000));
        assert_eq!(event.image_size, Some(0x12000));
        assert_eq!(event.raw_user_data_len, data.len());
        assert!(event.raw_user_data_preview.starts_with("00 00 00 00"));
    }

    #[test]
    fn parses_kernel_process_thread_start_as_thread_provider() {
        let mut data = Vec::new();
        data.extend_from_slice(&30056_u32.to_le_bytes());
        data.extend_from_slice(&777_u32.to_le_bytes());
        data.extend_from_slice(&0_u64.to_le_bytes());
        data.extend_from_slice(&0x7ff7_0000_1234_u64.to_le_bytes());

        let event = parse_event_record(&PROCESS_GUID, 1, 3, 30056, 991, 1780000000001, &data);

        assert_eq!(event.provider, ProviderKind::Thread);
        assert_eq!(event.op, "start");
        assert_eq!(event.target, "thread:777");
        assert_eq!(event.start_address, Some(0x7ff7_0000_1234));
        assert_eq!(event.raw_user_data_len, data.len());
        assert!(event.raw_user_data_preview.contains("34 12 00 00 f7 7f"));
    }

    #[test]
    fn raw_user_data_preview_is_bounded_hex() {
        let data: Vec<u8> = (0..120).collect();
        let event = parse_event_record(&PROCESS_GUID, 0, 5, 30056, 991, 1780000000000, &data);

        assert_eq!(event.raw_user_data_len, 120);
        assert!(event.raw_user_data_preview.starts_with("00 01 02 03"));
        assert!(event.raw_user_data_preview.ends_with('…'));
        assert!(!event.raw_user_data_preview.contains("61"));
    }
}
