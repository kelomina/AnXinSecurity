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
    let (provider, op, target, target2) = if same_guid(provider_guid, &PROCESS_GUID) {
        parse_process_event(opcode, user_data)
    } else if same_guid(provider_guid, &FILE_GUID) {
        parse_file_event(id, user_data)
    } else if same_guid(provider_guid, &REGISTRY_GUID) {
        parse_registry_event(opcode, user_data)
    } else if same_guid(provider_guid, &NETWORK_GUID) {
        parse_network_event(opcode, user_data)
    } else {
        (ProviderKind::Unknown, String::new(), String::new(), String::new())
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
    }
}

// Kernel provider GUIDs
pub const PROCESS_GUID: [u8; 16] = [0xD6, 0x2C, 0xFB, 0x22, 0x7B, 0x0E, 0x2B, 0x42, 0xA0, 0xC7, 0x2F, 0xAD, 0x1F, 0xD0, 0xE7, 0x16];
pub const FILE_GUID: [u8; 16] = [0x27, 0x89, 0xD0, 0xED, 0xC4, 0x9C, 0x65, 0x4E, 0xB9, 0x70, 0xC2, 0x56, 0x0F, 0xB5, 0xC2, 0x89];
pub const REGISTRY_GUID: [u8; 16] = [0x03, 0x4F, 0xEB, 0x70, 0xDE, 0xC1, 0x73, 0x4F, 0xA0, 0x51, 0x33, 0xD1, 0x3D, 0x54, 0x13, 0xBD];
pub const NETWORK_GUID: [u8; 16] = [0x49, 0x2A, 0xD4, 0x7D, 0x29, 0x53, 0x32, 0x48, 0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88];

fn same_guid(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a == b
}

fn parse_process_event(opcode: u16, data: &[u8]) -> (ProviderKind, String, String, String) {
    let op = match opcode {
        1 => "start",
        2 => "stop",
        _ => "unknown",
    };
    let mut process_name = String::new();
    // Try to extract image path from UserData
    if data.len() >= 8 {
        // Process events typically have image path as wide string at offset 8
        let offset = 8;
        if data.len() > offset {
            process_name = extract_wide_string(&data[offset..]);
        }
    }
    (ProviderKind::Process, op.to_string(), process_name.clone(), String::new())
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

            if !is_private && !is_loopback && !reserved && a0 > 0 && a1 < 256 && a2 < 256 && a3 < 256 {
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
    }.to_string()
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
    }.to_string()
}

fn is_private_ipv4(a0: u32, a1: u32, _a2: u32, _a3: u32) -> bool {
    // 10.x.x.x
    if a0 == 10 { return true; }
    // 172.16-31.x.x
    if a0 == 172 && a1 >= 16 && a1 <= 31 { return true; }
    // 192.168.x.x
    if a0 == 192 && a1 == 168 { return true; }
    // 169.254.x.x (link-local)
    if a0 == 169 && a1 == 254 { return true; }
    false
}

/// 函数名称：extract_wide_string
/// 函数作用：从原始字节中提取第一个 UTF-16 LE null 结尾字符串，过滤非打印字符。
/// Purpose: Extracts first null-terminated UTF-16 LE string from raw bytes, filters non-printable chars.
/// 中文关键词：宽字符串提取，UTF-16，字节解析，字符串清洗
/// English keywords: wide string extraction, UTF-16, byte parsing, string sanitization
fn extract_wide_string(data: &[u8]) -> String {
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
    // Find first null terminator
    if let Some(pos) = utf16.iter().position(|&c| c == 0) {
        utf16.truncate(pos);
    }
    // Sanitize: remove non-printable chars
    let sanitized: String = String::from_utf16_lossy(&utf16)
        .chars()
        .filter(|c| !c.is_control() || *c == '\t' || *c == '\n' || *c == '\r')
        .collect();
    sanitized.trim().to_string()
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
        if s.is_empty() { continue; }

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
