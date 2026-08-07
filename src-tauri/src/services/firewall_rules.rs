// 防火墙规则模型 — 加载、校验并编译为驱动可用的定长二进制表
//  Firewall rule model - loads, validates and compiles rules into the fixed-size
//  binary tables the driver consumes.
//
// 规则文件位于 config/firewall_rules.json，采用与 config/etw_match_rules.json
// 一致的 camelCase JSON 风格，便于运维用同一套习惯维护两份规则。
//  The rule file lives at config/firewall_rules.json and follows the same
//  camelCase JSON style as config/etw_match_rules.json so both are maintained
//  with the same conventions.
//
// 编译产物是三张表：连接级规则、域名规则、限速条目，分别对应驱动的
// SET_RULES / SET_DOMAINS / SET_LIMITS 三个 IOCTL。
//  Compilation produces three tables — connection rules, domain rules and rate
//  limits — matching the driver's SET_RULES / SET_DOMAINS / SET_LIMITS IOCTLs.
//
// 中文关键词：防火墙规则，规则编译，CIDR，进程匹配
// English keywords: firewall rules, rule compilation, CIDR, process matching

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::utils::net_driver_client::{
    app_id_hash_for_path, NetAddr, NetDomainRule, NetLimit, NetRule, ACTION_ALLOW, ACTION_BLOCK,
    ACTION_CONTINUE, ACTION_PROMPT, DIR_ANY, DIR_INBOUND, DIR_OUTBOUND, DM_CONTAINS, DM_EXACT,
    DM_SUFFIX, NET_MAX_DOMAIN_RULES, NET_MAX_LIMITS, NET_MAX_RULES, PROTO_ANY, PROTO_TCP,
    PROTO_UDP, RF_ENABLED, RF_LOG, RF_MATCH_LOOPBACK,
};

/// 规则文件相对路径 / Relative path of the rule file
pub const FIREWALL_RULES_FILE: &str = "config/firewall_rules.json";

// ============================================================================
// JSON 模型 / JSON model
// ============================================================================

/// 端口区间，闭区间；`[0, 0]` 表示不限。
///  An inclusive port range; `[0, 0]` means "any port".
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortRange {
    pub low: u32,
    pub high: u32,
}

/// 连接级规则的 JSON 形式 / JSON form of a connection rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRule {
    /// 规则编号，事件回传时用它定位命中的规则
    ///  Rule id; events carry it back so the matching rule can be identified
    pub rule_id: u32,
    /// 规则名称，仅用于界面展示 / Display name, UI only
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// allow / block / prompt / continue
    pub action: String,
    /// outbound / inbound / any
    #[serde(default = "default_direction")]
    pub direction: String,
    /// tcp / udp / any
    #[serde(default = "default_protocol")]
    pub protocol: String,
    /// 进程可执行文件路径；为空表示匹配任意进程
    ///  Process image path; empty matches any process
    #[serde(default)]
    pub process_path: Option<String>,
    /// 远端地址，CIDR 形式（如 `10.0.0.0/8`、`::1/128`）；为空表示不限
    ///  Remote address in CIDR form; empty means "any"
    #[serde(default)]
    pub remote_address: Option<String>,
    #[serde(default)]
    pub remote_port_range: Option<PortRange>,
    #[serde(default)]
    pub local_port_range: Option<PortRange>,
    /// 是否让本规则也作用于回环流量，默认否
    ///  Whether the rule also applies to loopback traffic; off by default
    #[serde(default)]
    pub match_loopback: bool,
    #[serde(default = "default_true")]
    pub log: bool,
    #[serde(default)]
    pub description: String,
}

/// 域名规则的 JSON 形式 / JSON form of a domain rule
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallDomainRule {
    pub rule_id: u32,
    pub domain: String,
    /// allow / block
    pub action: String,
    /// exact / suffix / contains
    #[serde(default = "default_match_type")]
    pub match_type: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

/// 限速条目的 JSON 形式 / JSON form of a rate-limit entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRateLimit {
    /// 进程路径；为空表示全局限速 / Process path; empty means a global limit
    #[serde(default)]
    pub process_path: Option<String>,
    #[serde(default)]
    pub bytes_per_sec_in: u64,
    #[serde(default)]
    pub bytes_per_sec_out: u64,
    #[serde(default)]
    pub burst_bytes: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub description: String,
}

/// 规则文件的顶层结构 / Top-level structure of the rule file
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct FirewallRuleSet {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
    #[serde(default)]
    pub domain_rules: Vec<FirewallDomainRule>,
    #[serde(default)]
    pub rate_limits: Vec<FirewallRateLimit>,
}

fn default_true() -> bool {
    true
}
fn default_version() -> u32 {
    1
}
fn default_direction() -> String {
    "any".to_string()
}
fn default_protocol() -> String {
    "any".to_string()
}
fn default_match_type() -> String {
    "suffix".to_string()
}

// ============================================================================
// 编译产物 / Compilation output
// ============================================================================

/// 编译后的三张驱动表，以及编译过程中收集到的告警。
///  The three compiled driver tables plus any warnings gathered while compiling.
#[derive(Debug, Default)]
pub struct CompiledRules {
    pub version: u32,
    pub rules: Vec<NetRule>,
    pub domains: Vec<NetDomainRule>,
    pub limits: Vec<NetLimit>,
    /// 被跳过的条目及原因，供日志与界面提示使用
    ///  Skipped entries and why, for logs and UI hints
    pub warnings: Vec<String>,
}

// ============================================================================
// 解析辅助 / Parsing helpers
// ============================================================================

/// 函数名称：parse_action
/// 函数作用：把动作字符串解析为驱动的动作常量。
/// Purpose: Parses an action string into the driver's action constant.
/// 中文关键词：动作解析，放行，拦截，询问
/// English keywords: action parsing, allow, block, prompt
fn parse_action(value: &str) -> Result<u32, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "allow" | "permit" => Ok(ACTION_ALLOW),
        "block" | "deny" => Ok(ACTION_BLOCK),
        "prompt" | "ask" => Ok(ACTION_PROMPT),
        "continue" | "next" => Ok(ACTION_CONTINUE),
        other => Err(format!("unknown action '{}'", other)),
    }
}

fn parse_direction(value: &str) -> Result<u32, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "outbound" | "out" => Ok(DIR_OUTBOUND),
        "inbound" | "in" => Ok(DIR_INBOUND),
        "any" | "both" => Ok(DIR_ANY),
        other => Err(format!("unknown direction '{}'", other)),
    }
}

fn parse_protocol(value: &str) -> Result<u32, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "tcp" => Ok(PROTO_TCP),
        "udp" => Ok(PROTO_UDP),
        "any" | "" => Ok(PROTO_ANY),
        other => Err(format!("unknown protocol '{}'", other)),
    }
}

fn parse_match_type(value: &str) -> Result<u32, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "exact" => Ok(DM_EXACT),
        "suffix" => Ok(DM_SUFFIX),
        "contains" => Ok(DM_CONTAINS),
        other => Err(format!("unknown matchType '{}'", other)),
    }
}

/// 函数名称：parse_cidr
/// 函数作用：解析 `地址/前缀` 形式的网段，返回驱动侧的地址结构与前缀长度。
/// Purpose: Parses `address/prefix` into the driver's address form and prefix length.
///
/// 允许省略 `/前缀`，此时按单主机处理（IPv4 为 /32，IPv6 为 /128）。
/// 前缀超出地址位宽时报错而不是静默截断 —— 一条本意是 `/24` 却被写成 `/240`
/// 的规则如果被悄悄改成 `/32`，匹配范围会与作者的意图相差极大。
/// The `/prefix` part may be omitted, meaning a single host (/32 for IPv4, /128
/// for IPv6). A prefix wider than the address is an error rather than a silent
/// clamp: a rule meant as `/24` but typed as `/240` would otherwise become `/32`
/// and match a wildly different set of hosts than intended.
///
/// 中文关键词：CIDR 解析，网段，前缀长度
/// English keywords: CIDR parsing, network, prefix length
fn parse_cidr(value: &str) -> Result<(NetAddr, u8), String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("empty CIDR".to_string());
    }

    let (addr_part, prefix_part) = match trimmed.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (trimmed, None),
    };

    let ip: IpAddr = addr_part
        .parse()
        .map_err(|_| format!("invalid IP address '{}'", addr_part))?;

    let max_bits: u8 = if ip.is_ipv4() { 32 } else { 128 };

    let prefix = match prefix_part {
        Some(p) => p
            .trim()
            .parse::<u8>()
            .map_err(|_| format!("invalid prefix length '{}'", p))?,
        None => max_bits,
    };

    if prefix > max_bits {
        return Err(format!(
            "prefix /{} exceeds the {} bits of address '{}'",
            prefix, max_bits, addr_part
        ));
    }

    let addr = match ip {
        IpAddr::V4(v4) => NetAddr::from_ipv4(v4.octets()),
        IpAddr::V6(v6) => NetAddr::from_ipv6(v6.octets()),
    };

    Ok((addr, prefix))
}

fn normalize_port_range(range: Option<PortRange>, label: &str) -> Result<(u32, u32), String> {
    match range {
        None => Ok((0, 0)),
        Some(r) => {
            if r.low > 65535 || r.high > 65535 {
                return Err(format!("{} port out of range (max 65535)", label));
            }
            if r.low > r.high {
                return Err(format!(
                    "{} port range low {} is greater than high {}",
                    label, r.low, r.high
                ));
            }
            Ok((r.low, r.high))
        }
    }
}

// ============================================================================
// 加载与编译 / Loading and compilation
// ============================================================================

impl FirewallRuleSet {
    /// 函数名称：load
    /// 函数作用：从 config/firewall_rules.json 加载规则集，兼容 tauri dev 的上级目录布局、
    ///          可执行文件目录与打包后的 _up_ 资源布局。
    /// Purpose: Loads the rule set from config/firewall_rules.json, handling the
    ///          tauri-dev parent-directory layout, the executable directory, and the
    ///          bundled `_up_` resource layout.
    ///
    /// 文件不存在时返回空规则集而不是错误：没有规则文件是合法状态，意味着
    /// 一切按 app.json 里的默认动作处理。
    /// A missing file yields an empty set rather than an error: having no rule
    /// file is a legitimate state meaning "everything follows the default action
    /// from app.json".
    ///
    /// 调用方：FirewallService::reload_rules
    /// Called by: FirewallService::reload_rules
    /// 中文关键词：规则加载，路径解析，缺省为空
    /// English keywords: rule loading, path resolution, empty default
    pub fn load() -> Result<Self, String> {
        let mut candidates = vec![
            PathBuf::from(FIREWALL_RULES_FILE),
            PathBuf::from("..").join(FIREWALL_RULES_FILE),
        ];

        // 与 etw/rules.rs 的 default_rule_config_paths 保持同一套路径策略：
        // 打包后规则文件落在 $INSTDIR\_up_\config\firewall_rules.json，
        // 只靠 cwd 相对路径在生产环境加载不到。
        //  Same path strategy as default_rule_config_paths in etw/rules.rs: after
        //  bundling the rules land at $INSTDIR\_up_\config\firewall_rules.json,
        //  which cwd-relative paths cannot reach in production.
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(exe_dir) = exe_path.parent() {
                candidates.push(exe_dir.join("config").join("firewall_rules.json"));
                candidates.push(exe_dir.join("resources").join("config").join("firewall_rules.json"));
                candidates.push(exe_dir.join("_up_").join("config").join("firewall_rules.json"));
                candidates.push(exe_dir.join("..").join("config").join("firewall_rules.json"));
            }
        }

        for candidate in candidates {
            if candidate.exists() {
                return Self::load_from_path(&candidate);
            }
        }

        // 规则文件缺失是合法状态 / a missing rule file is legitimate
        Ok(Self {
            version: 1,
            ..Default::default()
        })
    }

    /// 从指定路径加载 / Loads from an explicit path
    pub fn load_from_path(path: &PathBuf) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        Self::from_json(&content)
    }

    /// 从 JSON 文本解析 / Parses from JSON text
    pub fn from_json(content: &str) -> Result<Self, String> {
        serde_json::from_str(content).map_err(|e| format!("failed to parse firewall rules: {}", e))
    }

    /// 函数名称：compile
    /// 函数作用：把 JSON 规则编译为驱动可直接消费的定长二进制表。
    /// Purpose: Compiles the JSON rules into the fixed-size binary tables the
    ///          driver consumes.
    ///
    /// 单条规则出错只跳过该条并记入 warnings，不让整份规则文件失效：
    /// 一个手滑写错的 CIDR 不应该导致整台机器失去防护。
    /// A bad rule is skipped and recorded in warnings rather than failing the
    /// whole file: one mistyped CIDR must not strip the machine of protection.
    ///
    /// 超出驱动容量上限的部分会被截断并明确记录，绝不静默丢弃。
    /// Anything beyond the driver's capacity is truncated with an explicit
    /// warning — never dropped silently.
    ///
    /// 调用方：FirewallService::apply_rules
    /// Called by: FirewallService::apply_rules
    /// 中文关键词：规则编译，容错，容量截断
    /// English keywords: rule compilation, fault tolerance, capacity truncation
    pub fn compile(&self) -> CompiledRules {
        let mut out = CompiledRules {
            version: self.version,
            ..Default::default()
        };

        // ---- 连接级规则 / connection rules ----
        for rule in &self.rules {
            if !rule.enabled {
                continue;
            }

            match self.compile_rule(rule) {
                Ok(compiled) => out.rules.push(compiled),
                Err(e) => out.warnings.push(format!(
                    "rule {} ('{}') skipped: {}",
                    rule.rule_id, rule.name, e
                )),
            }
        }

        if out.rules.len() > NET_MAX_RULES {
            out.warnings.push(format!(
                "rule table truncated from {} to the driver limit of {}",
                out.rules.len(),
                NET_MAX_RULES
            ));
            out.rules.truncate(NET_MAX_RULES);
        }

        // ---- 域名规则 / domain rules ----
        for rule in &self.domain_rules {
            if !rule.enabled {
                continue;
            }
            if rule.domain.trim().is_empty() {
                out.warnings.push(format!(
                    "domain rule {} skipped: empty domain",
                    rule.rule_id
                ));
                continue;
            }

            let action = match parse_action(&rule.action) {
                Ok(a) if a == ACTION_ALLOW || a == ACTION_BLOCK => a,
                Ok(_) => {
                    out.warnings.push(format!(
                        "domain rule {} skipped: only allow/block are supported",
                        rule.rule_id
                    ));
                    continue;
                }
                Err(e) => {
                    out.warnings
                        .push(format!("domain rule {} skipped: {}", rule.rule_id, e));
                    continue;
                }
            };

            let match_type = match parse_match_type(&rule.match_type) {
                Ok(m) => m,
                Err(e) => {
                    out.warnings
                        .push(format!("domain rule {} skipped: {}", rule.rule_id, e));
                    continue;
                }
            };

            let mut compiled = NetDomainRule {
                rule_id: rule.rule_id,
                action,
                match_type,
                flags: 0,
                ..Default::default()
            };
            compiled.set_domain(rule.domain.trim());
            out.domains.push(compiled);
        }

        if out.domains.len() > NET_MAX_DOMAIN_RULES {
            out.warnings.push(format!(
                "domain table truncated from {} to the driver limit of {}",
                out.domains.len(),
                NET_MAX_DOMAIN_RULES
            ));
            out.domains.truncate(NET_MAX_DOMAIN_RULES);
        }

        // ---- 限速 / rate limits ----
        for limit in &self.rate_limits {
            if !limit.enabled {
                continue;
            }
            if limit.bytes_per_sec_in == 0 && limit.bytes_per_sec_out == 0 {
                continue; // 全 0 等于不限速，没有下发的必要 / all-zero means no limit
            }

            let app_id_hash = match &limit.process_path {
                Some(path) if !path.trim().is_empty() => app_id_hash_for_path(path.trim()),
                _ => 0,
            };

            out.limits.push(NetLimit {
                app_id_hash,
                bytes_per_sec_in: limit.bytes_per_sec_in,
                bytes_per_sec_out: limit.bytes_per_sec_out,
                burst_bytes: limit.burst_bytes,
            });
        }

        if out.limits.len() > NET_MAX_LIMITS {
            out.warnings.push(format!(
                "limit table truncated from {} to the driver limit of {}",
                out.limits.len(),
                NET_MAX_LIMITS
            ));
            out.limits.truncate(NET_MAX_LIMITS);
        }

        out
    }

    fn compile_rule(&self, rule: &FirewallRule) -> Result<NetRule, String> {
        let action = parse_action(&rule.action)?;
        let direction = parse_direction(&rule.direction)?;
        let protocol = parse_protocol(&rule.protocol)?;

        let (remote_low, remote_high) = normalize_port_range(rule.remote_port_range, "remote")?;
        let (local_low, local_high) = normalize_port_range(rule.local_port_range, "local")?;

        let (remote_addr, prefix) = match &rule.remote_address {
            Some(cidr) if !cidr.trim().is_empty() => parse_cidr(cidr)?,
            _ => (NetAddr::default(), 0),
        };

        let app_id_hash = match &rule.process_path {
            Some(path) if !path.trim().is_empty() => {
                let hash = app_id_hash_for_path(path.trim());
                if hash == 0 {
                    return Err(format!("could not derive an app id for '{}'", path.trim()));
                }
                hash
            }
            _ => 0,
        };

        let mut flags = RF_ENABLED;
        if rule.log {
            flags |= RF_LOG;
        }
        if rule.match_loopback {
            flags |= RF_MATCH_LOOPBACK;
        }

        Ok(NetRule {
            rule_id: rule.rule_id,
            action,
            direction,
            protocol,
            flags,
            remote_port_low: remote_low,
            remote_port_high: remote_high,
            local_port_low: local_low,
            local_port_high: local_high,
            remote_addr,
            remote_prefix_len: prefix,
            reserved: [0; 7],
            app_id_hash,
        })
    }
}

// ============================================================================
// 单元测试 / Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rule(action: &str) -> FirewallRule {
        FirewallRule {
            rule_id: 1,
            name: "test".to_string(),
            enabled: true,
            action: action.to_string(),
            direction: "outbound".to_string(),
            protocol: "tcp".to_string(),
            process_path: None,
            remote_address: None,
            remote_port_range: None,
            local_port_range: None,
            match_loopback: false,
            log: true,
            description: String::new(),
        }
    }

    #[test]
    fn parses_all_action_spellings() {
        assert_eq!(parse_action("allow").unwrap(), ACTION_ALLOW);
        assert_eq!(parse_action("Permit").unwrap(), ACTION_ALLOW);
        assert_eq!(parse_action("BLOCK").unwrap(), ACTION_BLOCK);
        assert_eq!(parse_action(" deny ").unwrap(), ACTION_BLOCK);
        assert_eq!(parse_action("prompt").unwrap(), ACTION_PROMPT);
        assert!(parse_action("maybe").is_err());
    }

    #[test]
    fn parses_ipv4_cidr() {
        let (addr, prefix) = parse_cidr("10.1.2.0/24").unwrap();
        assert_eq!(addr.family, crate::utils::net_driver_client::AF_INET);
        assert_eq!(&addr.bytes[..4], &[10, 1, 2, 0]);
        assert_eq!(prefix, 24);
    }

    #[test]
    fn parses_ipv6_cidr() {
        let (addr, prefix) = parse_cidr("::1/128").unwrap();
        assert_eq!(addr.family, crate::utils::net_driver_client::AF_INET6);
        assert_eq!(addr.bytes[15], 1);
        assert_eq!(prefix, 128);
    }

    /// 省略前缀时应按单主机处理，而不是变成匹配全网。
    ///  Omitting the prefix must mean a single host, not the whole internet.
    #[test]
    fn bare_address_defaults_to_host_prefix() {
        let (_, v4_prefix) = parse_cidr("192.168.1.5").unwrap();
        assert_eq!(v4_prefix, 32);

        let (_, v6_prefix) = parse_cidr("fe80::1").unwrap();
        assert_eq!(v6_prefix, 128);
    }

    /// 越界前缀必须报错，静默截断会让规则的作用范围与作者意图严重不符。
    ///  An out-of-range prefix must error; clamping would silently widen or
    ///  narrow the rule far from the author's intent.
    #[test]
    fn oversized_prefix_is_rejected() {
        assert!(parse_cidr("10.0.0.0/33").is_err());
        assert!(parse_cidr("::1/129").is_err());
        assert!(parse_cidr("not-an-ip/24").is_err());
    }

    #[test]
    fn rejects_inverted_and_oversized_port_ranges() {
        assert!(normalize_port_range(Some(PortRange { low: 100, high: 50 }), "remote").is_err());
        assert!(normalize_port_range(
            Some(PortRange {
                low: 0,
                high: 70000
            }),
            "remote"
        )
        .is_err());
        assert_eq!(
            normalize_port_range(Some(PortRange { low: 80, high: 443 }), "remote").unwrap(),
            (80, 443)
        );
        assert_eq!(normalize_port_range(None, "remote").unwrap(), (0, 0));
    }

    /// 禁用的规则不参与编译，也不占用驱动容量。
    ///  Disabled rules are not compiled and do not consume driver capacity.
    #[test]
    fn disabled_rules_are_not_compiled() {
        let mut disabled = sample_rule("block");
        disabled.enabled = false;

        let set = FirewallRuleSet {
            version: 1,
            rules: vec![sample_rule("allow"), disabled],
            ..Default::default()
        };

        let compiled = set.compile();
        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(compiled.rules[0].action, ACTION_ALLOW);
    }

    /// 单条规则出错只跳过该条，其余规则必须照常生效。
    ///  A single bad rule is skipped; every other rule must still take effect.
    #[test]
    fn bad_rule_is_skipped_without_failing_the_set() {
        let mut broken = sample_rule("allow");
        broken.rule_id = 2;
        broken.remote_address = Some("999.999.999.999/24".to_string());

        let set = FirewallRuleSet {
            version: 1,
            rules: vec![sample_rule("block"), broken],
            ..Default::default()
        };

        let compiled = set.compile();
        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(compiled.rules[0].rule_id, 1);
        assert_eq!(compiled.warnings.len(), 1);
        assert!(compiled.warnings[0].contains("rule 2"));
    }

    /// 超出驱动容量时必须截断并留下明确记录，不能静默丢弃。
    ///  Exceeding driver capacity must truncate with an explicit record.
    #[test]
    fn oversized_rule_set_is_truncated_with_a_warning() {
        let rules: Vec<FirewallRule> = (0..(NET_MAX_RULES + 5))
            .map(|i| {
                let mut r = sample_rule("allow");
                r.rule_id = i as u32;
                r
            })
            .collect();

        let set = FirewallRuleSet {
            version: 1,
            rules,
            ..Default::default()
        };

        let compiled = set.compile();
        assert_eq!(compiled.rules.len(), NET_MAX_RULES);
        assert!(compiled.warnings.iter().any(|w| w.contains("truncated")));
    }

    #[test]
    fn domain_rules_compile_and_normalize() {
        let set = FirewallRuleSet {
            version: 1,
            domain_rules: vec![FirewallDomainRule {
                rule_id: 100,
                domain: "  EVIL.example.COM  ".to_string(),
                action: "block".to_string(),
                match_type: "suffix".to_string(),
                enabled: true,
                description: String::new(),
            }],
            ..Default::default()
        };

        let compiled = set.compile();
        assert_eq!(compiled.domains.len(), 1);
        assert_eq!(compiled.domains[0].action, ACTION_BLOCK);
        assert_eq!(compiled.domains[0].match_type, DM_SUFFIX);

        let stored: String = {
            let d = &compiled.domains[0].domain;
            let end = d.iter().position(|&c| c == 0).unwrap_or(d.len());
            String::from_utf16_lossy(&d[..end])
        };
        assert_eq!(stored, "evil.example.com");
    }

    /// 域名规则只接受 allow/block；prompt 之类的动作在域名层面无从实现。
    ///  Domain rules accept only allow/block; prompt has no meaning at this layer.
    #[test]
    fn domain_rule_rejects_prompt_action() {
        let set = FirewallRuleSet {
            version: 1,
            domain_rules: vec![FirewallDomainRule {
                rule_id: 101,
                domain: "example.com".to_string(),
                action: "prompt".to_string(),
                match_type: "suffix".to_string(),
                enabled: true,
                description: String::new(),
            }],
            ..Default::default()
        };

        let compiled = set.compile();
        assert!(compiled.domains.is_empty());
        assert_eq!(compiled.warnings.len(), 1);
    }

    /// 上下行都为 0 的限速条目没有意义，不应占用驱动的限速表容量。
    ///  A limit entry with both directions zero is meaningless and must not
    ///  consume driver capacity.
    #[test]
    fn zero_rate_limits_are_not_emitted() {
        let set = FirewallRuleSet {
            version: 1,
            rate_limits: vec![
                FirewallRateLimit {
                    process_path: None,
                    bytes_per_sec_in: 0,
                    bytes_per_sec_out: 0,
                    burst_bytes: 0,
                    enabled: true,
                    description: String::new(),
                },
                FirewallRateLimit {
                    process_path: None,
                    bytes_per_sec_in: 0,
                    bytes_per_sec_out: 1024,
                    burst_bytes: 0,
                    enabled: true,
                    description: String::new(),
                },
            ],
            ..Default::default()
        };

        let compiled = set.compile();
        assert_eq!(compiled.limits.len(), 1);
        assert_eq!(compiled.limits[0].bytes_per_sec_out, 1024);
    }

    #[test]
    fn parses_json_with_camel_case_keys() {
        let json = r#"{
            "version": 3,
            "rules": [
                {
                    "ruleId": 10,
                    "name": "块 DNS 外发",
                    "action": "block",
                    "direction": "outbound",
                    "protocol": "udp",
                    "remotePortRange": { "low": 53, "high": 53 },
                    "description": "示例"
                }
            ],
            "domainRules": [
                { "ruleId": 20, "domain": "bad.example", "action": "block" }
            ],
            "rateLimits": []
        }"#;

        let set = FirewallRuleSet::from_json(json).unwrap();
        assert_eq!(set.version, 3);
        assert_eq!(set.rules.len(), 1);
        assert_eq!(set.rules[0].rule_id, 10);
        assert!(set.rules[0].enabled, "enabled should default to true");
        assert_eq!(set.domain_rules[0].match_type, "suffix");

        let compiled = set.compile();
        assert_eq!(compiled.rules.len(), 1);
        assert_eq!(compiled.rules[0].protocol, PROTO_UDP);
        assert_eq!(compiled.rules[0].remote_port_low, 53);
        assert_eq!(compiled.rules[0].remote_port_high, 53);
        assert_eq!(compiled.rules[0].flags & RF_ENABLED, RF_ENABLED);
    }

    /// 空规则文件必须产出空表，而不是报错 —— 没有规则是合法状态。
    ///  An empty rule file must compile to empty tables, not an error.
    #[test]
    fn empty_rule_set_compiles_to_empty_tables() {
        let set = FirewallRuleSet::from_json("{}").unwrap();
        let compiled = set.compile();
        assert!(compiled.rules.is_empty());
        assert!(compiled.domains.is_empty());
        assert!(compiled.limits.is_empty());
        assert!(compiled.warnings.is_empty());
    }
}
