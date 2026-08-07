use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::parser::ParsedEvent;

const DEFAULT_CONTEXT_CAPACITY: usize = 192;
const DEFAULT_RULE_CONFIG_PATHS: [&str; 2] = [
    "config/etw_match_rules.json",
    "../config/etw_match_rules.json",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    Process,
    Thread,
    Image,
    File,
    Registry,
    Network,
    Unknown,
}

impl ProviderKind {
    fn name(&self) -> &'static str {
        match self {
            ProviderKind::Process => "Process",
            ProviderKind::Thread => "Thread",
            ProviderKind::Image => "Image",
            ProviderKind::File => "File",
            ProviderKind::Registry => "Registry",
            ProviderKind::Network => "Network",
            ProviderKind::Unknown => "Unknown",
        }
    }

    fn key_char(&self) -> char {
        match self {
            ProviderKind::Process => 'p',
            ProviderKind::Thread => 't',
            ProviderKind::Image => 'i',
            ProviderKind::File => 'f',
            ProviderKind::Registry => 'r',
            ProviderKind::Network => 'n',
            ProviderKind::Unknown => 'u',
        }
    }

    fn from_config_name(provider: &str) -> Option<Self> {
        match provider.trim().to_ascii_lowercase().as_str() {
            "process" => Some(ProviderKind::Process),
            "thread" => Some(ProviderKind::Thread),
            "image" | "module" => Some(ProviderKind::Image),
            "file" => Some(ProviderKind::File),
            "registry" => Some(ProviderKind::Registry),
            "network" => Some(ProviderKind::Network),
            "unknown" => Some(ProviderKind::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MatchedEvent {
    pub rule_id: String,
    pub threat_type: String,
    pub severity: i32,
    pub recommend_action: String,
    pub description: String,
    pub provider: String,
    pub op: String,
    pub path: String,
    pub evidence: Vec<String>,
    pub context: Vec<ContextItem>,
    pub pid: u32,
    pub ts_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContextItem {
    pub ts_ms: u64,
    pub provider: String,
    pub op: String,
    pub target: String,
}

struct RuleOp {
    provider: ProviderKind,
    op: String,
}

struct Rule {
    rule_id: String,
    threat_type: String,
    severity: i32,
    recommend_action: String,
    description: String,
    provider: ProviderKind,
    op: String,
    target_contains: Vec<String>,
    target_prefix: Vec<String>,
    target_patterns: Vec<String>,
    window_ms: u32,
    required_ops: Vec<RuleOp>,
}

struct ContextRing {
    buf: Vec<ContextItem>,
    next: usize,
    full: bool,
}

impl ContextRing {
    fn new(capacity: usize) -> Self {
        Self {
            buf: vec![
                ContextItem {
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

    fn push(&mut self, item: ContextItem) {
        self.buf[self.next] = item;
        self.next += 1;
        if self.next >= self.buf.len() {
            self.next = 0;
            self.full = true;
        }
    }

    fn snapshot(&self) -> Vec<ContextItem> {
        if !self.full {
            return self.buf[..self.next].to_vec();
        }
        let mut result = self.buf[self.next..].to_vec();
        result.extend_from_slice(&self.buf[..self.next]);
        result
    }

    /// 环内是否存在 `[start_ms, end_ms]` 区间中匹配指定 provider/op 的事件。
    ///  Whether the ring holds an event matching the given provider/op within `[start_ms, end_ms]`.
    ///
    /// 直接扫描底层缓冲区，不做 snapshot 克隆——本函数在 ETW 回调线程上按
    /// 「规则 × 先决条件」的次数调用，克隆 192 项上下文的代价不可接受。
    ///  Scans the backing buffer directly instead of cloning a snapshot: this runs on the ETW
    ///  callback thread once per (rule × required op), where cloning 192 context items would be
    ///  unacceptable.
    fn contains_op_within(&self, provider: &str, op: &str, start_ms: u64, end_ms: u64) -> bool {
        let len = if self.full { self.buf.len() } else { self.next };
        self.buf[..len].iter().any(|item| {
            item.ts_ms >= start_ms
                && item.ts_ms <= end_ms
                && item.provider.eq_ignore_ascii_case(provider)
                && normalize_op_name(&item.op) == op
        })
    }
}

pub struct EtwRuleEngine {
    rules: Vec<Rule>,
    index: HashMap<String, Vec<usize>>,
    tracked: std::collections::HashSet<u32>,
    include_children: bool,
    context_capacity: usize,
    contexts: HashMap<u32, ContextRing>,
    // 时间窗口判定已改为直接查询 per-PID 上下文环（见 match_window_rule），
    // 原先的 per-(pid, ruleId) seen 集合是失效实现，已移除以免误导后续维护者。
    //  Window matching now queries the per-PID context ring directly (see match_window_rule);
    //  the old per-(pid, ruleId) seen set was the broken implementation and has been removed.
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleConfig {
    rule_id: String,
    provider: String,
    op: String,
    severity: i32,
    threat_type: String,
    recommend_action: Option<String>,
    description: Option<String>,
    #[serde(default)]
    target_contains: Vec<String>,
    #[serde(default)]
    target_prefix: Vec<String>,
    #[serde(default)]
    target_patterns: Vec<String>,
    #[serde(default)]
    window_ms: u32,
    #[serde(default)]
    required_ops: Vec<RuleOpConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuleOpConfig {
    provider: String,
    op: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RuleConfigDocument {
    List(Vec<RuleConfig>),
    Object { rules: Vec<RuleConfig> },
}

impl EtwRuleEngine {
    /// 函数名称：new
    /// 函数作用：创建生产使用的 ETW 规则引擎，优先从默认配置文件加载规则；配置缺失或损坏时明确记录并回退为空规则。
    /// Purpose: Creates the production ETW rule engine, preferring default config rules; missing or broken config is logged and falls back to empty rules.
    /// 调用方：EtwSession::new。
    /// Called by: EtwSession::new.
    /// 被调用方：EtwRuleEngine::from_default_config、EtwRuleEngine::empty。
    /// Calls: EtwRuleEngine::from_default_config, EtwRuleEngine::empty.
    /// 返回值说明：成功加载配置时返回带规则的引擎；加载失败时返回空引擎，避免 ETW 会话启动中断。
    /// Returns: Config-backed engine on success; empty engine on load failure so ETW session startup is not interrupted.
    /// 错误处理：配置读取/解析错误写入 stderr，调用方可继续接收普通 ETW 事件。
    /// Error handling: Writes config read/parse errors to stderr; callers can still receive normal ETW events.
    /// 中文关键词：ETW规则加载，配置回退，规则引擎初始化
    /// English keywords: ETW rule loading, config fallback, rule engine initialization
    pub fn new() -> Self {
        match Self::from_default_config() {
            Ok(engine) => {
                eprintln!(
                    "[EtwRuleEngine] Loaded {} ETW rule(s) from default config",
                    engine.rule_count()
                );
                engine
            }
            Err(err) => {
                eprintln!(
                    "[EtwRuleEngine] Failed to load ETW rules from default config: {}. Rule matching disabled until config is fixed.",
                    err
                );
                Self::empty()
            }
        }
    }

    /// 函数名称：empty
    /// 函数作用：创建显式空规则引擎，仅用于测试或配置加载失败后的安全回退。
    /// Purpose: Creates an explicitly empty rule engine, used only by tests or safe fallback after config load failure.
    /// 中文关键词：空规则，引擎回退，测试入口
    /// English keywords: empty rules, engine fallback, test entry
    pub fn empty() -> Self {
        Self {
            rules: Vec::new(),
            index: HashMap::new(),
            tracked: HashSet::new(),
            include_children: false,
            context_capacity: DEFAULT_CONTEXT_CAPACITY,
            contexts: HashMap::new(),
        }
    }

    /// 函数名称：from_default_config
    /// 函数作用：按运行目录和可执行文件目录候选路径加载默认 ETW 规则配置。
    /// Purpose: Loads the default ETW rule config from working-directory and executable-directory candidates.
    /// 调用方：EtwRuleEngine::new，规则加载测试。
    /// Called by: EtwRuleEngine::new, rule loading tests.
    /// 被调用方：default_rule_config_paths、EtwRuleEngine::from_config_path。
    /// Calls: default_rule_config_paths, EtwRuleEngine::from_config_path.
    /// 返回值说明：找到并成功解析配置时返回规则引擎；未找到或解析失败返回 String。
    /// Returns: Rule engine when config is found and parsed; String when missing or invalid.
    /// 中文关键词：默认规则配置，路径解析，生产入口
    /// English keywords: default rule config, path resolution, production entry
    pub fn from_default_config() -> Result<Self, String> {
        let mut tried_paths = Vec::new();

        for config_path in default_rule_config_paths() {
            tried_paths.push(config_path.display().to_string());
            if config_path.exists() {
                return Self::from_config_path(&config_path);
            }
        }

        Err(format!(
            "ETW rule config not found. Tried: {}",
            tried_paths.join(", ")
        ))
    }

    /// 函数名称：from_config_path
    /// 函数作用：从指定 JSON 文件加载 ETW 匹配规则，并构建 provider/op 索引。
    /// Purpose: Loads ETW match rules from a JSON file and builds the provider/op index.
    /// 调用方：EtwRuleEngine::from_default_config，规则加载测试。
    /// Called by: EtwRuleEngine::from_default_config, rule loading tests.
    /// 被调用方：fs::read_to_string、serde_json::from_str、EtwRuleEngine::from_rule_configs。
    /// Calls: fs::read_to_string, serde_json::from_str, EtwRuleEngine::from_rule_configs.
    /// 参数说明：config_path 为 etw_match_rules.json 或同结构测试配置路径。
    /// Parameters: config_path is etw_match_rules.json or a test config with the same shape.
    /// 返回值说明：成功返回规则引擎；文件读取、JSON 解析或规则字段校验失败返回 String。
    /// Returns: Rule engine on success; String on file read, JSON parse, or rule validation failure.
    /// 错误处理：坏配置不会被吞掉，错误消息包含配置路径，方便定位。
    /// Error handling: Invalid config is not swallowed; error includes the config path for diagnosis.
    /// 中文关键词：规则配置加载，JSON解析，规则索引，安全失败
    /// English keywords: rule config loading, JSON parsing, rule index, safe failure
    pub fn from_config_path<P: AsRef<Path>>(config_path: P) -> Result<Self, String> {
        let path = config_path.as_ref();
        let content = fs::read_to_string(path)
            .map_err(|err| format!("Failed to read ETW rule config {}: {}", path.display(), err))?;
        let document: RuleConfigDocument = serde_json::from_str(&content).map_err(|err| {
            format!(
                "Failed to parse ETW rule config {}: {}",
                path.display(),
                err
            )
        })?;
        let configs = match document {
            RuleConfigDocument::List(rules) => rules,
            RuleConfigDocument::Object { rules } => rules,
        };

        Self::from_rule_configs(configs)
    }

    /// 函数名称：rule_count
    /// 函数作用：返回当前已加载规则数量，供测试和诊断确认配置是否生效。
    /// Purpose: Returns loaded rule count for tests and diagnostics to confirm config effectiveness.
    /// 中文关键词：规则数量，配置诊断
    /// English keywords: rule count, config diagnostics
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 函数名称：on_event
    /// 函数作用：处理一个解析后的事件，执行规则匹配。返回匹配结果。
    /// Purpose: Processes a parsed event and applies rule matching. Returns match result.
    /// 调用方：session callback (每收到一个 ETW 事件时)
    /// Called by: session callback (on each ETW event received)
    /// 中文关键词：事件处理，规则匹配，威胁检测，事件分析
    /// English keywords: event processing, rule matching, threat detection, event analysis
    pub fn on_event(&mut self, ev: &ParsedEvent) -> Option<MatchedEvent> {
        let pid = ev.pid;
        let ppid = ev.ppid;

        // 如果事件父 PID 是被追踪的，且开启了子进程追踪，自动追踪子进程
        if self.include_children && !self.tracked.is_empty() && self.tracked.contains(&ppid) {
            self.tracked.insert(pid);
        }

        if !self.is_tracked(pid) {
            return None;
        }

        // 更新上下文
        self.push_context(ev);

        let key = index_key(ev.provider, &ev.op);
        // Clone rule indices to break the borrow
        let rule_indices: Vec<usize> = self.index.get(&key).cloned().unwrap_or_default();
        let mut best: Option<MatchedEvent> = None;
        for idx in rule_indices {
            // Clone rule data to avoid borrow conflicts
            let rule_id = self.rules[idx].rule_id.clone();
            let threat_type = self.rules[idx].threat_type.clone();
            let severity = self.rules[idx].severity;
            let recommend_action = self.rules[idx].recommend_action.clone();
            let description = self.rules[idx].description.clone();
            let provider_name = self.rules[idx].provider.name().to_string();
            let op = ev.op.clone();
            let window_ms = self.rules[idx].window_ms;
            let has_required_ops = !self.rules[idx].required_ops.is_empty();
            let path = event_primary_target(ev);

            let mut evidence: Vec<String> = Vec::new();

            let matched = if window_ms > 0 && has_required_ops {
                self.match_window_rule(idx, ev, &mut evidence)
            } else {
                self.match_rule_by_idx(idx, ev, &mut evidence)
            };

            if matched {
                let result = MatchedEvent {
                    rule_id,
                    threat_type,
                    severity,
                    recommend_action,
                    description,
                    provider: provider_name,
                    op,
                    path,
                    evidence,
                    context: self.snapshot_context(pid),
                    pid,
                    ts_ms: ev.ts_ms,
                };
                if best.as_ref().map_or(true, |b| result.severity > b.severity) {
                    best = Some(result);
                }
            }
        }
        best
    }

    fn is_tracked(&self, pid: u32) -> bool {
        if self.tracked.is_empty() {
            true
        } else {
            self.tracked.contains(&pid)
        }
    }

    fn push_context(&mut self, ev: &ParsedEvent) {
        let ring = self
            .contexts
            .entry(ev.pid)
            .or_insert_with(|| ContextRing::new(self.context_capacity));
        ring.push(ContextItem {
            ts_ms: ev.ts_ms,
            provider: ev.provider.name().to_string(),
            op: ev.op.clone(),
            target: ev.target.clone(),
        });
    }

    fn snapshot_context(&self, pid: u32) -> Vec<ContextItem> {
        self.contexts
            .get(&pid)
            .map(|r| r.snapshot().into_iter().take(100).collect())
            .unwrap_or_default()
    }

    fn match_rule_by_idx(&self, idx: usize, ev: &ParsedEvent, evidence: &mut Vec<String>) -> bool {
        if idx >= self.rules.len() {
            return false;
        }
        let rule = &self.rules[idx];
        let target_lower = normalize_str(&ev.target);
        if !rule.target_contains.is_empty() {
            if !rule
                .target_contains
                .iter()
                .any(|tc| target_lower.contains(tc.as_str()))
            {
                return false;
            }
            evidence.push(format!("target contains: {}", target_lower));
        }
        if !rule.target_prefix.is_empty() {
            if !rule
                .target_prefix
                .iter()
                .any(|tp| target_lower.starts_with(tp.as_str()))
            {
                return false;
            }
            evidence.push(format!("target prefix: {}", target_lower));
        }
        if !rule.target_patterns.is_empty() {
            if !rule
                .target_patterns
                .iter()
                .any(|pat| simple_wildcard_match(pat, &target_lower))
            {
                return false;
            }
            evidence.push(format!("target pattern: {}", target_lower));
        }
        true
    }

    fn match_window_rule(
        &mut self,
        idx: usize,
        ev: &ParsedEvent,
        evidence: &mut Vec<String>,
    ) -> bool {
        if !self.match_rule_by_idx(idx, ev, evidence) {
            return false;
        }
        let window_ms = self.rules[idx].window_ms;
        let required_ops: Vec<(String, String)> = self.rules[idx]
            .required_ops
            .iter()
            .map(|ro| (ro.provider.name().to_string(), ro.op.clone()))
            .collect();
        let now = ev.ts_ms;
        let window_start = now.saturating_sub(window_ms as u64);

        // 先决事件从该 PID 的上下文环里查。上下文环由 push_context 对**每一个**事件写入，
        // 与规则是否命中无关，因此能真实反映窗口内发生过什么。
        //
        // 修复前这里用的是一个 per-(pid, ruleId) 的 `seen` 集合，但集合里只会被插入常量
        // "_event"，而判定查的是 "{provider}:{op}" 形式的键，导致 requiredOps 非空时
        // all_required 恒为 false —— 所有时间窗口规则永远不可能命中，文档宣传的行为链
        // 关联能力实际是死特性。
        //  Prerequisites are looked up in this PID's context ring, which push_context fills for
        //  *every* event regardless of rule matching, so it truly reflects what happened in the
        //  window. The previous implementation used a per-(pid, ruleId) `seen` set that only ever
        //  received the constant "_event" while the check looked for "{provider}:{op}" keys, so
        //  all_required was permanently false and every windowed rule was dead code.
        let history = self.contexts.get(&ev.pid);
        let all_required = required_ops.iter().all(|(provider, op)| {
            history.is_some_and(|ring| ring.contains_op_within(provider, op, window_start, now))
        });

        if all_required {
            evidence.push(format!("window match: {}ms", window_ms));
            for (provider, op) in &required_ops {
                evidence.push(format!("required op satisfied: {}/{}", provider, op));
            }
        }
        all_required
    }

    fn from_rule_configs(configs: Vec<RuleConfig>) -> Result<Self, String> {
        let mut engine = Self::empty();
        let mut rules = Vec::with_capacity(configs.len());

        for (idx, config) in configs.into_iter().enumerate() {
            rules.push(rule_from_config(idx, config)?);
        }

        engine.rules = rules;
        engine.index = build_rule_index(&engine.rules);
        Ok(engine)
    }
}

/// 函数名称：rule_from_config
/// 函数作用：将外部 JSON 规则配置转换为内部强类型规则，并校验必填字段、规范化严重程度。
/// Purpose: Converts external JSON rule config into an internal typed rule, validates required fields, and normalizes severity.
/// 中文关键词：规则转换，字段校验，配置规范化，严重程度映射
/// English keywords: rule conversion, field validation, config normalization, severity mapping
fn rule_from_config(idx: usize, config: RuleConfig) -> Result<Rule, String> {
    let rule_id = require_non_empty(config.rule_id, idx, "ruleId")?;
    let provider = ProviderKind::from_config_name(&config.provider).ok_or_else(|| {
        format!(
            "Invalid ETW rule provider at index {} ruleId={}: {}",
            idx, rule_id, config.provider
        )
    })?;
    let op = normalize_op_name(&config.op);
    if op.is_empty() {
        return Err(format!(
            "Invalid ETW rule op at index {} ruleId={}: operation is empty",
            idx, rule_id
        ));
    }
    if config.severity < 0 {
        return Err(format!(
            "Invalid ETW rule severity at index {} ruleId={}: severity must be >= 0",
            idx, rule_id
        ));
    }
    let severity = normalize_rule_severity(config.severity);
    let threat_type = require_non_empty(config.threat_type, idx, "threatType")?;
    let recommend_action = config
        .recommend_action
        .filter(|action| !action.trim().is_empty())
        .unwrap_or_else(|| "alert".to_string());
    let description = config
        .description
        .filter(|description| !description.trim().is_empty())
        .unwrap_or_else(|| threat_type.clone());

    let required_ops = config
        .required_ops
        .into_iter()
        .map(|required| {
            let provider = ProviderKind::from_config_name(&required.provider).ok_or_else(|| {
                format!(
                    "Invalid requiredOps provider at index {} ruleId={}: {}",
                    idx, rule_id, required.provider
                )
            })?;
            let op = normalize_op_name(&required.op);
            if op.is_empty() {
                return Err(format!(
                    "Invalid requiredOps op at index {} ruleId={}: operation is empty",
                    idx, rule_id
                ));
            }
            Ok(RuleOp { provider, op })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(Rule {
        rule_id,
        threat_type,
        severity,
        recommend_action,
        description,
        provider,
        op,
        target_contains: normalize_config_strings(config.target_contains),
        target_prefix: normalize_config_strings(config.target_prefix),
        target_patterns: normalize_config_strings(config.target_patterns),
        window_ms: config.window_ms,
        required_ops,
    })
}

/// 函数名称：normalize_rule_severity
/// 函数作用：兼容配置里的 1-5 严重度等级和 RiskService 使用的 0-100 风险分。
/// Purpose: Keeps 1-5 config severity levels compatible with RiskService's 0-100 risk score.
/// 调用方：rule_from_config。
/// Called by: rule_from_config.
/// 参数说明：severity 为配置文件中的严重程度；1-5 会映射为 20-100，其他非负值按 0-100 分保留。
/// Parameters: severity is the configured severity; 1-5 maps to 20-100 and other non-negative values stay as 0-100 scores.
/// 返回值说明：返回供 ETW 匹配事件和风险分析使用的严重程度。
/// Returns: severity used by ETW matched events and risk analysis.
/// 中文关键词：严重程度，风险分，规则配置，兼容映射
/// English keywords: severity, risk score, rule config, compatibility mapping
fn normalize_rule_severity(severity: i32) -> i32 {
    if (1..=5).contains(&severity) {
        severity * 20
    } else {
        severity
    }
}

/// 函数名称：build_rule_index
/// 函数作用：按 provider/op 为规则建立索引，减少每个 ETW 事件需要扫描的规则数量。
/// Purpose: Builds a provider/op index for rules to reduce rule scans per ETW event.
/// 中文关键词：规则索引，事件匹配，性能
/// English keywords: rule index, event matching, performance
fn build_rule_index(rules: &[Rule]) -> HashMap<String, Vec<usize>> {
    let mut index = HashMap::new();
    for (idx, rule) in rules.iter().enumerate() {
        index
            .entry(index_key(rule.provider, &rule.op))
            .or_insert_with(Vec::new)
            .push(idx);
    }
    index
}

/// 函数名称：default_rule_config_paths
/// 函数作用：返回默认 ETW 规则配置候选路径，兼容项目根目录、src-tauri 目录和可执行文件目录运行。
/// Purpose: Returns default ETW rule config candidates for project-root, src-tauri, and executable-directory runs.
/// 中文关键词：配置路径，运行目录，生产入口
/// English keywords: config path, working directory, production entry
fn default_rule_config_paths() -> Vec<PathBuf> {
    let mut paths = DEFAULT_RULE_CONFIG_PATHS
        .iter()
        .map(PathBuf::from)
        .collect::<Vec<_>>();

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            paths.push(exe_dir.join("config").join("etw_match_rules.json"));
            paths.push(
                exe_dir
                    .join("resources")
                    .join("config")
                    .join("etw_match_rules.json"),
            );
            paths.push(
                exe_dir
                    .join("..")
                    .join("config")
                    .join("etw_match_rules.json"),
            );
        }
    }

    paths
}

/// 函数名称：require_non_empty
/// 函数作用：校验配置字符串字段非空，并保留字段名和规则下标用于错误定位。
/// Purpose: Validates a config string field is non-empty and keeps field/index context for diagnostics.
/// 中文关键词：配置校验，错误定位
/// English keywords: config validation, error diagnostics
fn require_non_empty(value: String, idx: usize, field_name: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(format!(
            "Invalid ETW rule at index {}: {} is empty",
            idx, field_name
        ))
    } else {
        Ok(trimmed.to_string())
    }
}

/// 函数名称：normalize_config_strings
/// 函数作用：规范化配置中的路径/目标匹配字符串，便于与运行时事件目标比较。
/// Purpose: Normalizes path/target match strings from config for comparison with runtime event targets.
/// 中文关键词：配置字符串，路径规范化，规则匹配
/// English keywords: config strings, path normalization, rule matching
fn normalize_config_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized_values = Vec::new();

    for value in values {
        let normalized = normalize_str(value.trim());
        push_unique_config_string(&mut normalized_values, &mut seen, normalized.clone());
        push_unique_config_string(
            &mut normalized_values,
            &mut seen,
            collapse_duplicate_backslashes(&normalized),
        );
    }

    normalized_values
}

fn push_unique_config_string(values: &mut Vec<String>, seen: &mut HashSet<String>, value: String) {
    if !value.is_empty() && seen.insert(value.clone()) {
        values.push(value);
    }
}

/// 函数名称：collapse_duplicate_backslashes
/// 函数作用：把配置中重复写入的反斜杠压缩为单个反斜杠，兼容过度转义的 JSON 路径片段。
/// Purpose: Collapses duplicated backslashes from config strings to support over-escaped JSON path fragments.
/// 中文关键词：配置路径，反斜杠压缩，过度转义兼容
/// English keywords: config path, backslash collapse, over-escape compatibility
fn collapse_duplicate_backslashes(value: &str) -> String {
    let mut collapsed = String::with_capacity(value.len());
    let mut previous_was_backslash = false;

    for ch in value.chars() {
        if ch == '\\' {
            if !previous_was_backslash {
                collapsed.push(ch);
            }
            previous_was_backslash = true;
        } else {
            collapsed.push(ch);
            previous_was_backslash = false;
        }
    }

    collapsed
}

/// 函数名称：event_primary_target
/// 函数作用：从解析后的 ETW 事件中提取风险链路使用的主要目标路径或对象名。
/// Purpose: Extracts the primary target path or object name used by the risk pipeline from a parsed ETW event.
/// 中文关键词：事件目标，风险链路，路径字段
/// English keywords: event target, risk pipeline, path field
fn event_primary_target(ev: &ParsedEvent) -> String {
    if !ev.target.is_empty() {
        ev.target.clone()
    } else {
        ev.target2.clone()
    }
}

/// 函数名称：normalize_op_name
/// 函数作用：将配置和运行时操作名统一为小写 snake_case，例如 SetValue 转为 set_value。
/// Purpose: Normalizes config and runtime operation names into lowercase snake_case, for example SetValue to set_value.
/// 中文关键词：操作名规范化，驼峰转换，规则索引
/// English keywords: operation normalization, camel case conversion, rule index
fn normalize_op_name(op: &str) -> String {
    let chars = op.trim().chars().collect::<Vec<_>>();
    let mut normalized = String::with_capacity(chars.len());

    for (idx, ch) in chars.iter().enumerate() {
        if matches!(ch, '-' | ' ' | '/' | '\\' | '_') {
            push_underscore_once(&mut normalized);
            continue;
        }

        if ch.is_ascii_uppercase() {
            let prev = idx.checked_sub(1).and_then(|prev_idx| chars.get(prev_idx));
            let next = chars.get(idx + 1);
            let has_lower_prev = prev
                .map(|prev_ch| prev_ch.is_ascii_lowercase() || prev_ch.is_ascii_digit())
                .unwrap_or(false);
            let ends_acronym = prev
                .map(|prev_ch| prev_ch.is_ascii_uppercase())
                .unwrap_or(false)
                && next
                    .map(|next_ch| next_ch.is_ascii_lowercase())
                    .unwrap_or(false);

            if idx > 0 && (has_lower_prev || ends_acronym) {
                push_underscore_once(&mut normalized);
            }
            normalized.push(ch.to_ascii_lowercase());
            continue;
        }

        normalized.push(*ch);
    }

    normalized.trim_matches('_').to_string()
}

fn push_underscore_once(value: &mut String) {
    if !value.is_empty() && !value.ends_with('_') {
        value.push('_');
    }
}

fn index_key(provider: ProviderKind, op: &str) -> String {
    format!("{}:{}", provider.key_char(), normalize_op_name(op))
}

/// 函数名称：normalize_str
/// 函数作用：字符串规范化：正斜杠转反斜杠、大写转小写。
/// Purpose: Normalizes string: converts / to \\, uppercases to lowercase.
/// 中文关键词：字符串规范化，大小写转换，路径规范化
/// English keywords: string normalization, case conversion, path normalization
fn normalize_str(s: &str) -> String {
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

/// 函数名称：simple_wildcard_match
/// 函数作用：通配符匹配（支持 * 和 ?），使用 DP 算法。
/// Purpose: Simple wildcard match (supports * and ?), using DP algorithm.
/// 中文关键词：通配符匹配，DP匹配，*匹配，?匹配，模式匹配
/// English keywords: wildcard match, DP match, * match, ? match, pattern match
fn simple_wildcard_match(pattern: &str, text: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let txt: Vec<char> = text.chars().collect();
    let pn = pat.len();
    let tn = txt.len();

    // DP approach for simple wildcard (* only)
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
