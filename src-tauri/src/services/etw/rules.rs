use std::collections::HashMap;

use serde::Serialize;

use super::parser::ParsedEvent;

const DEFAULT_CONTEXT_CAPACITY: usize = 192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    Process,
    File,
    Registry,
    Network,
    Unknown,
}

impl ProviderKind {
    fn name(&self) -> &'static str {
        match self {
            ProviderKind::Process => "Process",
            ProviderKind::File => "File",
            ProviderKind::Registry => "Registry",
            ProviderKind::Network => "Network",
            ProviderKind::Unknown => "Unknown",
        }
    }

    fn key_char(&self) -> char {
        match self {
            ProviderKind::Process => 'p',
            ProviderKind::File => 'f',
            ProviderKind::Registry => 'r',
            ProviderKind::Network => 'n',
            ProviderKind::Unknown => 'u',
        }
    }
}

#[derive(Debug, Clone)]
pub struct MatchedEvent {
    pub rule_id: String,
    pub threat_type: String,
    pub severity: i32,
    pub recommend_action: String,
    pub provider: String,
    pub op: String,
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
    provider: ProviderKind,
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
            buf: vec![ContextItem { ts_ms: 0, provider: String::new(), op: String::new(), target: String::new() }; capacity],
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
}

pub struct EtwRuleEngine {
    rules: Vec<Rule>,
    index: HashMap<String, Vec<usize>>,
    tracked: std::collections::HashSet<u32>,
    include_children: bool,
    context_capacity: usize,
    contexts: HashMap<u32, ContextRing>,
    window_states: HashMap<u32, HashMap<String, (u64, u64, std::collections::HashSet<String>)>>,
}

impl EtwRuleEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            index: HashMap::new(),
            tracked: std::collections::HashSet::new(),
            include_children: false,
            context_capacity: DEFAULT_CONTEXT_CAPACITY,
            contexts: HashMap::new(),
            window_states: HashMap::new(),
        }
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
            let provider_name = self.rules[idx].provider.name().to_string();
            let op = ev.op.clone();
            let window_ms = self.rules[idx].window_ms;
            let has_required_ops = !self.rules[idx].required_ops.is_empty();

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
                    provider: provider_name,
                    op,
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
        if self.tracked.is_empty() { true }
        else { self.tracked.contains(&pid) }
    }

    fn push_context(&mut self, ev: &ParsedEvent) {
        let ring = self.contexts.entry(ev.pid).or_insert_with(|| {
            ContextRing::new(self.context_capacity)
        });
        ring.push(ContextItem {
            ts_ms: ev.ts_ms,
            provider: ev.provider.name().to_string(),
            op: ev.op.clone(),
            target: ev.target.clone(),
        });
    }

    fn snapshot_context(&self, pid: u32) -> Vec<ContextItem> {
        self.contexts.get(&pid)
            .map(|r| r.snapshot().into_iter().take(100).collect())
            .unwrap_or_default()
    }

    fn match_rule_by_idx(&self, idx: usize, ev: &ParsedEvent, evidence: &mut Vec<String>) -> bool {
        if idx >= self.rules.len() { return false; }
        let rule = &self.rules[idx];
        let target_lower = normalize_str(&ev.target);
        if !rule.target_contains.is_empty() {
            if !rule.target_contains.iter().any(|tc| target_lower.contains(tc.as_str())) {
                return false;
            }
            evidence.push(format!("target contains: {}", target_lower));
        }
        if !rule.target_prefix.is_empty() {
            if !rule.target_prefix.iter().any(|tp| target_lower.starts_with(tp.as_str())) {
                return false;
            }
            evidence.push(format!("target prefix: {}", target_lower));
        }
        if !rule.target_patterns.is_empty() {
            if !rule.target_patterns.iter().any(|pat| simple_wildcard_match(pat, &target_lower)) {
                return false;
            }
            evidence.push(format!("target pattern: {}", target_lower));
        }
        true
    }

    fn match_window_rule(&mut self, idx: usize, ev: &ParsedEvent, evidence: &mut Vec<String>) -> bool {
        if !self.match_rule_by_idx(idx, ev, evidence) {
            return false;
        }
        let rule_id = self.rules[idx].rule_id.clone();
        let window_ms = self.rules[idx].window_ms;
        let required_ops: Vec<(char, String)> = self.rules[idx].required_ops.iter()
            .map(|ro| (ro.provider.key_char(), ro.op.clone()))
            .collect();
        let now = ev.ts_ms;
        let pid = ev.pid;

        let state = self.window_states.get(&pid);
        let (window_start, _last_update, seen_ops) = state.map(|s| {
            s.get(&rule_id)
        }).flatten().cloned().unwrap_or((0, 0, std::collections::HashSet::new()));

        let effective_start = if window_start > 0 && (now - window_start) <= window_ms as u64 {
            window_start
        } else {
            now
        };

        let mut seen = seen_ops;
        if effective_start == now {
            seen.clear();
        }
        seen.insert("_event".to_string());

        let all_required = required_ops.iter().all(|(pc, op)| {
            let needle = format!("{}:{}", pc, op);
            seen.contains(&needle)
        });

        self.window_states.entry(pid).or_default()
            .insert(rule_id, (effective_start, now, seen));

        if all_required {
            evidence.push(format!("window match: {}ms", window_ms));
        }
        all_required
    }
}

fn index_key(provider: ProviderKind, op: &str) -> String {
    format!("{}:{}", provider.key_char(), op.to_lowercase())
}

/// 函数名称：normalize_str
/// 函数作用：字符串规范化：正斜杠转反斜杠、大写转小写。
/// Purpose: Normalizes string: converts / to \\, uppercases to lowercase.
/// 中文关键词：字符串规范化，大小写转换，路径规范化
/// English keywords: string normalization, case conversion, path normalization
fn normalize_str(s: &str) -> String {
    s.chars().map(|c| {
        if c == '/' { '\\' }
        else if c.is_ascii_uppercase() { c.to_ascii_lowercase() }
        else { c }
    }).collect()
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
