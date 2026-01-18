#include "etw_rule_engine.h"

#include "json_reader.h"

#include <algorithm>
#include <cstring>
#include <shlwapi.h>

namespace anxin {

EtwRuleEngine::EtwRuleEngine() = default;

std::string EtwRuleEngine::toLowerAscii(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (unsigned char ch : s) {
    if (ch >= 'A' && ch <= 'Z') out.push_back(static_cast<char>(ch - 'A' + 'a'));
    else out.push_back(static_cast<char>(ch));
  }
  return out;
}

ProviderKind EtwRuleEngine::parseProvider(std::string_view s) {
  const auto x = toLowerAscii(s);
  if (x == "process") return ProviderKind::Process;
  if (x == "file") return ProviderKind::File;
  if (x == "registry") return ProviderKind::Registry;
  if (x == "network") return ProviderKind::Network;
  return ProviderKind::Unknown;
}

std::string EtwRuleEngine::keyForIndex(ProviderKind provider, const std::string& op) {
  char p = 'u';
  switch (provider) {
    case ProviderKind::Process: p = 'p'; break;
    case ProviderKind::File: p = 'f'; break;
    case ProviderKind::Registry: p = 'r'; break;
    case ProviderKind::Network: p = 'n'; break;
    default: break;
  }
  std::string out;
  out.reserve(2 + op.size());
  out.push_back(p);
  out.push_back(':');
  out += toLowerAscii(op);
  return out;
}

void EtwRuleEngine::rebuildIndex() {
  index_.clear();
  for (std::size_t i = 0; i < rules_.size(); i++) {
    const auto& r = rules_[i];
    index_[keyForIndex(r.provider, r.op)].push_back(i);
  }
}

bool EtwRuleEngine::isTracked(std::uint32_t pid) const {
  if (tracked_.empty()) return true;
  return tracked_.find(pid) != tracked_.end();
}

void EtwRuleEngine::maybeTrackChild(std::uint32_t pid, std::uint32_t ppid) {
  if (!includeChildren_) return;
  if (tracked_.empty()) return;
  if (tracked_.find(ppid) == tracked_.end()) return;
  tracked_.insert(pid);
}

void EtwRuleEngine::setContextCapacity(std::uint32_t perPidEvents) {
  contextCapacity_ = perPidEvents > 0 ? perPidEvents : 192;
  for (auto& [pid, ring] : context_) {
    if (ring.buf.size() == contextCapacity_) continue;
    ring.buf.assign(contextCapacity_, {});
    ring.next = 0;
    ring.full = false;
  }
}

int EtwRuleEngine::setTrackedPids(const std::uint32_t* pids, std::uint32_t count, bool includeChildren) {
  tracked_.clear();
  includeChildren_ = includeChildren;
  if (pids && count > 0) {
    for (std::uint32_t i = 0; i < count; i++) {
      const std::uint32_t pid = pids[i];
      tracked_.insert(pid);
    }
  }
  return static_cast<int>(tracked_.size());
}

int EtwRuleEngine::setRulesJson(std::string_view rulesJsonUtf8) {
  JsonReader r(rulesJsonUtf8);
  auto root = r.parse();
  if (!root) return -1;
  if (root->kind != JsonValue::Kind::Array) return -2;

  std::vector<Rule> parsed;
  const auto& arr = root->asArray->values;
  parsed.reserve(arr.size());

  for (const auto& item : arr) {
    if (item.kind != JsonValue::Kind::Object) continue;
    const auto* obj = item.asObject.get();
    if (!obj) continue;

    Rule rr;
    rr.ruleId = jsonAsString(jsonGet(*obj, "ruleId")).value_or("");
    rr.threatType = jsonAsString(jsonGet(*obj, "threatType")).value_or("");
    rr.recommendAction = jsonAsString(jsonGet(*obj, "recommendAction")).value_or("");
    rr.severity = static_cast<int>(jsonAsNumber(jsonGet(*obj, "severity")).value_or(3.0));

    const auto providerStr = jsonAsString(jsonGet(*obj, "provider")).value_or("");
    rr.provider = parseProvider(providerStr);
    rr.op = jsonAsString(jsonGet(*obj, "op")).value_or("");
    rr.windowMs = static_cast<std::uint32_t>(jsonAsNumber(jsonGet(*obj, "windowMs")).value_or(0.0));

    if (const auto* a = jsonAsArray(jsonGet(*obj, "targetContains"))) {
      for (const auto& v : a->values) {
        if (v.kind != JsonValue::Kind::String) continue;
        const auto s = toLowerAscii(v.asString.value);
        if (!s.empty()) rr.targetContains.push_back(s);
      }
    }
    if (const auto* a = jsonAsArray(jsonGet(*obj, "targetPrefix"))) {
      for (const auto& v : a->values) {
        if (v.kind != JsonValue::Kind::String) continue;
        auto s = toLowerAscii(v.asString.value);
        if (!s.empty()) rr.targetPrefix.push_back(std::move(s));
      }
    }
    if (const auto* a = jsonAsArray(jsonGet(*obj, "targetPattern"))) {
      for (const auto& v : a->values) {
        if (v.kind != JsonValue::Kind::String) continue;
        auto s = toLowerAscii(v.asString.value);
        if (!s.empty()) rr.targetPatterns.push_back(std::move(s));
      }
    }
    if (const auto* req = jsonAsArray(jsonGet(*obj, "requiredOps"))) {
      for (const auto& rv : req->values) {
        if (rv.kind != JsonValue::Kind::Object) continue;
        const auto* ro = rv.asObject.get();
        if (!ro) continue;
        RuleOp rop;
        rop.provider = parseProvider(jsonAsString(jsonGet(*ro, "provider")).value_or(""));
        rop.op = jsonAsString(jsonGet(*ro, "op")).value_or("");
        if (rop.provider == ProviderKind::Unknown || rop.op.empty()) continue;
        rop.op = toLowerAscii(rop.op);
        rr.requiredOps.push_back(std::move(rop));
      }
    }

    if (rr.ruleId.empty()) continue;
    if (rr.provider == ProviderKind::Unknown) continue;
    if (rr.op.empty()) continue;
    rr.op = toLowerAscii(rr.op);
    if (rr.threatType.empty()) rr.threatType = rr.ruleId;
    if (rr.recommendAction.empty()) rr.recommendAction = "block";
    if (rr.severity < 1) rr.severity = 1;
    if (rr.severity > 5) rr.severity = 5;

    parsed.push_back(std::move(rr));
  }

  rules_ = std::move(parsed);
  rebuildIndex();
  seenOps_.clear();
  return static_cast<int>(rules_.size());
}

void EtwRuleEngine::pushContext(const EtwEventInput& ev) {
  if (!isTracked(ev.pid)) return;
  auto it = context_.find(ev.pid);
  if (it == context_.end()) {
    ContextRing ring;
    ring.buf.assign(contextCapacity_, {});
    ring.next = 0;
    ring.full = false;
    it = context_.insert({ev.pid, std::move(ring)}).first;
  }
  auto& ring = it->second;
  EtwContextItem item;
  item.tsMs = ev.tsMs;
  item.provider = ev.provider;
  item.op = ev.op;
  item.target = ev.target;
  ring.buf[ring.next] = std::move(item);
  ring.next = (ring.next + 1) % ring.buf.size();
  if (ring.next == 0) ring.full = true;
}

std::vector<EtwContextItem> EtwRuleEngine::snapshotContext(std::uint32_t pid) const {
  std::vector<EtwContextItem> out;
  const auto it = context_.find(pid);
  if (it == context_.end()) return out;
  const auto& ring = it->second;
  const std::size_t cap = ring.buf.size();
  if (cap == 0) return out;
  const std::size_t limit = std::min<std::size_t>(100, cap);
  if (!ring.full) {
    const std::size_t n = std::min<std::size_t>(ring.next, limit);
    out.reserve(n);
    const std::size_t start = ring.next >= n ? (ring.next - n) : 0;
    for (std::size_t i = start; i < ring.next; i++) out.push_back(ring.buf[i]);
    return out;
  }
  out.reserve(limit);
  const std::size_t start = (ring.next + cap - limit) % cap;
  for (std::size_t i = 0; i < limit; i++) {
    const std::size_t idx = (start + i) % cap;
    out.push_back(ring.buf[idx]);
  }
  return out;
}

bool EtwRuleEngine::matchRule(const Rule& r, const EtwEventInput& ev, std::vector<std::string>& evidence) {
  if (r.provider != ev.provider) return false;
  if (r.op != ev.op) return false;
  const auto targetLower = toLowerAscii(ev.target);
  for (const auto& pre : r.targetPrefix) {
    if (pre.empty()) continue;
    if (targetLower.rfind(pre, 0) == 0) {
      evidence.push_back(std::string("targetPrefix:") + pre);
      return true;
    }
  }
  for (const auto& pat : r.targetPatterns) {
    if (pat.empty()) continue;
    if (::PathMatchSpecA(targetLower.c_str(), pat.c_str())) {
      evidence.push_back(std::string("targetPattern:") + pat);
      return true;
    }
  }
  for (const auto& c : r.targetContains) {
    if (c.empty()) continue;
    if (targetLower.find(c) == std::string::npos) return false;
  }
  if (!r.targetContains.empty()) {
    for (const auto& c : r.targetContains) evidence.push_back(std::string("targetContains:") + c);
  }
  if (!r.targetPrefix.empty()) {
    for (const auto& pre : r.targetPrefix) evidence.push_back(std::string("targetPrefix:") + pre);
  }
  if (!r.targetPatterns.empty()) {
    for (const auto& pat : r.targetPatterns) evidence.push_back(std::string("targetPattern:") + pat);
  }
  if (r.targetContains.empty() && r.targetPrefix.empty() && r.targetPatterns.empty()) evidence.push_back("basic");
  return true;
}

bool EtwRuleEngine::matchWindowRule(const Rule& r, const EtwEventInput& ev, std::vector<std::string>& evidence) {
  if (!matchRule(r, ev, evidence)) return false;
  if (r.requiredOps.empty() || r.windowMs == 0) return true;
  const auto it = seenOps_.find(ev.pid);
  if (it == seenOps_.end()) return false;
  const auto& seen = it->second;
  for (const auto& rop : r.requiredOps) {
    const auto key = keyForIndex(rop.provider, rop.op);
    const auto sit = seen.find(key);
    if (sit == seen.end()) return false;
    const auto t = sit->second;
    if (t == 0 || ev.tsMs < t || (ev.tsMs - t) > r.windowMs) return false;
  }
  evidence.push_back("windowed");
  return true;
}

std::optional<EtwMatchResult> EtwRuleEngine::onEvent(const EtwEventInput& evIn) {
  EtwEventInput ev = evIn;
  ev.op = toLowerAscii(ev.op);

  if (ev.provider == ProviderKind::Process && ev.ppid > 0) {
    parent_[ev.pid] = ev.ppid;
    maybeTrackChild(ev.pid, ev.ppid);
  }

  {
    auto& seen = seenOps_[ev.pid];
    const auto key = keyForIndex(ev.provider, ev.op);
    seen[key] = ev.tsMs;
    if (seen.size() > 256) {
      const std::uint64_t cutoff = ev.tsMs > 60000 ? (ev.tsMs - 60000) : 0;
      for (auto it = seen.begin(); it != seen.end();) {
        if (it->second < cutoff) it = seen.erase(it);
        else ++it;
      }
    }
  }

  pushContext(ev);
  if (!isTracked(ev.pid)) return std::nullopt;

  const auto idxKey = keyForIndex(ev.provider, ev.op);
  const auto it = index_.find(idxKey);
  if (it == index_.end()) return std::nullopt;

  for (const auto ridx : it->second) {
    if (ridx >= rules_.size()) continue;
    const auto& rule = rules_[ridx];
    std::vector<std::string> evidence;
    if (!matchWindowRule(rule, ev, evidence)) continue;
    EtwMatchResult out;
    out.ruleId = rule.ruleId;
    out.threatType = rule.threatType;
    out.severity = rule.severity;
    out.recommendAction = rule.recommendAction;
    out.evidence = std::move(evidence);
    out.context = snapshotContext(ev.pid);
    return out;
  }
  return std::nullopt;
}

}  // namespace anxin
