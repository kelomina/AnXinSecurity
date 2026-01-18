#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace anxin {

enum class ProviderKind : std::uint8_t { Process, File, Registry, Network, Unknown };

struct EtwEventInput {
  std::uint64_t tsMs{0};
  std::uint32_t pid{0};
  std::uint32_t ppid{0};
  ProviderKind provider{ProviderKind::Unknown};
  std::string op;
  std::string target;
  std::string target2;
  std::string processImage;
};

struct EtwContextItem {
  std::uint64_t tsMs{0};
  ProviderKind provider{ProviderKind::Unknown};
  std::string op;
  std::string target;
};

struct EtwMatchResult {
  std::string ruleId;
  std::string threatType;
  int severity{3};
  std::string recommendAction;
  std::vector<std::string> evidence;
  std::vector<EtwContextItem> context;
};

class EtwRuleEngine {
 public:
  EtwRuleEngine();

  int setRulesJson(std::string_view rulesJsonUtf8);
  int setTrackedPids(const std::uint32_t* pids, std::uint32_t count, bool includeChildren);
  void setContextCapacity(std::uint32_t perPidEvents);

  std::optional<EtwMatchResult> onEvent(const EtwEventInput& ev);

 private:
  struct RuleOp {
    ProviderKind provider{ProviderKind::Unknown};
    std::string op;
  };

  struct Rule {
    std::string ruleId;
    std::string threatType;
    int severity{3};
    std::string recommendAction;
    ProviderKind provider{ProviderKind::Unknown};
    std::string op;
    std::vector<std::string> targetContains;
    std::vector<std::string> targetPrefix;
    std::vector<std::string> targetPatterns;
    std::uint32_t windowMs{0};
    std::vector<RuleOp> requiredOps;
  };

  struct ContextRing {
    std::vector<EtwContextItem> buf;
    std::size_t next{0};
    bool full{false};
  };

  struct RuleWindowState {
    std::uint64_t windowStartMs{0};
    std::uint64_t lastUpdateMs{0};
    std::unordered_set<std::string> seenOps;
  };

  std::vector<Rule> rules_;
  std::unordered_map<std::string, std::vector<std::size_t>> index_;
  std::unordered_set<std::uint32_t> tracked_;
  std::unordered_map<std::uint32_t, std::uint32_t> parent_;
  bool includeChildren_{false};
  std::uint32_t contextCapacity_{192};
  std::unordered_map<std::uint32_t, ContextRing> context_;
  std::unordered_map<std::uint32_t, std::unordered_map<std::string, std::uint64_t>> seenOps_;

  static ProviderKind parseProvider(std::string_view s);
  static std::string toLowerAscii(std::string_view s);
  static std::string keyForIndex(ProviderKind provider, const std::string& op);
  void rebuildIndex();
  bool isTracked(std::uint32_t pid) const;
  void maybeTrackChild(std::uint32_t pid, std::uint32_t ppid);
  void pushContext(const EtwEventInput& ev);
  std::vector<EtwContextItem> snapshotContext(std::uint32_t pid) const;
  bool matchRule(const Rule& r, const EtwEventInput& ev, std::vector<std::string>& evidence);
  bool matchWindowRule(const Rule& r, const EtwEventInput& ev, std::vector<std::string>& evidence);
};

}  // namespace anxin

