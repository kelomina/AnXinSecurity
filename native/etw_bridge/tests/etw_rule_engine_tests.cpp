#include "etw_rule_engine.h"
#include "json_reader.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using anxin::EtwEventInput;
using anxin::EtwRuleEngine;
using anxin::ProviderKind;

static int expect(bool cond) {
  return cond ? 0 : 1;
}

static std::uint64_t nowMs() {
  return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count());
}

int main() {
  EtwRuleEngine eng;
  const std::string rules = R"([
    {"ruleId":"r1","provider":"File","op":"Create","severity":4,"threatType":"Dropper","recommendAction":"block",
      "targetContains":["\\temp\\"]},
    {"ruleId":"r3","provider":"File","op":"Rename","severity":5,"threatType":"RenameTest","recommendAction":"block",
      "targetPatterns":["*\\anxin_rule_test_trigger.bin"]},
    {"ruleId":"r2","provider":"Network","op":"Connect","severity":5,"threatType":"C2","recommendAction":"block",
      "windowMs":5000,
      "requiredOps":[{"provider":"File","op":"Create"},{"provider":"Registry","op":"SetValue"}]}
  ])";
  {
    anxin::JsonReader r(rules);
    auto root = r.parse();
    if (!root) {
      std::fprintf(stderr, "json_parse_error:%s\n", r.lastError().c_str());
      return 101;
    }
    if (root->kind != anxin::JsonValue::Kind::Array) return 102;
    if (!root->asArray) return 103;
    if (root->asArray->values.size() != 3) return 104;
    if (root->asArray->values[0].kind != anxin::JsonValue::Kind::Object) return 105;
    const auto* obj = root->asArray->values[0].asObject.get();
    if (!obj) return 106;
    if (!anxin::jsonGet(*obj, "ruleId")) return 107;
  }
  if (expect(eng.setRulesJson(rules) == 3) != 0) return 1;
  eng.setContextCapacity(8);

  const auto t0 = nowMs();
  {
    EtwEventInput ev;
    ev.tsMs = t0;
    ev.pid = 123;
    ev.provider = ProviderKind::File;
    ev.op = "Create";
    ev.target = "C:\\\\Temp\\\\a.bin";
    const auto m = eng.onEvent(ev);
    if (expect(m.has_value()) != 0) return 2;
    if (expect(m->ruleId == "r1") != 0) return 3;
    if (expect(m->severity == 4) != 0) return 4;
    if (expect(!m->context.empty()) != 0) return 5;
  }

  {
    EtwEventInput ev1;
    ev1.tsMs = t0 + 10;
    ev1.pid = 200;
    ev1.provider = ProviderKind::File;
    ev1.op = "Create";
    ev1.target = "C:\\\\Users\\\\u\\\\AppData\\\\Local\\\\Temp\\\\x.dll";
    eng.onEvent(ev1);

    EtwEventInput ev2;
    ev2.tsMs = t0 + 30;
    ev2.pid = 200;
    ev2.provider = ProviderKind::Registry;
    ev2.op = "SetValue";
    ev2.target = "HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run";
    eng.onEvent(ev2);

    EtwEventInput ev3;
    ev3.tsMs = t0 + 60;
    ev3.pid = 200;
    ev3.provider = ProviderKind::Network;
    ev3.op = "Connect";
    ev3.target = "TCP 8.8.8.8:443";
    const auto m = eng.onEvent(ev3);
    if (expect(m.has_value()) != 0) return 6;
    if (expect(m->ruleId == "r2") != 0) return 7;
  }

  {
    EtwEventInput ev;
    ev.tsMs = t0 + 80;
    ev.pid = 400;
    ev.provider = ProviderKind::File;
    ev.op = "Rename";
    ev.target = "C:\\\\Temp\\\\old.bin";
    ev.target2 = "C:\\\\Temp\\\\anxin_rule_test_trigger.bin";
    const auto m = eng.onEvent(ev);
    if (expect(m.has_value()) != 0) return 10;
    if (expect(m->ruleId == "r3") != 0) return 11;
  }

  {
    const std::uint64_t start = nowMs();
    std::uint64_t matches = 0;
    for (std::uint32_t i = 0; i < 200000; i++) {
      EtwEventInput ev;
      ev.tsMs = t0 + 100 + i;
      ev.pid = 300;
      ev.provider = ProviderKind::File;
      ev.op = "Create";
      ev.target = (i % 16 == 0) ? "C:\\\\Temp\\\\hit.bin" : "C:\\\\Windows\\\\System32\\\\a.dll";
      const auto m = eng.onEvent(ev);
      if (m) matches++;
    }
    const std::uint64_t elapsed = nowMs() - start;
    if (expect(elapsed > 0) != 0) return 8;
    if (expect(matches > 0) != 0) return 9;
  }

  return 0;
}
