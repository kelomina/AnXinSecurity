#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace anxin {

struct JsonString {
  std::string value;
};

struct JsonNumber {
  double value{0.0};
};

struct JsonBool {
  bool value{false};
};

struct JsonNull {};

struct JsonArray;
struct JsonObject;

struct JsonValue {
  enum class Kind { Null, Bool, Number, String, Array, Object };
  Kind kind{Kind::Null};
  JsonNull asNull{};
  JsonBool asBool{};
  JsonNumber asNumber{};
  JsonString asString{};
  std::unique_ptr<JsonArray> asArray;
  std::unique_ptr<JsonObject> asObject;

  JsonValue() = default;
  JsonValue(JsonValue&&) noexcept = default;
  JsonValue& operator=(JsonValue&&) noexcept = default;
  JsonValue(const JsonValue&) = delete;
  JsonValue& operator=(const JsonValue&) = delete;
  ~JsonValue();
};

struct JsonArray {
  std::vector<JsonValue> values;
};

struct JsonObjectItem {
  std::string key;
  JsonValue value;
};

struct JsonObject {
  std::vector<JsonObjectItem> items;
};

inline JsonValue::~JsonValue() = default;

class JsonReader {
 public:
  explicit JsonReader(std::string_view input);
  std::optional<JsonValue> parse();
  std::string lastError() const;

 private:
  const char* p_{nullptr};
  const char* end_{nullptr};
  std::string error_;

  void setError(std::string msg);
  void skipWs();
  bool consume(char c);
  bool peek(char c) const;

  std::optional<JsonValue> parseValue();
  std::optional<JsonValue> parseObject();
  std::optional<JsonValue> parseArray();
  std::optional<JsonValue> parseString();
  std::optional<JsonValue> parseNumber();
  std::optional<JsonValue> parseTrue();
  std::optional<JsonValue> parseFalse();
  std::optional<JsonValue> parseNull();

  static int hexVal(char c);
  static bool isDigit(char c);
};

const JsonValue* jsonGet(const JsonObject& obj, const std::string_view key);
std::optional<std::string> jsonAsString(const JsonValue* v);
std::optional<double> jsonAsNumber(const JsonValue* v);
std::optional<bool> jsonAsBool(const JsonValue* v);
const JsonObject* jsonAsObject(const JsonValue* v);
const JsonArray* jsonAsArray(const JsonValue* v);

}  // namespace anxin

