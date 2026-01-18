#include "json_reader.h"

#include <cmath>
#include <cstdlib>

namespace anxin {

JsonReader::JsonReader(std::string_view input) {
  p_ = input.data();
  end_ = input.data() + input.size();
}

void JsonReader::setError(std::string msg) {
  if (!error_.empty()) return;
  error_ = std::move(msg);
}

std::string JsonReader::lastError() const {
  return error_;
}

bool JsonReader::isDigit(char c) {
  return c >= '0' && c <= '9';
}

int JsonReader::hexVal(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
  if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
  return -1;
}

void JsonReader::skipWs() {
  while (p_ < end_) {
    const char c = *p_;
    if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
      ++p_;
      continue;
    }
    break;
  }
}

bool JsonReader::peek(char c) const {
  return p_ < end_ && *p_ == c;
}

bool JsonReader::consume(char c) {
  if (!peek(c)) return false;
  ++p_;
  return true;
}

std::optional<JsonValue> JsonReader::parse() {
  skipWs();
  auto v = parseValue();
  if (!v) return std::nullopt;
  skipWs();
  if (p_ != end_) {
    setError("trailing_characters");
    return std::nullopt;
  }
  return v;
}

std::optional<JsonValue> JsonReader::parseValue() {
  skipWs();
  if (p_ >= end_) {
    setError("unexpected_eof");
    return std::nullopt;
  }
  const char c = *p_;
  if (c == '{') return parseObject();
  if (c == '[') return parseArray();
  if (c == '"') return parseString();
  if (c == '-' || isDigit(c)) return parseNumber();
  if (c == 't') return parseTrue();
  if (c == 'f') return parseFalse();
  if (c == 'n') return parseNull();
  setError("unexpected_token");
  return std::nullopt;
}

std::optional<JsonValue> JsonReader::parseNull() {
  const char* start = p_;
  if (end_ - start >= 4 && start[0] == 'n' && start[1] == 'u' && start[2] == 'l' && start[3] == 'l') {
    p_ += 4;
    JsonValue v;
    v.kind = JsonValue::Kind::Null;
    return v;
  }
  setError("invalid_null");
  return std::nullopt;
}

std::optional<JsonValue> JsonReader::parseTrue() {
  const char* start = p_;
  if (end_ - start >= 4 && start[0] == 't' && start[1] == 'r' && start[2] == 'u' && start[3] == 'e') {
    p_ += 4;
    JsonValue v;
    v.kind = JsonValue::Kind::Bool;
    v.asBool.value = true;
    return v;
  }
  setError("invalid_true");
  return std::nullopt;
}

std::optional<JsonValue> JsonReader::parseFalse() {
  const char* start = p_;
  if (end_ - start >= 5 && start[0] == 'f' && start[1] == 'a' && start[2] == 'l' && start[3] == 's' &&
      start[4] == 'e') {
    p_ += 5;
    JsonValue v;
    v.kind = JsonValue::Kind::Bool;
    v.asBool.value = false;
    return v;
  }
  setError("invalid_false");
  return std::nullopt;
}

std::optional<JsonValue> JsonReader::parseNumber() {
  const char* start = p_;
  if (p_ < end_ && *p_ == '-') ++p_;
  if (p_ >= end_) {
    setError("invalid_number");
    return std::nullopt;
  }
  if (*p_ == '0') {
    ++p_;
  } else {
    if (!isDigit(*p_)) {
      setError("invalid_number");
      return std::nullopt;
    }
    while (p_ < end_ && isDigit(*p_)) ++p_;
  }
  if (p_ < end_ && *p_ == '.') {
    ++p_;
    if (p_ >= end_ || !isDigit(*p_)) {
      setError("invalid_number");
      return std::nullopt;
    }
    while (p_ < end_ && isDigit(*p_)) ++p_;
  }
  if (p_ < end_ && (*p_ == 'e' || *p_ == 'E')) {
    ++p_;
    if (p_ < end_ && (*p_ == '+' || *p_ == '-')) ++p_;
    if (p_ >= end_ || !isDigit(*p_)) {
      setError("invalid_number");
      return std::nullopt;
    }
    while (p_ < end_ && isDigit(*p_)) ++p_;
  }
  std::string tmp(start, static_cast<std::size_t>(p_ - start));
  char* endNum = nullptr;
  const double val = std::strtod(tmp.c_str(), &endNum);
  if (!endNum || endNum == tmp.c_str() || !std::isfinite(val)) {
    setError("invalid_number");
    return std::nullopt;
  }
  JsonValue v;
  v.kind = JsonValue::Kind::Number;
  v.asNumber.value = val;
  return v;
}

std::optional<JsonValue> JsonReader::parseString() {
  if (!consume('"')) {
    setError("expected_quote");
    return std::nullopt;
  }
  std::string out;
  while (p_ < end_) {
    char c = *p_++;
    if (c == '"') {
      JsonValue v;
      v.kind = JsonValue::Kind::String;
      v.asString.value = std::move(out);
      return v;
    }
    if (static_cast<unsigned char>(c) < 0x20) {
      setError("invalid_string");
      return std::nullopt;
    }
    if (c != '\\') {
      out.push_back(c);
      continue;
    }
    if (p_ >= end_) {
      setError("invalid_escape");
      return std::nullopt;
    }
    char e = *p_++;
    switch (e) {
      case '"': out.push_back('"'); break;
      case '\\': out.push_back('\\'); break;
      case '/': out.push_back('/'); break;
      case 'b': out.push_back('\b'); break;
      case 'f': out.push_back('\f'); break;
      case 'n': out.push_back('\n'); break;
      case 'r': out.push_back('\r'); break;
      case 't': out.push_back('\t'); break;
      case 'u': {
        if (end_ - p_ < 4) {
          setError("invalid_unicode_escape");
          return std::nullopt;
        }
        int h1 = hexVal(p_[0]);
        int h2 = hexVal(p_[1]);
        int h3 = hexVal(p_[2]);
        int h4 = hexVal(p_[3]);
        if (h1 < 0 || h2 < 0 || h3 < 0 || h4 < 0) {
          setError("invalid_unicode_escape");
          return std::nullopt;
        }
        const std::uint32_t cp = static_cast<std::uint32_t>((h1 << 12) | (h2 << 8) | (h3 << 4) | h4);
        p_ += 4;
        if (cp <= 0x7F) {
          out.push_back(static_cast<char>(cp));
        } else if (cp <= 0x7FF) {
          out.push_back(static_cast<char>(0xC0 | ((cp >> 6) & 0x1F)));
          out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
          out.push_back(static_cast<char>(0xE0 | ((cp >> 12) & 0x0F)));
          out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
          out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
        break;
      }
      default:
        setError("invalid_escape");
        return std::nullopt;
    }
  }
  setError("unterminated_string");
  return std::nullopt;
}

std::optional<JsonValue> JsonReader::parseArray() {
  if (!consume('[')) {
    setError("expected_array");
    return std::nullopt;
  }
  JsonValue v;
  v.kind = JsonValue::Kind::Array;
  v.asArray = std::make_unique<JsonArray>();
  skipWs();
  if (consume(']')) return v;
  while (true) {
    auto item = parseValue();
    if (!item) return std::nullopt;
    v.asArray->values.push_back(std::move(*item));
    skipWs();
    if (consume(']')) break;
    if (!consume(',')) {
      setError("expected_comma");
      return std::nullopt;
    }
  }
  return v;
}

std::optional<JsonValue> JsonReader::parseObject() {
  if (!consume('{')) {
    setError("expected_object");
    return std::nullopt;
  }
  JsonValue v;
  v.kind = JsonValue::Kind::Object;
  v.asObject = std::make_unique<JsonObject>();
  skipWs();
  if (consume('}')) return v;
  while (true) {
    skipWs();
    auto key = parseString();
    if (!key || key->kind != JsonValue::Kind::String) {
      setError("expected_key_string");
      return std::nullopt;
    }
    skipWs();
    if (!consume(':')) {
      setError("expected_colon");
      return std::nullopt;
    }
    auto val = parseValue();
    if (!val) return std::nullopt;
    v.asObject->items.push_back(JsonObjectItem{key->asString.value, std::move(*val)});
    skipWs();
    if (consume('}')) break;
    if (!consume(',')) {
      setError("expected_comma");
      return std::nullopt;
    }
  }
  return v;
}

const JsonValue* jsonGet(const JsonObject& obj, const std::string_view key) {
  for (const auto& it : obj.items) {
    if (it.key == key) return &it.value;
  }
  return nullptr;
}

std::optional<std::string> jsonAsString(const JsonValue* v) {
  if (!v || v->kind != JsonValue::Kind::String) return std::nullopt;
  return v->asString.value;
}

std::optional<double> jsonAsNumber(const JsonValue* v) {
  if (!v || v->kind != JsonValue::Kind::Number) return std::nullopt;
  return v->asNumber.value;
}

std::optional<bool> jsonAsBool(const JsonValue* v) {
  if (!v || v->kind != JsonValue::Kind::Bool) return std::nullopt;
  return v->asBool.value;
}

const JsonObject* jsonAsObject(const JsonValue* v) {
  if (!v || v->kind != JsonValue::Kind::Object) return nullptr;
  return v->asObject.get();
}

const JsonArray* jsonAsArray(const JsonValue* v) {
  if (!v || v->kind != JsonValue::Kind::Array) return nullptr;
  return v->asArray.get();
}

}  // namespace anxin

