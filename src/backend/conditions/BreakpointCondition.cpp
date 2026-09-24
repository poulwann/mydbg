#include "backend/conditions/BreakpointCondition.h"
#include "localization/Localization.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

namespace debugger::conditions {
namespace {

enum class NodeKind {
  Literal,
  Truthy,
  Not,
  And,
  Or,
  Compare,
  MaskedCompare,
  StringCompare,
};

enum class CompareOperator {
  Equal,
  NotEqual,
  Less,
  LessEqual,
  Greater,
  GreaterEqual
};

struct NumericValue {
  bool literal{};
  std::uint64_t value{};
  std::string register_name;
};

} // namespace

struct ConditionNode {
  NodeKind kind{NodeKind::Literal};
  bool literal{};
  CompareOperator comparison{CompareOperator::Equal};
  NumericValue numeric;
  NumericValue right_numeric;
  std::unique_ptr<ConditionNode> left;
  std::unique_ptr<ConditionNode> right;
  std::vector<std::uint8_t> expected;
  std::vector<std::uint8_t> mask;
  std::string text;
};

namespace {

class Parser {
public:
  explicit Parser(std::string_view source) : source_(source) {}

  std::unique_ptr<ConditionNode> parse() {
    skip_space();
    std::unique_ptr<ConditionNode> result;
    if (consume_keyword("if")) {
      if (!consume("(")) {
        fail(l10n::Key::ConditionExpectedOpenAfterIf);
        return nullptr;
      }
      result = parse_or();
      if (result != nullptr && !consume(")")) {
        fail(l10n::Key::ConditionExpectedCloseAfterCondition);
        return nullptr;
      }
    } else {
      result = parse_or();
    }
    skip_space();
    if (result != nullptr && position_ != source_.size()) {
      fail(l10n::Key::ConditionUnexpectedInput);
      return nullptr;
    }
    return result;
  }

  const std::string &error() const noexcept { return error_; }

private:
  std::unique_ptr<ConditionNode> parse_or() {
    return parse_binary(&Parser::parse_and, "||", NodeKind::Or);
  }

  std::unique_ptr<ConditionNode> parse_and() {
    return parse_binary(&Parser::parse_unary, "&&", NodeKind::And);
  }

  std::unique_ptr<ConditionNode>
  parse_binary(std::unique_ptr<ConditionNode> (Parser::*parse_operand)(),
               std::string_view token, NodeKind kind) {
    auto left = (this->*parse_operand)();
    while (left != nullptr && consume(token)) {
      auto right = (this->*parse_operand)();
      if (right == nullptr)
        return nullptr;
      auto node = std::make_unique<ConditionNode>();
      node->kind = kind;
      node->left = std::move(left);
      node->right = std::move(right);
      left = std::move(node);
    }
    return left;
  }

  std::unique_ptr<ConditionNode> parse_unary() {
    if (consume("!")) {
      if (!enter_nested())
        return nullptr;
      auto operand = parse_unary();
      leave_nested();
      if (operand == nullptr)
        return nullptr;
      auto node = std::make_unique<ConditionNode>();
      node->kind = NodeKind::Not;
      node->left = std::move(operand);
      return node;
    }
    return parse_primary();
  }

  std::unique_ptr<ConditionNode> parse_primary() {
    if (consume("(")) {
      if (!enter_nested())
        return nullptr;
      auto node = parse_or();
      leave_nested();
      if (node != nullptr && !consume(")")) {
        fail(l10n::Key::ConditionExpectedClose);
        return nullptr;
      }
      return node;
    }
    if (consume_keyword("true")) {
      auto node = std::make_unique<ConditionNode>();
      node->kind = NodeKind::Literal;
      node->literal = true;
      return node;
    }
    if (consume_keyword("false")) {
      auto node = std::make_unique<ConditionNode>();
      node->kind = NodeKind::Literal;
      return node;
    }

    const std::size_t saved = position_;
    const auto identifier = parse_identifier();
    if (identifier &&
        (*identifier == "masked_cmp" || *identifier == "strcmp")) {
      return parse_memory_function(*identifier);
    }
    position_ = saved;

    auto left_value = parse_numeric();
    if (!left_value) {
      fail(l10n::Key::ConditionExpectedExpression);
      return nullptr;
    }
    auto node = std::make_unique<ConditionNode>();
    node->numeric = std::move(*left_value);
    const auto comparison = parse_comparison_operator();
    if (!comparison) {
      node->kind = NodeKind::Truthy;
      return node;
    }
    auto right_value = parse_numeric();
    if (!right_value) {
      fail(l10n::Key::ConditionExpectedComparisonValue);
      return nullptr;
    }
    node->kind = NodeKind::Compare;
    node->comparison = *comparison;
    node->right_numeric = std::move(*right_value);
    return node;
  }

  std::unique_ptr<ConditionNode>
  parse_memory_function(std::string_view function_name) {
    if (!consume("(")) {
      fail(l10n::Key::ConditionExpectedOpenAfterFunction,
           static_cast<int>(function_name.size()), function_name.data());
      return nullptr;
    }
    if (!consume_keyword("valueAt") || !consume("(")) {
      fail(l10n::Key::ConditionExpectedValueAt);
      return nullptr;
    }
    auto address = parse_numeric();
    if (!address || !consume(")")) {
      fail(l10n::Key::ConditionExpectedValueAtAddress);
      return nullptr;
    }
    if (!(consume(",") || (function_name == "strcmp" && consume("==")))) {
      fail(l10n::Key::ConditionExpectedComparisonComma);
      return nullptr;
    }
    auto string = parse_string();
    if (!string || !consume(")")) {
      if (error_.empty())
        fail(l10n::Key::ConditionExpectedStringAndClose);
      return nullptr;
    }

    auto node = std::make_unique<ConditionNode>();
    node->numeric = std::move(*address);
    if (function_name == "strcmp") {
      node->kind = NodeKind::StringCompare;
      node->text = std::move(*string);
      return node;
    }

    node->kind = NodeKind::MaskedCompare;
    if (!decode_pattern(*string, node->expected, node->mask)) {
      return nullptr;
    }
    return node;
  }

  bool decode_pattern(std::string_view pattern,
                      std::vector<std::uint8_t> &expected,
                      std::vector<std::uint8_t> &mask) {
    std::string compact;
    compact.reserve(pattern.size());
    for (const char character : pattern) {
      if (!std::isspace(static_cast<unsigned char>(character))) {
        compact.push_back(character);
      }
    }
    pattern = compact;
    if (pattern.empty() || pattern.size() % 2 != 0) {
      fail(l10n::Key::ConditionPatternIncompleteBytes);
      return false;
    }
    if (pattern.size() / 2 > 256) {
      fail(l10n::Key::ConditionPatternTooLong);
      return false;
    }
    expected.reserve(pattern.size() / 2);
    mask.reserve(pattern.size() / 2);
    for (std::size_t index = 0; index < pattern.size(); index += 2) {
      std::uint8_t byte = 0;
      std::uint8_t byte_mask = 0;
      for (std::size_t nibble = 0; nibble < 2; ++nibble) {
        const char character = pattern[index + nibble];
        byte = static_cast<std::uint8_t>(byte << 4U);
        byte_mask = static_cast<std::uint8_t>(byte_mask << 4U);
        if (character == '?')
          continue;
        const int value = hex_value(character);
        if (value < 0) {
          fail(l10n::Key::ConditionPatternInvalidHex);
          return false;
        }
        byte =
            static_cast<std::uint8_t>(byte | static_cast<std::uint8_t>(value));
        byte_mask = static_cast<std::uint8_t>(byte_mask | 0x0FU);
      }
      expected.push_back(byte);
      mask.push_back(byte_mask);
    }
    return true;
  }

  std::optional<NumericValue> parse_numeric() {
    skip_space();
    const std::size_t start = position_;
    if (position_ < source_.size() &&
        std::isdigit(static_cast<unsigned char>(source_[position_]))) {
      int base = 10;
      if (source_.substr(position_).starts_with("0x") ||
          source_.substr(position_).starts_with("0X")) {
        base = 16;
        position_ += 2;
      }
      const std::size_t digits = position_;
      while (position_ < source_.size() &&
             (base == 16 ? std::isxdigit(
                               static_cast<unsigned char>(source_[position_]))
                         : std::isdigit(static_cast<unsigned char>(
                               source_[position_])))) {
        ++position_;
      }
      if (position_ == digits) {
        position_ = start;
        return std::nullopt;
      }
      std::uint64_t value = 0;
      const auto parsed = std::from_chars(
          source_.data() + digits, source_.data() + position_, value, base);
      if (parsed.ec != std::errc{}) {
        fail(l10n::Key::ConditionNumericLiteralOutOfRange);
        return std::nullopt;
      }
      return NumericValue{.literal = true, .value = value, .register_name = {}};
    }
    const auto identifier = parse_identifier();
    if (!identifier)
      return std::nullopt;
    return NumericValue{.register_name = *identifier};
  }

  std::optional<CompareOperator> parse_comparison_operator() {
    if (consume("===") || consume("=="))
      return CompareOperator::Equal;
    if (consume("!="))
      return CompareOperator::NotEqual;
    if (consume("<="))
      return CompareOperator::LessEqual;
    if (consume(">="))
      return CompareOperator::GreaterEqual;
    if (consume("<"))
      return CompareOperator::Less;
    if (consume(">"))
      return CompareOperator::Greater;
    return std::nullopt;
  }

  std::optional<std::string> parse_identifier() {
    skip_space();
    const std::size_t start = position_;
    if (position_ < source_.size() && source_[position_] == '$')
      ++position_;
    if (position_ >= source_.size() ||
        !(std::isalpha(static_cast<unsigned char>(source_[position_])) ||
          source_[position_] == '_')) {
      position_ = start;
      return std::nullopt;
    }
    ++position_;
    while (position_ < source_.size() &&
           (std::isalnum(static_cast<unsigned char>(source_[position_])) ||
            source_[position_] == '_')) {
      ++position_;
    }
    std::string result{source_.substr(start, position_ - start)};
    if (!result.empty() && result.front() == '$')
      result.erase(0, 1);
    return result;
  }

  std::optional<std::string> parse_string() {
    skip_space();
    if (position_ >= source_.size() || source_[position_] != '"')
      return std::nullopt;
    ++position_;
    std::string result;
    while (position_ < source_.size()) {
      const char character = source_[position_++];
      if (character == '"')
        return result;
      if (character != '\\') {
        result.push_back(character);
        continue;
      }
      if (position_ >= source_.size())
        break;
      const char escaped = source_[position_++];
      switch (escaped) {
      case 'n':
        result.push_back('\n');
        break;
      case 'r':
        result.push_back('\r');
        break;
      case 't':
        result.push_back('\t');
        break;
      case '\\':
      case '"':
        result.push_back(escaped);
        break;
      default:
        fail(l10n::Key::ConditionUnsupportedStringEscape);
        return std::nullopt;
      }
      if (result.size() > 1024) {
        fail(l10n::Key::ConditionStringLiteralTooLong);
        return std::nullopt;
      }
    }
    fail(l10n::Key::ConditionUnterminatedStringLiteral);
    return std::nullopt;
  }

  bool consume(std::string_view token) {
    skip_space();
    if (!source_.substr(position_).starts_with(token))
      return false;
    position_ += token.size();
    return true;
  }

  bool consume_keyword(std::string_view keyword) {
    skip_space();
    if (!source_.substr(position_).starts_with(keyword))
      return false;
    const std::size_t end = position_ + keyword.size();
    if (end < source_.size() &&
        (std::isalnum(static_cast<unsigned char>(source_[end])) ||
         source_[end] == '_')) {
      return false;
    }
    position_ = end;
    return true;
  }

  void skip_space() {
    while (position_ < source_.size() &&
           std::isspace(static_cast<unsigned char>(source_[position_]))) {
      ++position_;
    }
  }

  bool enter_nested() {
    if (++depth_ > 64) {
      fail(l10n::Key::ConditionNestingTooDeep);
      return false;
    }
    return true;
  }
  void leave_nested() { --depth_; }

  static int hex_value(char character) {
    if (character >= '0' && character <= '9')
      return character - '0';
    if (character >= 'a' && character <= 'f')
      return character - 'a' + 10;
    if (character >= 'A' && character <= 'F')
      return character - 'A' + 10;
    return -1;
  }

  template <typename... Args> void fail(l10n::Key key, Args... args) {
    if (error_.empty()) {
      error_ = l10n::format(key, args..., position_);
    }
  }

  std::string_view source_;
  std::size_t position_{};
  std::size_t depth_{};
  std::string error_;
};

bool numeric_value(const NumericValue &input, const EvaluationContext &context,
                   std::uint64_t &output, std::string &error) {
  if (input.literal) {
    output = input.value;
    return true;
  }
  if (context.read_register == nullptr) {
    error = l10n::text(l10n::Key::ConditionRegisterAccessUnavailable);
    return false;
  }
  return context.read_register(context.user_data, input.register_name, output,
                               error);
}

bool evaluate_node(const ConditionNode &node, const EvaluationContext &context,
                   bool &output, std::string &error) {
  switch (node.kind) {
  case NodeKind::Literal:
    output = node.literal;
    return true;
  case NodeKind::Truthy: {
    std::uint64_t value = 0;
    if (!numeric_value(node.numeric, context, value, error))
      return false;
    output = value != 0;
    return true;
  }
  case NodeKind::Not:
    if (!evaluate_node(*node.left, context, output, error))
      return false;
    output = !output;
    return true;
  case NodeKind::And:
  case NodeKind::Or: {
    bool left = false;
    if (!evaluate_node(*node.left, context, left, error))
      return false;
    if (left == (node.kind == NodeKind::Or)) {
      output = left;
      return true;
    }
    return evaluate_node(*node.right, context, output, error);
  }
  case NodeKind::Compare: {
    std::uint64_t left = 0;
    std::uint64_t right = 0;
    if (!numeric_value(node.numeric, context, left, error) ||
        !numeric_value(node.right_numeric, context, right, error)) {
      return false;
    }
    switch (node.comparison) {
    case CompareOperator::Equal:
      output = left == right;
      break;
    case CompareOperator::NotEqual:
      output = left != right;
      break;
    case CompareOperator::Less:
      output = left < right;
      break;
    case CompareOperator::LessEqual:
      output = left <= right;
      break;
    case CompareOperator::Greater:
      output = left > right;
      break;
    case CompareOperator::GreaterEqual:
      output = left >= right;
      break;
    }
    return true;
  }
  case NodeKind::MaskedCompare:
  case NodeKind::StringCompare: {
    std::uint64_t address = 0;
    if (!numeric_value(node.numeric, context, address, error))
      return false;
    if (context.read_memory == nullptr) {
      error = l10n::text(l10n::Key::ConditionMemoryAccessUnavailable);
      return false;
    }
    const std::size_t size = node.kind == NodeKind::StringCompare
                                 ? node.text.size() + 1
                                 : node.expected.size();
    std::vector<std::uint8_t> bytes(size);
    if (!context.read_memory(context.user_data, address, bytes, error))
      return false;
    if (node.kind == NodeKind::StringCompare) {
      output = std::equal(node.text.begin(), node.text.end(), bytes.begin()) &&
               bytes.back() == 0;
      return true;
    }
    output = true;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
      if ((bytes[index] & node.mask[index]) != node.expected[index]) {
        output = false;
        break;
      }
    }
    return true;
  }
  }
  error = l10n::text(l10n::Key::ConditionInvalidNode);
  return false;
}

} // namespace

CompileResult compile(std::string_view source) {
  CompileResult result;
  if (source.empty()) {
    result.error = l10n::text(l10n::Key::ConditionEmpty);
    return result;
  }
  if (source.size() > 4096) {
    result.error = l10n::text(l10n::Key::ConditionTooLong);
    return result;
  }
  Parser parser{source};
  auto root = parser.parse();
  if (root == nullptr) {
    result.error = parser.error();
    return result;
  }
  result.condition.root_ =
      std::shared_ptr<const ConditionNode>{std::move(root)};
  result.condition.source_ = source;
  return result;
}

EvaluationResult evaluate(const CompiledCondition &condition,
                          const EvaluationContext &context) {
  if (!condition.valid())
    return {.error = l10n::text(l10n::Key::ConditionNotCompiled)};
  EvaluationResult result;
  if (!evaluate_node(*condition.root_, context, result.matched, result.error)) {
    result.matched = false;
  }
  return result;
}

} // namespace debugger::conditions
