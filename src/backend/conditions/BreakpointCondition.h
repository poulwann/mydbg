#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>

namespace debugger::conditions {

struct ConditionNode;
struct CompileResult;
struct EvaluationContext;
struct EvaluationResult;

class CompiledCondition {
public:
  CompiledCondition() = default;

  [[nodiscard]] bool valid() const noexcept { return root_ != nullptr; }
  [[nodiscard]] const std::string &source() const noexcept { return source_; }

private:
  std::shared_ptr<const ConditionNode> root_;
  std::string source_;

  friend CompileResult compile(std::string_view source);
  friend EvaluationResult evaluate(const CompiledCondition &condition,
                                   const struct EvaluationContext &context);
};

struct CompileResult {
  CompiledCondition condition;
  std::string error;

  [[nodiscard]] explicit operator bool() const noexcept {
    return condition.valid() && error.empty();
  }
};

struct EvaluationContext {
  void *user_data{};
  bool (*read_register)(void *user_data, std::string_view name,
                        std::uint64_t &value, std::string &error){};
  bool (*read_memory)(void *user_data, std::uint64_t address,
                      std::span<std::uint8_t> bytes, std::string &error){};
};

struct EvaluationResult {
  bool matched{};
  std::string error;

  [[nodiscard]] explicit operator bool() const noexcept {
    return error.empty();
  }
};

// The intentionally small, side-effect-free language supports if(...),
// &&, ||, !, numeric/register comparisons, valueAt(address),
// masked_cmp(valueAt(address), "DEAD????") and
// strcmp(valueAt(address), "text").
[[nodiscard]] CompileResult compile(std::string_view source);
[[nodiscard]] EvaluationResult evaluate(const CompiledCondition &condition,
                                        const EvaluationContext &context);

} // namespace debugger::conditions
