#include "backend/conditions/BreakpointCondition.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <unordered_map>

namespace {

struct TestContext {
  std::unordered_map<std::string, std::uint64_t> registers;
  std::unordered_map<std::uint64_t, std::uint8_t> memory;
};

bool read_register(void *user_data, std::string_view name, std::uint64_t &value,
                   std::string &error) {
  auto &context = *static_cast<TestContext *>(user_data);
  const auto found = context.registers.find(std::string{name});
  if (found == context.registers.end()) {
    error = "unknown register '" + std::string{name} + "'";
    return false;
  }
  value = found->second;
  return true;
}

bool read_memory(void *user_data, std::uint64_t address,
                 std::span<std::uint8_t> bytes, std::string &error) {
  auto &context = *static_cast<TestContext *>(user_data);
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    const auto found = context.memory.find(address + index);
    if (found == context.memory.end()) {
      error = "unmapped test byte";
      return false;
    }
    bytes[index] = found->second;
  }
  return true;
}

void store(TestContext &context, std::uint64_t address, std::string_view bytes,
           bool nul_terminate = false) {
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    context.memory[address + index] = static_cast<std::uint8_t>(bytes[index]);
  }
  if (nul_terminate)
    context.memory[address + bytes.size()] = 0;
}

struct TestRunner {
  int checks{};
  int failures{};

  void require(bool condition, std::string_view message) {
    ++checks;
    if (!condition) {
      ++failures;
      std::fprintf(stderr, "condition test failed: %.*s\n",
                   static_cast<int>(message.size()), message.data());
    }
  }
};

} // namespace

int main() {
  using debugger::conditions::CompileResult;
  using debugger::conditions::EvaluationContext;
  using debugger::conditions::EvaluationResult;

  TestRunner runner;
  TestContext data;
  data.registers = {{"rax", 0},          {"rbx", 42},      {"rcx", 7},
                    {"pattern", 0x1000}, {"text", 0x1100}, {"escaped", 0x1200}};
  data.memory[0x1000] = 0xDE;
  data.memory[0x1001] = 0xAD;
  data.memory[0x1002] = 0x42;
  data.memory[0x1003] = 0xEF;
  store(data, 0x1100, "I am a string", true);
  store(data, 0x1200, "line\n\"quoted\"", true);
  const EvaluationContext context{.user_data = &data,
                                  .read_register = read_register,
                                  .read_memory = read_memory};

  const auto evaluate_expression = [&](std::string_view source, bool expected) {
    const CompileResult compiled = debugger::conditions::compile(source);
    runner.require(static_cast<bool>(compiled), source);
    if (!compiled)
      return;
    const EvaluationResult result =
        debugger::conditions::evaluate(compiled.condition, context);
    runner.require(static_cast<bool>(result), source);
    if (result)
      runner.require(result.matched == expected, source);
  };

  const std::array<std::pair<std::string_view, bool>, 25> expressions{{
      {"true", true},
      {"false", false},
      {"1", true},
      {"0x0", false},
      {"rbx", true},
      {"$rax", false},
      {"rbx === 42", true},
      {"rbx == 0x2a", true},
      {"rbx != rcx", true},
      {"rcx < rbx", true},
      {"rcx <= 7", true},
      {"rbx > rcx", true},
      {"rbx >= 42", true},
      {"true || false && false", true},
      {"false || false || true && true && true", true},
      {"(false || true) && !false", true},
      {"false && missing_register", false},
      {"true || missing_register", true},
      {"if(rbx == 42)", true},
      {"masked_cmp(valueAt(pattern), \"DE AD 42 EF\")", true},
      {"masked_cmp(valueAt(pattern), \"D? A? ?? EF\")", true},
      {"masked_cmp(valueAt(pattern), \"DE AD 41 EF\")", false},
      {"strcmp(valueAt(text), \"I am a string\")", true},
      {"strcmp(valueAt(text) == \"I am a string\")", true},
      {"strcmp(valueAt(escaped), \"line\\n\\\"quoted\\\"\")", true},
  }};
  for (const auto &[source, expected] : expressions)
    evaluate_expression(source, expected);

  const std::array<std::string_view, 11> invalid{{
      "",
      "if true",
      "if(true",
      "true trailing",
      "rax ===",
      "0x",
      "masked_cmp(valueAt(pattern), \"\")",
      "masked_cmp(valueAt(pattern), \"ABC\")",
      "masked_cmp(valueAt(pattern), \"GG\")",
      "strcmp(valueAt(text), \"unterminated)",
      "strcmp(valueAt(text), \"bad\\q\")",
  }};
  for (const std::string_view source : invalid) {
    const CompileResult compiled = debugger::conditions::compile(source);
    runner.require(!compiled && !compiled.error.empty(), source);
  }

  std::string too_deep(65, '!');
  too_deep += "true";
  runner.require(!debugger::conditions::compile(too_deep),
                 "nesting limit must reject 65 levels");
  const std::string too_long(4097, '1');
  runner.require(!debugger::conditions::compile(too_long),
                 "source size limit must reject 4097 bytes");
  const std::string oversized_pattern =
      "masked_cmp(valueAt(pattern), \"" + std::string(514, '?') + "\")";
  runner.require(!debugger::conditions::compile(oversized_pattern),
                 "pattern size limit must reject 257 bytes");

  const CompileResult missing_register =
      debugger::conditions::compile("missing_register == 1");
  runner.require(static_cast<bool>(missing_register),
                 "register lookup must happen during evaluation");
  const EvaluationResult register_error =
      debugger::conditions::evaluate(missing_register.condition, context);
  runner.require(!register_error,
                 "unknown register must be an evaluation error");

  const CompileResult memory_expression =
      debugger::conditions::compile("strcmp(valueAt(text), \"I am a string\")");
  const EvaluationContext no_memory{.user_data = &data,
                                    .read_register = read_register};
  runner.require(
      !debugger::conditions::evaluate(memory_expression.condition, no_memory),
      "missing memory callback must be an evaluation error");

  const CompileResult register_expression =
      debugger::conditions::compile("rax == 0");
  const EvaluationContext no_register{.user_data = &data,
                                      .read_memory = read_memory};
  runner.require(!debugger::conditions::evaluate(register_expression.condition,
                                                 no_register),
                 "missing register callback must be an evaluation error");
  runner.require(!debugger::conditions::evaluate({}, context),
                 "uncompiled condition must be an evaluation error");

  std::printf("condition-language checks=%d failures=%d\n", runner.checks,
              runner.failures);
  return runner.failures == 0 ? 0 : 1;
}
