#pragma once

#include "TestSupport.h"
#include "backend/lldb/LldbEngine.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <string_view>
#include <utility>

namespace debugger::test {

template <typename Predicate>
SessionSnapshot wait_for_state(
    LldbEngine &engine, SessionSnapshot current, const Predicate &predicate,
    std::chrono::milliseconds timeout = std::chrono::seconds{15},
    std::string_view state_error = "timed out waiting for engine state",
    std::string_view update_error = "timed out waiting for engine update") {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  while (!predicate(current)) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    require(remaining > std::chrono::milliseconds{0}, state_error);
    auto update = engine.wait_for_update(current.revision, remaining);
    require(update.has_value(), update_error);
    current = std::move(*update);
  }
  return current;
}

inline const RegisterValue *find_register(const SessionSnapshot &state,
                                           std::string_view name) {
  const auto found = std::ranges::find(state.registers, name, &RegisterValue::name);
  return found == state.registers.end() ? nullptr : &*found;
}

inline bool has_function(const SessionSnapshot &state, std::string_view name) {
  return std::ranges::any_of(state.threads, [name](const auto &thread) {
    return std::ranges::any_of(thread.frames, [name](const auto &frame) {
      return frame.function.find(name) != std::string::npos;
    });
  });
}

inline const ModuleInfo *local_module(const SessionSnapshot &state,
                                     const std::filesystem::path &executable,
                                     bool filename_fallback = false) {
  std::error_code executable_error;
  const auto canonical_executable =
      std::filesystem::weakly_canonical(executable, executable_error);
  const auto found = std::ranges::find_if(state.modules, [&](const auto &module) {
    if (module.path == executable.string()) {
      return true;
    }
    if (executable_error) {
      return filename_fallback &&
             std::filesystem::path{module.path}.filename() == executable.filename();
    }
    std::error_code module_error;
    return std::filesystem::weakly_canonical(module.path, module_error) ==
               canonical_executable &&
           !module_error;
  });
  return found == state.modules.end() ? nullptr : &*found;
}

} // namespace debugger::test
