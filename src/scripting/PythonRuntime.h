#pragma once

#include "backend/lldb/LldbEngine.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace debugger::scripting {

enum class ScriptStatus {
  Idle,
  Queued,
  Running,
  Cancelling,
  Succeeded,
  Failed,
  Cancelled,
  ShuttingDown,
};

enum class ScriptDebugState {
  Inactive,
  Running,
  Paused,
};

struct ScriptValue {
  std::string name;
  std::string type;
  std::string value;
};

struct ScriptFrame {
  std::string file;
  std::string function;
  std::uint32_t line{};
  std::vector<ScriptValue> locals;
};

struct ScriptSnapshot {
  std::uint64_t revision{};
  std::uint64_t job_id{};
  ScriptStatus status{ScriptStatus::Idle};
  std::string file;
  std::string output;
  std::string traceback;
  bool control_lease{};
  ScriptDebugState debug_state{ScriptDebugState::Inactive};
  std::uint32_t current_line{};
  std::vector<std::uint32_t> breakpoints;
  std::vector<ScriptFrame> frames;
  std::vector<ScriptValue> globals;
};

class PythonRuntime final {
public:
  explicit PythonRuntime(LldbEngine &engine);
  ~PythonRuntime();

  PythonRuntime(const PythonRuntime &) = delete;
  PythonRuntime &operator=(const PythonRuntime &) = delete;

  [[nodiscard]] bool run_file(std::string file);
  [[nodiscard]] bool debug_source(std::string file, std::string source,
                                  std::vector<std::uint32_t> breakpoints = {},
                                  bool stop_on_entry = true);
  void continue_script();
  void step_into_script();
  void step_over_script();
  void step_out_script();
  void pause_script();
  void set_breakpoints(std::vector<std::uint32_t> breakpoints);
  void stop();
  void shutdown();

  [[nodiscard]] ScriptSnapshot snapshot() const;
  [[nodiscard]] bool
  wait_for_completion(std::chrono::milliseconds timeout) const;

private:
  enum class StepMode {
    None,
    Into,
    Over,
    Out,
  };

  [[nodiscard]] bool submit_job(std::string file, std::string source,
                                std::vector<std::uint32_t> breakpoints,
                                bool debug, bool stop_on_entry);
  void resume_script(StepMode mode);
  void run();
  void append_output(std::string text);
  void finish(ScriptStatus status, std::string traceback);

  LldbEngine &engine_;
  mutable std::mutex mutex_;
  mutable std::condition_variable changed_;
  std::condition_variable wake_;
  ScriptSnapshot snapshot_;
  std::string pending_file_;
  std::string pending_source_;
  std::vector<std::uint32_t> pending_breakpoints_;
  bool pending_debug_{};
  std::shared_ptr<std::atomic_bool> cancellation_;
  bool has_job_{};
  bool shutting_down_{};
  std::thread worker_;
  std::condition_variable debug_wake_;
  bool pause_requested_{};
  StepMode step_mode_{StepMode::None};
  std::uint32_t step_frame_depth_{};
};

[[nodiscard]] const char *to_string(ScriptStatus status) noexcept;
[[nodiscard]] const char *to_string(ScriptDebugState state) noexcept;

} // namespace debugger::scripting
