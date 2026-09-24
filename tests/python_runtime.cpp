#include "backend/lldb/LldbEngine.h"
#include "scripting/PythonHost.h"
#include "scripting/PythonRuntime.h"
#include "TestSupport.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>

using namespace std::chrono_literals;

namespace {

using debugger::test::require;

void run_and_check(debugger::scripting::PythonRuntime &runtime,
                   const std::string &script, const std::string &expected) {
  require(runtime.run_file(script), "runtime rejected script job");
  require(runtime.wait_for_completion(30s), "script job timed out");
  const debugger::scripting::ScriptSnapshot result = runtime.snapshot();
  if (result.status != debugger::scripting::ScriptStatus::Succeeded) {
    throw std::runtime_error("script failed: " + result.traceback + "\n" +
                             result.output);
  }
  require(result.output.find(expected) != std::string::npos,
          "script output was not captured");
  require(!result.control_lease, "completed script retained the control lease");
}

void run_failure_check(debugger::scripting::PythonRuntime &runtime,
                       const std::string &script) {
  require(runtime.run_file(script), "runtime rejected traceback job");
  require(runtime.wait_for_completion(5s), "traceback job timed out");
  const debugger::scripting::ScriptSnapshot result = runtime.snapshot();
  require(result.status == debugger::scripting::ScriptStatus::Failed,
          "exceptional script did not fail");
  require(result.traceback.find("intentional traceback") != std::string::npos &&
              result.traceback.find("nested_failure") != std::string::npos,
          "full Python traceback was not captured");
}

void run_cancellation_check(debugger::scripting::PythonRuntime &runtime,
                            const std::string &script) {
  require(runtime.run_file(script), "runtime rejected cancellation job");
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  while (runtime.snapshot().output.find("blocking-start") ==
         std::string::npos) {
    require(std::chrono::steady_clock::now() < deadline,
            "blocking script did not start");
    std::this_thread::sleep_for(10ms);
  }
  runtime.stop();
  require(runtime.wait_for_completion(5s), "script cancellation timed out");
  const debugger::scripting::ScriptSnapshot result = runtime.snapshot();
  require(result.status == debugger::scripting::ScriptStatus::Cancelled,
          "blocked script was not cooperatively cancelled");
  require(!result.control_lease, "cancelled script retained the control lease");
}

void run_shutdown_check(debugger::LldbEngine &engine,
                        const std::string &script) {
  const auto started = std::chrono::steady_clock::now();
  {
    debugger::scripting::PythonRuntime runtime{engine};
    require(runtime.run_file(script), "runtime rejected shutdown job");
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (runtime.snapshot().output.find("blocking-start") ==
           std::string::npos) {
      require(std::chrono::steady_clock::now() < deadline,
              "shutdown script did not start");
      std::this_thread::sleep_for(10ms);
    }
  }
  require(std::chrono::steady_clock::now() - started < 5s,
          "shutdown blocked on a script waiting for the inferior");
}

debugger::scripting::ScriptSnapshot
wait_for_debug_pause(debugger::scripting::PythonRuntime &runtime,
                     std::uint64_t after_revision) {
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  for (;;) {
    debugger::scripting::ScriptSnapshot snapshot = runtime.snapshot();
    if (snapshot.revision > after_revision &&
        snapshot.debug_state == debugger::scripting::ScriptDebugState::Paused) {
      return snapshot;
    }
    if (snapshot.status == debugger::scripting::ScriptStatus::Failed) {
      throw std::runtime_error("debug script failed: " + snapshot.traceback);
    }
    require(std::chrono::steady_clock::now() < deadline,
            "script debugger did not pause");
    std::this_thread::sleep_for(5ms);
  }
}

void run_debugger_check(debugger::scripting::PythonRuntime &runtime,
                        const std::string &script) {
  std::ifstream input{script, std::ios::binary};
  require(input.good(), "unable to read debug script");
  const std::string source{std::istreambuf_iterator<char>{input},
                           std::istreambuf_iterator<char>{}};
  require(runtime.debug_source(script, source), "runtime rejected debug job");

  debugger::scripting::ScriptSnapshot paused = wait_for_debug_pause(runtime, 0);
  require(paused.current_line == 1, "debugger did not stop on entry");
  require(!paused.frames.empty() && paused.frames.front().line == 1,
          "paused Python stack was not captured");

  runtime.set_breakpoints({8});
  runtime.continue_script();
  paused = wait_for_debug_pause(runtime, paused.revision);
  require(paused.current_line == 8, "script breakpoint was not honored");
  require(paused.breakpoints == std::vector<std::uint32_t>{8},
          "script breakpoint state was not published");
  require(!paused.frames.empty() && paused.frames.front().function == "run",
          "script breakpoint did not capture the run frame");

  runtime.step_into_script();
  paused = wait_for_debug_pause(runtime, paused.revision);
  require(paused.current_line == 2 && !paused.frames.empty() &&
              paused.frames.front().function == "add_one",
          "step into did not enter the called script function");

  runtime.step_over_script();
  paused = wait_for_debug_pause(runtime, paused.revision);
  require(paused.current_line == 3 && !paused.frames.empty() &&
              paused.frames.front().function == "add_one",
          "step over did not advance within the called function");

  runtime.step_out_script();
  paused = wait_for_debug_pause(runtime, paused.revision);
  require(paused.current_line == 9 && !paused.frames.empty() &&
              paused.frames.front().function == "run",
          "step out did not return to the caller");

  runtime.step_over_script();
  paused = wait_for_debug_pause(runtime, paused.revision);
  require(paused.current_line == 10 && !paused.frames.empty() &&
              paused.frames.front().function == "run",
          "step over entered a called script function");
  const auto third =
      std::ranges::find_if(paused.frames.front().locals,
                           [](const debugger::scripting::ScriptValue &value) {
                             return value.name == "third";
                           });
  require(third != paused.frames.front().locals.end() && third->type == "int" &&
              third->value == "3",
          "step over did not preserve the caller's computed value");

  runtime.continue_script();
  require(runtime.wait_for_completion(5s), "debug script did not complete");
  const debugger::scripting::ScriptSnapshot completed = runtime.snapshot();
  require(completed.status == debugger::scripting::ScriptStatus::Succeeded &&
              completed.output.find("script-debugger-value=3") !=
                  std::string::npos,
          "debug script result was not preserved");

  const std::string pausable_source = "import time\n"
                                      "def run(dbg):\n"
                                      "    for index in range(100):\n"
                                      "        time.sleep(0.01)\n";
  require(runtime.debug_source(script, pausable_source, {}, false),
          "runtime rejected pausable debug job");
  runtime.pause_script();
  paused = wait_for_debug_pause(runtime, completed.revision);
  require(paused.current_line > 0, "pause did not retain a source location");
  runtime.stop();
  require(runtime.wait_for_completion(5s), "paused script did not cancel");
  require(runtime.snapshot().status ==
              debugger::scripting::ScriptStatus::Cancelled,
          "paused script cancellation was not reported");
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 6) {
    std::fprintf(
        stderr, "usage: %s INTEGRATION BEHAVIORS FAILURE BLOCKING DEBUGGABLE\n",
        argv[0]);
    return 2;
  }

  try {
    debugger::scripting::PythonHost host;
    debugger::LldbEngine engine;
    {
      debugger::scripting::PythonRuntime runtime{engine};
      run_and_check(runtime, argv[1], "python-runtime-ok");
      run_and_check(runtime, argv[1], "python-runtime-ok");
      run_and_check(runtime, argv[2], "python-behaviors-ok");
      run_failure_check(runtime, argv[3]);
      run_cancellation_check(runtime, argv[4]);
      run_debugger_check(runtime, argv[5]);
    }
    run_shutdown_check(engine, argv[4]);
  } catch (const std::exception &error) {
    std::fprintf(stderr, "python runtime failure: %s\n", error.what());
    return 1;
  }
  return 0;
}
