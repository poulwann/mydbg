#include "EngineTestSupport.h"
#include "plugins/PluginApi.h"

#include <chrono>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace std::chrono_literals;

namespace {

using debugger::test::require;
using debugger::test::wait_for_state;

} // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s DEBUGGEE\n", argv[0]);
    return 2;
  }

  try {
    {
      debugger::LldbEngine engine;
      debugger::SessionSnapshot state = wait_for_state(
          engine, engine.snapshot(),
          [](const debugger::SessionSnapshot &value) {
            return value.state == debugger::SessionState::NoTarget;
          });

      // The CTest catalog makes successful help start with "error:" and removes
      // that prefix from failures. Status must not depend on translated prose.
      const auto execute = [&](const char *command) {
        const auto ticket = engine.execute_command(command);
        require(ticket.wait_for(5s), "localized command did not complete");
        return ticket.get();
      };
      require(execute("help").success,
              "translated success was classified as an error");
      require(!execute("context").success,
              "translated native failure was classified as success");
      require(debugger::plugins::PluginRegistry::instance().register_command(
                  "localization-throw", "localization exception fixture",
                  [](std::string_view, const debugger::SessionSnapshot &)
                      -> std::string { throw std::runtime_error("fixture"); }),
              "plugin fixture registration failed");
      require(!execute("localization-throw").success,
              "translated plugin exception was classified as success");

      debugger::CommandTicket launch = engine.launch(argv[1]);
      require(launch.wait_for(15s), "launch command did not complete");
      const debugger::CommandResult launch_result = launch.get();
      require(launch_result.success, launch_result.message.c_str());
      require(launch_result.snapshot_revision > state.revision,
              "launch completion did not follow state publication");
      state = wait_for_state(
          engine, engine.snapshot(),
          [](const debugger::SessionSnapshot &value) {
            return value.state == debugger::SessionState::Stopped ||
                   value.state == debugger::SessionState::Error;
          });
      require(state.state == debugger::SessionState::Stopped,
              state.error.empty() ? "debuggee did not stop at main"
                                  : state.error.c_str());

      debugger::CommandTicket breakpoint = engine.set_breakpoint("calculate");
      require(breakpoint.id() > launch.id(), "command IDs are not increasing");
      require(breakpoint.wait_for(5s), "breakpoint command did not complete");
      require(breakpoint.get().success, "setting calculate breakpoint failed");

      const std::uint64_t generation = state.generation;
      const std::uint64_t stop_revision = state.stop_revision;
      debugger::CommandTicket continued = engine.continue_execution();
      require(continued.wait_for(5s), "continue command did not complete");
      const debugger::CommandResult continue_result = continued.get();
      require(continue_result.success, continue_result.message.c_str());
      require(continue_result.snapshot_revision >
                  launch_result.snapshot_revision,
              "continue completion preceded state publication");

      state = engine.snapshot();
      state = wait_for_state(
          engine, state,
          [generation, stop_revision](const debugger::SessionSnapshot &value) {
            return value.generation == generation &&
                   ((value.state == debugger::SessionState::Stopped &&
                     value.stop_revision > stop_revision) ||
                    value.state == debugger::SessionState::Exited);
          });
      require(state.state == debugger::SessionState::Stopped,
              "calculate breakpoint was not reached");
      require(state.stop_revision > stop_revision,
              "stop revision did not increase");

      debugger::CommandTicket invalid = engine.continue_execution();
      require(invalid.wait_for(5s), "second continue did not complete");
      require(invalid.get().success, "second continue failed");
      state =
          wait_for_state(engine, engine.snapshot(),
                         [](const debugger::SessionSnapshot &value) {
                           return value.state == debugger::SessionState::Exited;
                         });
      require(state.exit_status == 0, "debuggee exited unsuccessfully");
    }

    std::vector<debugger::CommandTicket> queued;
    {
      auto shutting_down = std::make_unique<debugger::LldbEngine>();
      wait_for_state(*shutting_down, shutting_down->snapshot(),
                     [](const debugger::SessionSnapshot &value) {
                       return value.state == debugger::SessionState::NoTarget;
                     });
      queued.reserve(256);
      for (int index = 0; index < 256; ++index) {
        queued.push_back(shutting_down->execute_command("help"));
      }
    }
    bool saw_shutdown_failure = false;
    for (const debugger::CommandTicket &ticket : queued) {
      require(ticket.wait_for(1s), "shutdown left a command future unresolved");
      const debugger::CommandResult result = ticket.get();
      saw_shutdown_failure =
          saw_shutdown_failure ||
          (!result.success && result.message == "engine is shutting down");
    }
    require(saw_shutdown_failure,
            "shutdown did not reject any queued engine commands");
  } catch (const std::exception &error) {
    std::fprintf(stderr, "command test failure: %s\n", error.what());
    return 1;
  }
  return 0;
}
