#include "EngineTestSupport.h"

#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {

using debugger::test::require;
using debugger::test::wait_for_state;

debugger::CommandResult complete(debugger::CommandTicket ticket,
                                 std::chrono::milliseconds timeout = 15s) {
  require(ticket.wait_for(timeout), "engine command timed out");
  debugger::CommandResult result = ticket.get();
  require(result.success, result.message.c_str());
  return result;
}


void stop_child(pid_t child) {
  if (child > 0) {
    ::kill(child, SIGKILL);
    ::waitpid(child, nullptr, 0);
  }
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 4) {
    std::fprintf(stderr, "usage: %s INTERACTIVE ATTACH WORKING_DIRECTORY\n",
                 argv[0]);
    return 2;
  }

  pid_t child = -1;
  try {
    debugger::LldbEngine engine;
    debugger::SessionSnapshot state = wait_for_state(
        engine, engine.snapshot(), [](const debugger::SessionSnapshot &value) {
          return value.state == debugger::SessionState::NoTarget;
        });

    debugger::LaunchOptions options{
        .executable = argv[1],
        .arguments = {"alpha"},
        .environment = {"MYDBG_SCRIPT_TEST=beta"},
        .working_directory = argv[3],
        .stop_policy = debugger::LaunchStopPolicy::Main,
    };
    complete(engine.launch(options));
    state = wait_for_state(
        engine, engine.snapshot(), [](const debugger::SessionSnapshot &value) {
          return value.state == debugger::SessionState::Stopped;
        });

    debugger::CommandResult evaluated =
        complete(engine.evaluate("&script_marker"));
    require(evaluated.has_numeric_value,
            "marker expression did not produce an address");
    const std::uint64_t marker_address = evaluated.numeric_value;

    constexpr std::uint64_t initial_marker = 0x1122334455667788ULL;
    debugger::CommandResult memory =
        complete(engine.read_memory(marker_address, 8));
    require(memory.bytes.size() == sizeof(initial_marker),
            "typed memory read returned the wrong size");
    require(std::memcmp(memory.bytes.data(), &initial_marker,
                        sizeof(initial_marker)) == 0,
            "typed memory read returned the wrong bytes");

    constexpr std::uint64_t patched_marker = 0x8877665544332211ULL;
    std::vector<std::uint8_t> patch(sizeof(patched_marker));
    std::memcpy(patch.data(), &patched_marker, sizeof(patched_marker));
    complete(engine.write_memory(marker_address, patch));
    require(!engine.snapshot().patches.empty(),
            "typed memory write bypassed tracked patches");
    memory = complete(engine.read_memory(marker_address, patch.size()));
    require(memory.bytes == patch, "typed memory write did not persist");

    debugger::CommandResult pc = complete(engine.read_register("pc"));
    require(pc.has_numeric_value, "typed register read was not numeric");
    const auto instructions = engine.snapshot().instructions;
    const auto destination = std::find_if(
        instructions.begin(), instructions.end(),
        [&pc](const debugger::InstructionRow &instruction) {
          return instruction.address != pc.numeric_value;
        });
    require(destination != instructions.end(), "no alternate PC destination");
    complete(engine.write_register("pc", destination->address));
    require(engine.snapshot().pc == destination->address &&
                complete(engine.read_register("pc")).numeric_value ==
                    destination->address,
            "register write left the frame PC or disassembly snapshot stale");
    complete(engine.write_register("pc", pc.numeric_value));
    require(engine.snapshot().pc == pc.numeric_value,
            "restoring PC left a stale disassembly snapshot");

    complete(engine.set_breakpoint("script_checkpoint"));
    const std::uint64_t generation = state.generation;
    const std::uint64_t stop_revision = state.stop_revision;
    complete(engine.continue_execution());
    complete(engine.send_stdin("payload\n"));
    state = wait_for_state(
        engine, engine.snapshot(),
        [generation, stop_revision](const debugger::SessionSnapshot &value) {
          return value.generation == generation &&
                 value.state == debugger::SessionState::Stopped &&
                 value.stop_revision > stop_revision;
        });
    require(state.process_output.find("ready arg=alpha env=beta cwd=" +
                                      std::string{argv[3]}) !=
                std::string::npos,
            "launch argv, environment, cwd, or stdout was not preserved");
    require(state.process_output.find("stderr-ready") != std::string::npos,
            "stderr was not captured");
    require(!state.output_chunks.empty(), "sequenced output chunks are empty");
    std::uint64_t sequence = 0;
    for (const debugger::OutputChunk &chunk : state.output_chunks) {
      require(chunk.sequence > sequence,
              "output chunk sequence did not increase");
      sequence = chunk.sequence;
    }

    complete(engine.continue_execution());
    state = wait_for_state(
        engine, engine.snapshot(), [](const debugger::SessionSnapshot &value) {
          return value.state == debugger::SessionState::Exited;
        });
    require(state.process_output.find(
                "echo=payload marker=0x8877665544332211") != std::string::npos,
            "inferior input or patched memory result was not observed");

    options.arguments.clear();
    options.environment.clear();
    options.working_directory.clear();
    options.stop_policy = debugger::LaunchStopPolicy::Entry;
    complete(engine.launch(options));
    state = wait_for_state(
        engine, engine.snapshot(), [](const debugger::SessionSnapshot &value) {
          return value.state == debugger::SessionState::Stopped;
        });
    complete(engine.terminate());
    wait_for_state(engine, engine.snapshot(),
                   [](const debugger::SessionSnapshot &value) {
                     return value.state == debugger::SessionState::Exited;
                   });

    child = ::fork();
    require(child >= 0, "fork failed");
    if (child == 0) {
      ::execl(argv[2], argv[2], static_cast<char *>(nullptr));
      ::_exit(127);
    }
    std::this_thread::sleep_for(100ms);
    complete(engine.attach(static_cast<std::uint64_t>(child)));
    state = wait_for_state(
        engine, engine.snapshot(),
        [child](const debugger::SessionSnapshot &value) {
          return value.state == debugger::SessionState::Stopped &&
                 value.process_id == static_cast<std::uint64_t>(child);
        });
    complete(engine.detach());
    state = engine.snapshot();
    require(state.state == debugger::SessionState::TargetLoaded,
            "typed detach did not preserve the target");
    stop_child(child);
    child = -1;
  } catch (const std::exception &error) {
    stop_child(child);
    std::fprintf(stderr, "scripting engine failure: %s\n", error.what());
    return 1;
  }
  return 0;
}
