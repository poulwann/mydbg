#include "EngineTestSupport.h"
#include "scripting/PythonHost.h"
#include "scripting/PythonRuntime.h"

#include <chrono>
#include <cerrno>
#include <cstdint>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <cstring>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace std::chrono_literals;

namespace {

using debugger::test::require;

class QemuUserStub final {
public:
  QemuUserStub(const char *qemu, const char *executable, const char *input) {
    const int reservation = ::socket(AF_INET, SOCK_STREAM, 0);
    require(reservation >= 0, "unable to create a loopback socket");

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(reservation, reinterpret_cast<sockaddr *>(&address),
               sizeof(address)) != 0) {
      const std::string failure = std::strerror(errno);
      ::close(reservation);
      throw std::runtime_error("unable to reserve a QEMU port: " + failure);
    }
    socklen_t address_size = sizeof(address);
    if (::getsockname(reservation, reinterpret_cast<sockaddr *>(&address),
                      &address_size) != 0) {
      const std::string failure = std::strerror(errno);
      ::close(reservation);
      throw std::runtime_error("unable to inspect the QEMU port: " + failure);
    }
    const std::uint16_t port = ntohs(address.sin_port);
    ::close(reservation);

    port_ = std::to_string(port);
    endpoint_ = "connect://127.0.0.1:" + port_;
    process_id_ = ::fork();
    require(process_id_ >= 0, "unable to fork QEMU user process");
    if (process_id_ == 0) {
      ::execl(qemu, qemu, "-g", port_.c_str(), executable, input,
              static_cast<char *>(nullptr));
      std::fprintf(stderr, "unable to execute QEMU user process: %s\n",
                   std::strerror(errno));
      ::_exit(127);
    }

    try {
      const auto deadline = std::chrono::steady_clock::now() + 10s;
      while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const pid_t child = ::waitpid(process_id_, &status, WNOHANG);
        if (child == process_id_) {
          process_id_ = -1;
          throw std::runtime_error(
              "QEMU exited before opening its GDB stub");
        }
        if (child < 0 && errno != EINTR) {
          throw std::runtime_error("unable to inspect QEMU user process");
        }

        const int probe = ::socket(AF_INET, SOCK_STREAM, 0);
        require(probe >= 0, "unable to probe the QEMU port");
        sockaddr_in probe_address{};
        probe_address.sin_family = AF_INET;
        probe_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        probe_address.sin_port = htons(port);
        const int bound =
            ::bind(probe, reinterpret_cast<sockaddr *>(&probe_address),
                   sizeof(probe_address));
        const int bind_error = errno;
        ::close(probe);
        if (bound != 0 && bind_error == EADDRINUSE) {
          return;
        }
        std::this_thread::sleep_for(10ms);
      }
      throw std::runtime_error("QEMU did not open its GDB stub");
    } catch (...) {
      stop();
      throw;
    }
  }

  QemuUserStub(const QemuUserStub &) = delete;
  QemuUserStub &operator=(const QemuUserStub &) = delete;

  ~QemuUserStub() { stop(); }

  [[nodiscard]] const std::string &endpoint() const { return endpoint_; }

  bool wait_for_exit(std::chrono::milliseconds timeout, int &status) {
    if (process_id_ <= 0) {
      return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
      const pid_t child = ::waitpid(process_id_, &status, WNOHANG);
      if (child == process_id_) {
        process_id_ = -1;
        return true;
      }
      if (child < 0 && errno != EINTR) {
        return false;
      }
      std::this_thread::sleep_for(10ms);
    }
    return false;
  }

private:
  void stop() noexcept {
    if (process_id_ <= 0) {
      return;
    }
    int status = 0;
    pid_t child = ::waitpid(process_id_, &status, WNOHANG);
    while (child < 0 && errno == EINTR) {
      child = ::waitpid(process_id_, &status, WNOHANG);
    }
    if (child == 0) {
      ::kill(process_id_, SIGTERM);
      const auto deadline = std::chrono::steady_clock::now() + 1s;
      while (std::chrono::steady_clock::now() < deadline) {
        child = ::waitpid(process_id_, &status, WNOHANG);
        if (child == process_id_) {
          process_id_ = -1;
          return;
        }
        if (child < 0 && errno != EINTR) {
          process_id_ = -1;
          return;
        }
        std::this_thread::sleep_for(10ms);
      }
      ::kill(process_id_, SIGKILL);
      while (::waitpid(process_id_, &status, 0) < 0 && errno == EINTR) {
      }
    }
    process_id_ = -1;
  }

  pid_t process_id_{-1};
  std::string port_;
  std::string endpoint_;
};

debugger::CommandResult complete(debugger::CommandTicket ticket,
                                 std::chrono::milliseconds timeout = 20s) {
  require(ticket.wait_for(timeout), "engine command timed out");
  debugger::CommandResult result = ticket.get();
  require(result.success, result.message);
  return result;
}

template <typename Predicate>
debugger::SessionSnapshot wait_for_engine(
    debugger::LldbEngine &engine, const Predicate &predicate) {
  return debugger::test::wait_for_state(
      engine, engine.snapshot(), predicate, 20s,
      "timed out waiting for remote debugger state",
      "timed out waiting for remote debugger update");
}

debugger::scripting::ScriptSnapshot
wait_for_script_pause(debugger::scripting::PythonRuntime &runtime,
                      std::uint64_t after_revision) {
  const auto deadline = std::chrono::steady_clock::now() + 10s;
  for (;;) {
    debugger::scripting::ScriptSnapshot current = runtime.snapshot();
    if (current.revision > after_revision &&
        current.debug_state == debugger::scripting::ScriptDebugState::Paused) {
      return current;
    }
    if (current.status == debugger::scripting::ScriptStatus::Failed) {
      throw std::runtime_error("Python scenario failed before pause: " +
                               current.traceback);
    }
    require(std::chrono::steady_clock::now() < deadline,
            "timed out waiting for Python script debugger pause");
    std::this_thread::sleep_for(5ms);
  }
}

std::string read_source(const char *path) {
  std::ifstream input{path, std::ios::binary};
  require(input.good(), std::string{"unable to read Python scenario: "} + path);
  return {std::istreambuf_iterator<char>{input},
          std::istreambuf_iterator<char>{}};
}

void set_environment(const char *name, const char *value) {
  require(::setenv(name, value, 1) == 0,
          std::string{"unable to set test environment variable: "} + name);
}

void exercise_script_debugger(debugger::scripting::PythonRuntime &runtime,
                              const char *script) {
  constexpr std::uint32_t probe_call_line = 11;
  constexpr std::uint32_t probe_body_line = 6;
  constexpr std::uint32_t probe_check_line = 12;
  constexpr std::uint32_t first_scenario_line = 15;

  require(runtime.debug_source(script, read_source(script), {}, true),
          "runtime rejected cross-architecture Python scenario");
  debugger::scripting::ScriptSnapshot paused = wait_for_script_pause(runtime, 0);
  require(paused.current_line == 1, "script debugger did not stop on entry");
  require(!paused.frames.empty() && paused.frames.front().line == 1,
          "entry pause did not publish a Python stack frame");

  runtime.set_breakpoints({probe_call_line});
  runtime.continue_script();
  paused = wait_for_script_pause(runtime, paused.revision);
  require(paused.current_line == probe_call_line && !paused.frames.empty() &&
              paused.frames.front().function == "run",
          "script breakpoint did not stop at the scenario probe");
  require(paused.breakpoints == std::vector<std::uint32_t>{probe_call_line},
          "script breakpoint state was not published");

  runtime.step_into_script();
  paused = wait_for_script_pause(runtime, paused.revision);
  require(paused.current_line == probe_body_line && !paused.frames.empty() &&
              paused.frames.front().function == "_script_debug_probe",
          "script step-into did not enter the probe helper");

  runtime.step_out_script();
  paused = wait_for_script_pause(runtime, paused.revision);
  require(paused.current_line == probe_check_line && !paused.frames.empty() &&
              paused.frames.front().function == "run",
          "script step-out did not return to the scenario");

  runtime.step_over_script();
  paused = wait_for_script_pause(runtime, paused.revision);
  require(paused.current_line == first_scenario_line && !paused.frames.empty() &&
              paused.frames.front().function == "run",
          "script step-over did not advance in the scenario frame");
  runtime.set_breakpoints({});
  runtime.continue_script();
}

void exercise_case(const char *script, const char *arch,
                   const char *executable, const char *qemu_executable,
                   const char *input, const char *scenario,
                   int expected_exit) {
  set_environment("MYDBG_CROSS_MODE",
                  qemu_executable == nullptr ? "native" : "connected");
  set_environment("MYDBG_CROSS_ARCH", arch);
  set_environment("MYDBG_CROSS_EXECUTABLE", executable);
  set_environment("MYDBG_CROSS_SEED", input);
  set_environment("MYDBG_CROSS_CASE", scenario);
  const std::string expected_exit_text = std::to_string(expected_exit);
  set_environment("MYDBG_CROSS_EXPECTED_EXIT", expected_exit_text.c_str());
  debugger::scripting::PythonHost host;

  std::unique_ptr<QemuUserStub> qemu;
  if (qemu_executable != nullptr) {
    qemu =
        std::make_unique<QemuUserStub>(qemu_executable, executable, input);
  }
  debugger::LldbEngine engine;
  if (qemu) {
    complete(engine.connect_remote({
        .executable = executable,
        .endpoint = qemu->endpoint(),
        .mode = debugger::SessionMode::QemuUser,
    }));
    const debugger::SessionSnapshot connected = wait_for_engine(
        engine, [](const debugger::SessionSnapshot &snapshot) {
          return snapshot.state == debugger::SessionState::Stopped ||
                 snapshot.state == debugger::SessionState::Error;
        });
    require(connected.state == debugger::SessionState::Stopped,
            connected.error.empty() ? "remote inferior did not stop"
                                    : connected.error);
  }

  debugger::scripting::PythonRuntime runtime{engine};
  exercise_script_debugger(runtime, script);
  require(runtime.wait_for_completion(90s),
          std::string{"cross-architecture Python "} + scenario +
              " scenario timed out");
  const debugger::scripting::ScriptSnapshot result = runtime.snapshot();
  const std::string stdout_marker =
      std::string{"python-cross-arch-stdout="} + arch;
  const std::string stderr_marker =
      std::string{"python-cross-arch-stderr="} + arch;
  require(result.output.find(stdout_marker) != std::string::npos,
          "Python stdout was not captured");
  require(result.output.find(stderr_marker) != std::string::npos,
          "Python stderr was not captured");
  require(!result.control_lease,
          "completed Python scenario retained the debugger control lease");
  if (qemu && engine.snapshot().state == debugger::SessionState::Exited) {
    int qemu_status = 0;
    require(qemu->wait_for_exit(10s, qemu_status),
            "QEMU did not exit after the remote inferior");
    require(WIFEXITED(qemu_status) &&
                WEXITSTATUS(qemu_status) == expected_exit,
            "QEMU user process did not preserve the inferior exit status");
  }
  if (result.status != debugger::scripting::ScriptStatus::Succeeded) {
    throw std::runtime_error(std::string{"cross-architecture Python "} +
                             scenario + " scenario failed:\n" +
                             result.traceback + "\n" + result.output);
  }
  const std::string success_marker =
      std::string{"python-cross-arch-ok="} + arch;
  require(result.output.find(success_marker) != std::string::npos,
          "Python scenario success marker was not captured");
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 6) {
    std::fprintf(stderr,
                 "usage: %s SCRIPT --native ARCH EXECUTABLE SEED\n"
                 "       %s SCRIPT --qemu ARCH EXECUTABLE QEMU_EXECUTABLE\n",
                 argv[0], argv[0]);
    return 2;
  }

  const std::string_view mode{argv[2]};
  if (mode != "--native" && mode != "--qemu") {
    std::fprintf(stderr, "unknown Python matrix mode: %s\n", argv[2]);
    return 2;
  }

  try {
    const bool qemu_mode = mode == "--qemu";
    const char *qemu_executable = qemu_mode ? argv[5] : nullptr;
    const char *success_input = qemu_mode ? "CTF!" : argv[5];
    exercise_case(argv[1], argv[3], argv[4], qemu_executable, success_input,
                  "success", 0);
  } catch (const std::exception &error) {
    std::fprintf(stderr, "Python cross-architecture failure (%s): %s\n", argv[3],
                 error.what());
    return 1;
  }
  return 0;
}
