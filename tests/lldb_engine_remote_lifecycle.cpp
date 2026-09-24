#include "EngineTestSupport.h"

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace std::chrono_literals;

namespace {

using debugger::test::require;
using debugger::test::wait_for_state;

void stop_child(pid_t &process_id) noexcept {
  if (process_id <= 0) {
    return;
  }
  int status = 0;
  const pid_t initial = ::waitpid(process_id, &status, WNOHANG);
  if (initial == process_id || (initial < 0 && errno == ECHILD)) {
    process_id = -1;
    return;
  }

  ::kill(process_id, SIGTERM);
  for (int attempt = 0; attempt < 50; ++attempt) {
    const pid_t result = ::waitpid(process_id, &status, WNOHANG);
    if (result == process_id || (result < 0 && errno == ECHILD)) {
      process_id = -1;
      return;
    }
    std::this_thread::sleep_for(10ms);
  }

  ::kill(process_id, SIGKILL);
  while (::waitpid(process_id, &status, 0) < 0 && errno == EINTR) {
  }
  process_id = -1;
}

bool wait_for_readable(int descriptor, std::chrono::milliseconds timeout) {
  pollfd event{.fd = descriptor, .events = POLLIN, .revents = 0};
  int result = 0;
  do {
    result = ::poll(&event, 1, static_cast<int>(timeout.count()));
  } while (result < 0 && errno == EINTR);
  return result > 0 && (event.revents & POLLIN) != 0;
}

class RemoteStub final {
public:
  RemoteStub(const char *debuggee, const char *lldb_server) {
    int port_pipe[2]{};
    require(::pipe(port_pipe) == 0, "failed to create lldb-server port pipe");
    process_id_ = ::fork();
    if (process_id_ < 0) {
      ::close(port_pipe[0]);
      ::close(port_pipe[1]);
      throw std::runtime_error("failed to fork lldb-server");
    }
    if (process_id_ == 0) {
      ::close(port_pipe[0]);
      const std::string descriptor = std::to_string(port_pipe[1]);
      ::execl(lldb_server, lldb_server, "gdbserver", "--pipe",
              descriptor.c_str(), "127.0.0.1:0", "--", debuggee, "CTF!",
              static_cast<char *>(nullptr));
      std::fprintf(stderr, "failed to execute lldb-server: %s\n",
                   std::strerror(errno));
      _exit(127);
    }

    ::close(port_pipe[1]);
    if (!wait_for_readable(port_pipe[0], 5s)) {
      ::close(port_pipe[0]);
      stop_child(process_id_);
      throw std::runtime_error("lldb-server did not report a port in time");
    }
    std::array<char, 32> port{};
    ssize_t size = 0;
    do {
      size = ::read(port_pipe[0], port.data(), port.size() - 1);
    } while (size < 0 && errno == EINTR);
    ::close(port_pipe[0]);
    if (size <= 0) {
      stop_child(process_id_);
      throw std::runtime_error("lldb-server did not report its listening port");
    }
    port[static_cast<std::size_t>(size)] = '\0';
    const std::string_view text{port.data()};
    const std::size_t end = text.find_first_not_of("0123456789");
    if (end == 0) {
      stop_child(process_id_);
      throw std::runtime_error("lldb-server reported an invalid port");
    }
    endpoint_ = "connect://127.0.0.1:" + std::string{text.substr(0, end)};
  }

  RemoteStub(const RemoteStub &) = delete;
  RemoteStub &operator=(const RemoteStub &) = delete;

  ~RemoteStub() { stop_child(process_id_); }

  [[nodiscard]] const std::string &endpoint() const { return endpoint_; }

private:
  pid_t process_id_{-1};
  std::string endpoint_;
};

class SilentAcceptServer final {
public:
  SilentAcceptServer() {
    const int listener = ::socket(AF_INET, SOCK_STREAM, 0);
    require(listener >= 0, "failed to create silent server socket");

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (::bind(listener, reinterpret_cast<const sockaddr *>(&address),
               sizeof(address)) != 0 ||
        ::listen(listener, 1) != 0) {
      ::close(listener);
      throw std::runtime_error("failed to bind silent server socket");
    }
    socklen_t address_size = sizeof(address);
    if (::getsockname(listener, reinterpret_cast<sockaddr *>(&address),
                      &address_size) != 0) {
      ::close(listener);
      throw std::runtime_error("failed to query silent server port");
    }

    int accepted_pipe[2]{};
    if (::pipe(accepted_pipe) != 0) {
      ::close(listener);
      throw std::runtime_error("failed to create silent server signal pipe");
    }
    process_id_ = ::fork();
    if (process_id_ < 0) {
      ::close(listener);
      ::close(accepted_pipe[0]);
      ::close(accepted_pipe[1]);
      throw std::runtime_error("failed to fork silent server");
    }
    if (process_id_ == 0) {
      ::close(accepted_pipe[0]);
      const int connection = ::accept(listener, nullptr, nullptr);
      ::close(listener);
      if (connection < 0) {
        _exit(126);
      }
      const char ready = '1';
      static_cast<void>(::write(accepted_pipe[1], &ready, 1));
      ::close(accepted_pipe[1]);
      for (;;) {
        ::pause();
      }
    }

    ::close(listener);
    ::close(accepted_pipe[1]);
    accepted_descriptor_ = accepted_pipe[0];
    endpoint_ = "connect://127.0.0.1:" +
                std::to_string(static_cast<unsigned>(ntohs(address.sin_port)));
  }

  SilentAcceptServer(const SilentAcceptServer &) = delete;
  SilentAcceptServer &operator=(const SilentAcceptServer &) = delete;

  ~SilentAcceptServer() {
    if (accepted_descriptor_ >= 0) {
      ::close(accepted_descriptor_);
    }
    stop_child(process_id_);
  }

  [[nodiscard]] const std::string &endpoint() const { return endpoint_; }

  void wait_for_accept() {
    require(wait_for_readable(accepted_descriptor_, 5s),
            "silent server did not accept the remote connection");
    char ready = 0;
    ssize_t size = 0;
    do {
      size = ::read(accepted_descriptor_, &ready, 1);
    } while (size < 0 && errno == EINTR);
    require(size == 1 && ready == '1',
            "silent server acceptance signal was invalid");
  }

private:
  pid_t process_id_{-1};
  int accepted_descriptor_{-1};
  std::string endpoint_;
};


debugger::CommandResult await(debugger::CommandTicket ticket,
                              std::chrono::milliseconds timeout,
                              const char *timeout_message) {
  require(ticket.wait_for(timeout), timeout_message);
  return ticket.get();
}

debugger::SessionSnapshot connect_and_stop(debugger::LldbEngine &engine,
                                           std::string executable,
                                           const std::string &endpoint) {
  const debugger::CommandResult result = await(
      engine.connect_remote({.executable = std::move(executable),
                             .endpoint = endpoint,
                             .mode = debugger::SessionMode::Remote}),
      15s, "remote connection did not complete");
  require(result.success, result.message.c_str());
  const debugger::SessionSnapshot state = wait_for_state(
      engine, engine.snapshot(), [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped ||
               snapshot.state == debugger::SessionState::Error;
      });
  require(state.state == debugger::SessionState::Stopped,
          state.error.empty() ? "remote process did not stop"
                              : state.error.c_str());
  return state;
}

void exercise_invalid_options_and_reconnect(const char *debuggee,
                                            const char *lldb_server) {
  debugger::LldbEngine engine;
  wait_for_state(engine, engine.snapshot(),
                 [](const debugger::SessionSnapshot &snapshot) {
                   return snapshot.state == debugger::SessionState::NoTarget;
                 });

  const debugger::CommandResult launched = await(
      engine.launch({.executable = debuggee,
                     .arguments = {"CTF!"},
                     .stop_policy = debugger::LaunchStopPolicy::Entry}),
      15s, "local launch did not complete");
  require(launched.success, launched.message.c_str());
  debugger::SessionSnapshot state = wait_for_state(
      engine, engine.snapshot(), [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped ||
               snapshot.state == debugger::SessionState::Error;
      });
  require(state.state == debugger::SessionState::Stopped,
          "local debuggee did not stop");

  const std::uint64_t local_generation = state.generation;
  const std::uint64_t local_process = state.process_id;
  debugger::CommandResult invalid = await(
      engine.connect_remote({.executable = debuggee,
                             .endpoint = {},
                             .mode = debugger::SessionMode::Remote}),
      2s, "empty-endpoint request did not complete");
  require(!invalid.success, "empty remote endpoint was accepted");
  state = engine.snapshot();
  require(state.state == debugger::SessionState::Stopped &&
              state.generation == local_generation &&
              state.process_id == local_process,
          "empty remote endpoint damaged the live local session");

  invalid = await(engine.connect_remote({.executable = debuggee,
                                         .endpoint = "127.0.0.1:1",
                                         .mode = debugger::SessionMode::Local}),
                  2s, "local-mode remote request did not complete");
  require(!invalid.success, "local remote-session mode was accepted");
  state = engine.snapshot();
  require(state.state == debugger::SessionState::Stopped &&
              state.generation == local_generation &&
              state.process_id == local_process,
          "invalid remote mode damaged the live local session");

  RemoteStub first{debuggee, lldb_server};
  state = connect_and_stop(engine, debuggee, first.endpoint());
  require(state.process_is_remote, "remote API session lacks provenance");
  require(state.local_symbol_path == debuggee,
          "explicit local symbol image provenance was lost");

  const debugger::CommandResult scan =
      await(engine.scan_binary_strings(1, false), 5s,
            "binary string scan did not complete");
  require(scan.success, scan.message.c_str());
  state = engine.snapshot();
  require(state.binary_string_count != 0 && !state.binary_strings.empty(),
          "binary string scan produced no baseline results");
  const std::uint64_t first_generation = state.generation;

  RemoteStub second{debuggee, lldb_server};
  state = connect_and_stop(engine, {}, second.endpoint());
  require(state.generation > first_generation,
          "remote reconnect did not advance the generation");
  require(state.binary_strings.empty() && state.binary_string_count == 0 &&
              state.binary_strings_error.empty(),
          "remote reconnect leaked binary string scan state");
  require(state.local_symbol_path.empty(),
          "remote-reported path was treated as a local symbol image");

  await(engine.scan_binary_strings(1, false), 5s,
        "provenance-gated scan did not complete");
  state = engine.snapshot();
  require(state.binary_strings.empty() &&
              state.binary_strings_error.find("local symbol image") !=
                  std::string::npos,
          "binary scan opened a remote-reported target path");

  const std::uint64_t replacement_generation = state.generation;
  const std::uint64_t replacement_process = state.process_id;
  std::this_thread::sleep_for(250ms);
  state = engine.snapshot();
  require(state.generation == replacement_generation &&
              state.process_id == replacement_process &&
              state.state == debugger::SessionState::Stopped,
          "a stale process event overwrote the replacement session");

  const debugger::CommandResult continued =
      await(engine.continue_execution(), 5s,
            "replacement remote continue did not complete");
  require(continued.success, continued.message.c_str());
  state = wait_for_state(engine, engine.snapshot(),
                         [](const debugger::SessionSnapshot &snapshot) {
                           return snapshot.state ==
                                  debugger::SessionState::Exited;
                         });
  require(state.exit_status == 0, "replacement remote debuggee failed");
}

void exercise_console_remote_isolation(const char *debuggee,
                                       const char *lldb_server) {
  RemoteStub stub{debuggee, lldb_server};
  debugger::LldbEngine engine;
  wait_for_state(engine, engine.snapshot(),
                 [](const debugger::SessionSnapshot &snapshot) {
                   return snapshot.state == debugger::SessionState::NoTarget;
                 });
  const debugger::CommandResult loaded =
      await(engine.load(debuggee), 5s, "local target load did not complete");
  require(loaded.success, loaded.message.c_str());

  const debugger::CommandResult connected = await(
      engine.execute_command("process connect " + stub.endpoint()), 15s,
      "console process connect did not complete");
  require(connected.success, connected.message.c_str());
  debugger::SessionSnapshot state = wait_for_state(
      engine, engine.snapshot(), [](const debugger::SessionSnapshot &snapshot) {
        return snapshot.state == debugger::SessionState::Stopped ||
               snapshot.state == debugger::SessionState::Error;
      });
  require(state.state == debugger::SessionState::Stopped &&
              state.process_is_remote &&
              state.mode == debugger::SessionMode::Remote,
          "console process connect was not classified as remote");

  const debugger::CommandResult procinfo =
      await(engine.execute_command("procinfo"), 2s,
            "remote procinfo command did not complete");
  require(!procinfo.success &&
              procinfo.message.find("unavailable for remote sessions") !=
                  std::string::npos,
          "console remote procinfo accessed host /proc");
  const debugger::CommandResult auxv =
      await(engine.execute_command("auxv"), 2s,
            "remote auxv command did not complete");
  require(!auxv.success &&
              auxv.message.find("unavailable for remote sessions") !=
                  std::string::npos,
          "console remote auxv accessed host /proc");

  const debugger::CommandResult continued =
      await(engine.continue_execution(), 5s,
            "console remote continue did not complete");
  require(continued.success, continued.message.c_str());
  state = wait_for_state(engine, engine.snapshot(),
                         [](const debugger::SessionSnapshot &snapshot) {
                           return snapshot.state ==
                                  debugger::SessionState::Exited;
                         });
  require(state.exit_status == 0, "console remote debuggee failed");
}

void exercise_silent_connection_shutdown() {
  SilentAcceptServer server;
  debugger::CommandTicket connection;
  std::chrono::steady_clock::duration destruction_time{};
  {
    auto engine = std::make_unique<debugger::LldbEngine>();
    wait_for_state(*engine, engine->snapshot(),
                   [](const debugger::SessionSnapshot &snapshot) {
                     return snapshot.state == debugger::SessionState::NoTarget;
                   });
    connection = engine->connect_remote({.executable = {},
                                         .endpoint = server.endpoint(),
                                         .mode = debugger::SessionMode::Remote});
    wait_for_state(*engine, engine->snapshot(),
                   [](const debugger::SessionSnapshot &snapshot) {
                     return snapshot.state == debugger::SessionState::Connecting;
                   });
    server.wait_for_accept();
    const auto started = std::chrono::steady_clock::now();
    engine.reset();
    destruction_time = std::chrono::steady_clock::now() - started;
  }
  require(destruction_time < 10s,
          "engine destruction did not bound a silent remote connection");
  require(connection.wait_for(0ms),
          "cancelled remote connection ticket was not completed");
  require(!connection.get().success,
          "cancelled remote connection unexpectedly succeeded");
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 3) {
    std::fprintf(stderr, "usage: %s DEBUGGEE LLDB_SERVER\n", argv[0]);
    return 2;
  }

  try {
    exercise_invalid_options_and_reconnect(argv[1], argv[2]);
    exercise_console_remote_isolation(argv[1], argv[2]);
    exercise_silent_connection_shutdown();
  } catch (const std::exception &error) {
    std::fprintf(stderr, "remote lifecycle test failure: %s\n", error.what());
    return 1;
  }
  return 0;
}
