#include "RemoteProcessHarness.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace std::chrono_literals;

namespace debugger::test {
namespace {

class FileDescriptor final {
public:
  explicit FileDescriptor(int descriptor = -1) noexcept
      : descriptor_(descriptor) {}
  ~FileDescriptor() {
    if (descriptor_ >= 0) {
      ::close(descriptor_);
    }
  }

  FileDescriptor(const FileDescriptor &) = delete;
  FileDescriptor &operator=(const FileDescriptor &) = delete;

  [[nodiscard]] int get() const noexcept { return descriptor_; }
  void close() noexcept {
    if (descriptor_ >= 0) {
      ::close(descriptor_);
      descriptor_ = -1;
    }
  }

private:
  int descriptor_;
};

[[noreturn]] void system_failure(std::string_view operation) {
  throw std::runtime_error(std::string{operation} + ": " +
                           std::strerror(errno));
}

std::uint16_t reserve_loopback_port() {
  FileDescriptor descriptor{::socket(AF_INET, SOCK_STREAM, 0)};
  if (descriptor.get() < 0) {
    system_failure("unable to create a loopback socket");
  }

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = 0;
  if (::bind(descriptor.get(), reinterpret_cast<sockaddr *>(&address),
             sizeof(address)) != 0) {
    system_failure("unable to reserve a loopback port");
  }

  socklen_t size = sizeof(address);
  if (::getsockname(descriptor.get(), reinterpret_cast<sockaddr *>(&address),
                    &size) != 0) {
    system_failure("unable to inspect a loopback port");
  }
  const std::uint16_t port = ntohs(address.sin_port);
  if (port == 0) {
    throw std::runtime_error("the kernel returned an invalid loopback port");
  }
  return port;
}

bool port_is_claimed(std::uint16_t port) {
  FileDescriptor descriptor{::socket(AF_INET, SOCK_STREAM, 0)};
  if (descriptor.get() < 0) {
    system_failure("unable to create a listener probe socket");
  }

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  if (::bind(descriptor.get(), reinterpret_cast<sockaddr *>(&address),
             sizeof(address)) == 0) {
    return false;
  }
  if (errno == EADDRINUSE) {
    return true;
  }
  system_failure("unable to probe the QEMU listener");
}

std::string read_lldb_server_port(int descriptor, ChildProcess &child,
                                  std::chrono::milliseconds timeout) {
  const int flags = ::fcntl(descriptor, F_GETFL, 0);
  if (flags < 0 || ::fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) != 0) {
    system_failure("unable to configure the lldb-server port pipe");
  }

  const auto deadline = std::chrono::steady_clock::now() + timeout;
  std::array<char, 32> buffer{};
  while (std::chrono::steady_clock::now() < deadline) {
    if (!child.running()) {
      throw std::runtime_error(
          "lldb-server exited before reporting its listening port");
    }

    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    pollfd event{.fd = descriptor, .events = POLLIN | POLLHUP, .revents = 0};
    const int waited = ::poll(&event, 1, static_cast<int>(
                                          std::min(remaining, 50ms).count()));
    if (waited < 0) {
      if (errno == EINTR) {
        continue;
      }
      system_failure("unable to wait for the lldb-server port");
    }
    if (waited == 0) {
      continue;
    }
    if ((event.revents & (POLLERR | POLLNVAL)) != 0) {
      throw std::runtime_error("lldb-server port pipe failed");
    }

    const ssize_t size = ::read(descriptor, buffer.data(), buffer.size() - 1U);
    if (size < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
        continue;
      }
      system_failure("unable to read the lldb-server port");
    }
    if (size == 0) {
      throw std::runtime_error(
          "lldb-server closed its port pipe without a listening port");
    }

    const std::string_view text{buffer.data(), static_cast<std::size_t>(size)};
    const std::size_t digits = text.find_first_not_of("0123456789");
    const std::string_view number = text.substr(0, digits);
    unsigned int port = 0;
    const auto parsed =
        std::from_chars(number.data(), number.data() + number.size(), port);
    if (number.empty() || parsed.ec != std::errc{} || port == 0 ||
        port > 65535U) {
      throw std::runtime_error(
          "lldb-server reported an invalid listening port");
    }
    return std::to_string(port);
  }
  throw std::runtime_error(
      "timed out waiting for lldb-server to report its listening port");
}

bool retryable_connection_error(std::string message) {
  std::ranges::transform(message, message.begin(), [](unsigned char character) {
    return static_cast<char>(std::tolower(character));
  });
  return message.find("connection refused") != std::string::npos ||
         message.find("failed to connect") != std::string::npos ||
         message.find("unable to create lldb_private::process") !=
             std::string::npos;
}

} // namespace

ChildProcess::ChildProcess(pid_t process_id) noexcept : process_id_(process_id) {}

ChildProcess::~ChildProcess() { terminate(); }

ChildProcess::ChildProcess(ChildProcess &&other) noexcept
    : process_id_(std::exchange(other.process_id_, -1)),
      status_(std::move(other.status_)) {
  other.status_.reset();
}

ChildProcess &ChildProcess::operator=(ChildProcess &&other) noexcept {
  if (this == &other) {
    return *this;
  }
  terminate();
  process_id_ = std::exchange(other.process_id_, -1);
  status_ = std::move(other.status_);
  other.status_.reset();
  return *this;
}

ChildProcess ChildProcess::spawn(const std::vector<std::string> &arguments) {
  if (arguments.empty() || arguments.front().empty()) {
    throw std::runtime_error("cannot spawn a process without an executable");
  }
  std::vector<char *> argv;
  argv.reserve(arguments.size() + 1U);
  for (const std::string &argument : arguments) {
    argv.push_back(const_cast<char *>(argument.c_str()));
  }
  argv.push_back(nullptr);

  const pid_t process_id = ::fork();
  if (process_id < 0) {
    system_failure("unable to fork child process");
  }
  if (process_id == 0) {
    ::execvp(argv.front(), argv.data());
    std::fprintf(stderr, "unable to execute %s: %s\n", argv.front(),
                 std::strerror(errno));
    ::_exit(127);
  }
  return ChildProcess{process_id};
}

bool ChildProcess::reap_without_wait() noexcept {
  if (process_id_ <= 0) {
    return status_.has_value();
  }
  int status = 0;
  pid_t observed = -1;
  do {
    observed = ::waitpid(process_id_, &status, WNOHANG);
  } while (observed < 0 && errno == EINTR);
  if (observed == process_id_) {
    status_ = status;
    process_id_ = -1;
    return true;
  }
  if (observed < 0) {
    process_id_ = -1;
  }
  return false;
}

bool ChildProcess::running() noexcept {
  if (process_id_ <= 0) {
    return false;
  }
  static_cast<void>(reap_without_wait());
  return process_id_ > 0;
}

bool ChildProcess::wait_for_exit(std::chrono::milliseconds timeout,
                                 int &status) noexcept {
  if (status_) {
    status = *status_;
    return true;
  }
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  do {
    if (reap_without_wait() && status_) {
      status = *status_;
      return true;
    }
    if (process_id_ <= 0) {
      return false;
    }
    std::this_thread::sleep_for(10ms);
  } while (std::chrono::steady_clock::now() < deadline);
  if (reap_without_wait() && status_) {
    status = *status_;
    return true;
  }
  return false;
}

void ChildProcess::terminate() noexcept {
  if (!running()) {
    return;
  }
  const pid_t process_id = process_id_;
  static_cast<void>(::kill(process_id, SIGTERM));
  int ignored = 0;
  if (wait_for_exit(1s, ignored)) {
    return;
  }
  static_cast<void>(::kill(process_id, SIGKILL));
  int status = 0;
  pid_t observed = -1;
  do {
    observed = ::waitpid(process_id, &status, 0);
  } while (observed < 0 && errno == EINTR);
  if (observed == process_id) {
    status_ = status;
  }
  process_id_ = -1;
}

LldbServerStub::LldbServerStub(const char *lldb_server, const char *executable,
                               const char *argument,
                               std::chrono::milliseconds startup_timeout) {
  int descriptors[2]{};
  if (::pipe(descriptors) != 0) {
    system_failure("unable to create the lldb-server port pipe");
  }
  FileDescriptor read_end{descriptors[0]};
  FileDescriptor write_end{descriptors[1]};

  const pid_t process_id = ::fork();
  if (process_id < 0) {
    system_failure("unable to fork lldb-server");
  }
  if (process_id == 0) {
    read_end.close();
    const std::string descriptor = std::to_string(write_end.get());
    if (argument != nullptr) {
      ::execl(lldb_server, lldb_server, "gdbserver", "--pipe",
              descriptor.c_str(), "127.0.0.1:0", "--", executable, argument,
              static_cast<char *>(nullptr));
    } else {
      ::execl(lldb_server, lldb_server, "gdbserver", "--pipe",
              descriptor.c_str(), "127.0.0.1:0", "--", executable,
              static_cast<char *>(nullptr));
    }
    std::fprintf(stderr, "unable to execute lldb-server: %s\n",
                 std::strerror(errno));
    ::_exit(127);
  }

  child_ = ChildProcess{process_id};
  write_end.close();
  const std::string port =
      read_lldb_server_port(read_end.get(), child_, startup_timeout);
  if (!child_.running()) {
    throw std::runtime_error(
        "lldb-server exited after reporting its listening port");
  }
  endpoint_ = "connect://127.0.0.1:" + port;
}

QemuUserStub::QemuUserStub(const char *qemu, const char *executable,
                           const char *argument)
    : qemu_(qemu), executable_(executable) {
  if (argument != nullptr) {
    argument_ = argument;
  }
  start_candidate();
}

void QemuUserStub::start_candidate() {
  child_.terminate();
  const std::uint16_t port = reserve_loopback_port();
  port_ = std::to_string(port);
  endpoint_ = "connect://127.0.0.1:" + port_;
  std::vector<std::string> arguments{qemu_, "-g", port_, executable_};
  if (argument_) {
    arguments.push_back(*argument_);
  }
  child_ = ChildProcess::spawn(arguments);
}

void QemuUserStub::wait_for_listener(std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  unsigned int launches = 1;
  while (std::chrono::steady_clock::now() < deadline) {
    if (!child_.running()) {
      if (launches >= 8U) {
        throw std::runtime_error(
            "QEMU repeatedly exited before opening its GDB listener");
      }
      start_candidate();
      ++launches;
      continue;
    }
    const unsigned long parsed = std::stoul(port_);
    if (port_is_claimed(static_cast<std::uint16_t>(parsed)) &&
        child_.running()) {
      return;
    }
    std::this_thread::sleep_for(10ms);
  }
  throw std::runtime_error("timed out waiting for the QEMU GDB listener");
}

SessionSnapshot connect_qemu_user(LldbEngine &engine, QemuUserStub &stub,
                                  std::chrono::milliseconds timeout,
                                  std::string_view operation) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  std::string last_error{"connection was not attempted"};
  unsigned int restarts = 0;
  while (std::chrono::steady_clock::now() < deadline) {
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - std::chrono::steady_clock::now());
    stub.wait_for_listener(
        std::min(remaining, std::chrono::milliseconds{10000}));

    CommandTicket ticket = engine.connect_remote({
        .executable = stub.executable_,
        .endpoint = stub.endpoint_,
        .mode = SessionMode::QemuUser,
    });
    if (!ticket.valid()) {
      throw std::runtime_error(std::string{operation} +
                               " returned no command ticket");
    }
    const auto command_timeout =
        std::min(remaining, std::chrono::milliseconds{5000});
    if (!ticket.wait_for(command_timeout)) {
      throw std::runtime_error(std::string{operation} + " timed out");
    }
    const CommandResult result = ticket.get();
    if (result.success) {
      SessionSnapshot state = engine.snapshot();
      while (state.state != SessionState::Stopped &&
             state.state != SessionState::Error &&
             std::chrono::steady_clock::now() < deadline) {
        const auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        const auto update = engine.wait_for_update(state.revision, wait);
        if (!update) {
          break;
        }
        state = *update;
      }
      if (state.state == SessionState::Stopped) {
        return state;
      }
      last_error = state.error.empty() ? "remote target did not stop"
                                       : state.error;
    } else {
      last_error = result.message;
    }

    if (!retryable_connection_error(last_error)) {
      throw std::runtime_error(std::string{operation} + " failed: " +
                               last_error);
    }
    if (!stub.child_.running() ||
        last_error.find("lldb_private::Process") != std::string::npos) {
      if (++restarts >= 8U) {
        break;
      }
      stub.start_candidate();
    }
    std::this_thread::sleep_for(10ms);
  }
  throw std::runtime_error(std::string{operation} + " failed: " + last_error);
}

} // namespace debugger::test
