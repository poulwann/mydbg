#pragma once

#include "backend/lldb/LldbEngine.h"

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <sys/types.h>

namespace debugger::test {

class ChildProcess final {
public:
  ChildProcess() noexcept = default;
  explicit ChildProcess(pid_t process_id) noexcept;
  ~ChildProcess();

  ChildProcess(const ChildProcess &) = delete;
  ChildProcess &operator=(const ChildProcess &) = delete;
  ChildProcess(ChildProcess &&other) noexcept;
  ChildProcess &operator=(ChildProcess &&other) noexcept;

  [[nodiscard]] static ChildProcess
  spawn(const std::vector<std::string> &arguments);

  [[nodiscard]] bool running() noexcept;
  [[nodiscard]] bool wait_for_exit(std::chrono::milliseconds timeout,
                                   int &status) noexcept;
  [[nodiscard]] std::optional<int> status() const noexcept { return status_; }
  void terminate() noexcept;

private:
  bool reap_without_wait() noexcept;

  pid_t process_id_{-1};
  std::optional<int> status_;
};

class LldbServerStub final {
public:
  LldbServerStub(const char *lldb_server, const char *executable,
                 const char *argument,
                 std::chrono::milliseconds startup_timeout =
                     std::chrono::seconds{10});

  LldbServerStub(const LldbServerStub &) = delete;
  LldbServerStub &operator=(const LldbServerStub &) = delete;

  [[nodiscard]] const std::string &endpoint() const noexcept {
    return endpoint_;
  }

private:
  ChildProcess child_;
  std::string endpoint_;
};

class QemuUserStub final {
public:
  QemuUserStub(const char *qemu, const char *executable,
               const char *argument);

  QemuUserStub(const QemuUserStub &) = delete;
  QemuUserStub &operator=(const QemuUserStub &) = delete;

  [[nodiscard]] const std::string &endpoint() const noexcept {
    return endpoint_;
  }
  [[nodiscard]] bool wait_for_exit(std::chrono::milliseconds timeout,
                                   int &status) noexcept {
    return child_.wait_for_exit(timeout, status);
  }
  void wait_for_listener(std::chrono::milliseconds timeout);

private:
  friend SessionSnapshot connect_qemu_user(LldbEngine &, QemuUserStub &,
                                            std::chrono::milliseconds,
                                            std::string_view);

  void start_candidate();

  std::string qemu_;
  std::string executable_;
  std::optional<std::string> argument_;
  ChildProcess child_;
  std::string port_;
  std::string endpoint_;
};

[[nodiscard]] SessionSnapshot
connect_qemu_user(LldbEngine &engine, QemuUserStub &stub,
                  std::chrono::milliseconds timeout,
                  std::string_view operation);

} // namespace debugger::test
