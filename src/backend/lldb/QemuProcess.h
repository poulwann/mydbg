#pragma once

#include "backend/DebuggerTypes.h"

#include <sys/types.h>

namespace debugger::lldb_detail {

// Created and destroyed on the LLDB worker. The engine provides stable ABI
// storage, but only this owner operates on its process and pipe handles.
class QemuProcess final {
public:
  QemuProcess(SessionSnapshot &output, pid_t &pid, int &stdin_fd,
              int &stdout_fd)
      : output_(output), pid_(pid), stdin_fd_(stdin_fd), stdout_fd_(stdout_fd) {
  }
  ~QemuProcess();

  QemuProcess(const QemuProcess &) = delete;
  QemuProcess &operator=(const QemuProcess &) = delete;

  bool start(const RemoteOptions &options, std::string &endpoint,
             std::string &failure);
  void drain_output();
  void stop();
  bool owns_stdin() const noexcept { return stdin_fd_ >= 0; }
  bool send_stdin(std::string_view bytes, std::string &failure);

private:
  SessionSnapshot &output_;
  pid_t &pid_;
  int &stdin_fd_;
  int &stdout_fd_;
};

} // namespace debugger::lldb_detail
