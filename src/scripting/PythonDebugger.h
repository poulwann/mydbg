#pragma once

#include "scripting/PythonBindingTypes.h"

#include <pybind11/pybind11.h>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace debugger {
class LldbEngine;
}

namespace debugger::scripting::detail {

class PythonProcess;

// Per-job execution adapter. Only this layer submits debugger commands and
// releases the GIL while waiting; registration code only describes the API.
class PythonDebugger final
    : public std::enable_shared_from_this<PythonDebugger> {
public:
  PythonDebugger(LldbEngine &engine,
                 std::shared_ptr<std::atomic_bool> cancellation);

  PythonSnapshot load(const std::string &executable, double timeout);
  std::shared_ptr<PythonProcess>
  launch(const std::vector<std::string> &argv, const std::string &stop_at,
         const std::map<std::string, std::string> &environment,
         const std::string &working_directory, double timeout,
         const std::string &stdin_path);
  std::shared_ptr<PythonProcess> attach(std::uint64_t process_id,
                                        double timeout);
  std::shared_ptr<PythonProcess> connect_remote(
      const std::string &executable, const std::string &endpoint,
      const std::string &mode, double timeout, const std::string &qemu,
      const std::string &sysroot, const std::vector<std::string> &arguments,
      const std::string &working_directory, const std::string &stdin_file);
  std::shared_ptr<PythonProcess> restart(double timeout);
  void detach(double timeout);
  void terminate(double timeout);
  void continue_execution(double timeout);
  PythonSnapshot continue_and_wait(double timeout);
  void interrupt(double timeout);
  PythonSnapshot interrupt_and_wait(double timeout);
  PythonSnapshot step_instruction(bool step_over, double timeout);
  PythonSnapshot run_to(std::uint64_t address, double timeout);
  PythonSnapshot disassemble(std::uint64_t address, double timeout);
  PythonSnapshot wait_for_stop(double timeout);
  PythonSnapshot wait_for_exit(double timeout);
  PythonSnapshot snapshot() const;
  PythonExpressionResult evaluate(const std::string &expression,
                                  double timeout);
  std::uint64_t read_register(const std::string &name, double timeout);
  void write_register(const std::string &name, std::uint64_t value,
                      double timeout);
  pybind11::bytes read_memory(std::uint64_t address, std::size_t size,
                              double timeout);
  void write_memory(std::uint64_t address, const pybind11::bytes &value,
                    double timeout);
  void select_thread(std::uint64_t thread_id, double timeout);
  void select_frame(std::uint64_t thread_id, std::uint32_t frame_index,
                    double timeout);
  std::uint32_t set_breakpoint(const std::string &specification,
                               double timeout);
  void remove_breakpoint(std::uint32_t id, double timeout);
  void enable_breakpoint(std::uint32_t id, bool enabled, double timeout);
  std::vector<BreakpointInfo> list_breakpoints() const;
  CommandResult execute(const std::string &command, double timeout);

private:
  friend class PythonProcess;

  std::shared_ptr<PythonProcess> launch_process(LaunchOptions options,
                                                double timeout);
  void send(const std::string &bytes, double timeout);
  SessionSnapshot wait_for_output(std::uint64_t revision,
                                  std::chrono::milliseconds timeout,
                                  std::uint64_t generation);
  std::optional<std::uint64_t>
  numeric_result(const CommandResult &result,
                 std::optional<std::string_view> register_name) const;
  PythonSnapshot wait_for_next_stop(const SessionSnapshot &previous,
                                    double timeout,
                                    bool accept_exit = true) const;
  void check_cancelled() const;
  CommandResult await(CommandTicket ticket,
                      std::chrono::milliseconds timeout) const;
  template <typename Predicate>
  SessionSnapshot wait_until(const Predicate &predicate,
                             std::chrono::milliseconds timeout,
                             std::uint64_t generation) const;

  LldbEngine &engine_;
  std::shared_ptr<std::atomic_bool> cancellation_;
  std::optional<LaunchOptions> last_launch_options_;
};

// Owns its output cursor and retains the job adapter, but cannot cross a
// session generation. A process object never owns the engine or interpreter.
class PythonProcess final {
public:
  PythonProcess(std::shared_ptr<PythonDebugger> debugger,
                std::uint64_t generation, std::uint64_t cursor);

  void send(const pybind11::bytes &data, double timeout);
  void sendline(const pybind11::bytes &data, double timeout);
  pybind11::bytes recv(std::size_t size, double timeout);
  pybind11::bytes recvuntil(const pybind11::bytes &delimiter, double timeout);

private:
  void collect(const SessionSnapshot &snapshot);
  void fill_pending(std::chrono::milliseconds timeout, std::string_view marker);

  std::shared_ptr<PythonDebugger> debugger_;
  std::uint64_t generation_{};
  std::uint64_t cursor_{};
  std::string pending_;
};

} // namespace debugger::scripting::detail
