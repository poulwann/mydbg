#include "scripting/PythonBindings.h"
#include "localization/Localization.h"

#include <pybind11/embed.h>
#include <pybind11/stl.h>

#include <algorithm>
#include <cctype>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace py = pybind11;
using namespace std::chrono_literals;

namespace debugger::scripting {
namespace {

std::chrono::milliseconds timeout_from_seconds(double seconds) {
  if (!std::isfinite(seconds) || seconds <= 0.0 || seconds > 3600.0) {
    throw std::invalid_argument(
        l10n::text(l10n::Key::PythonBindingTimeoutRange));
  }
  return std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::duration<double>{seconds});
}

py::bytes python_bytes(const std::vector<std::uint8_t> &bytes) {
  return py::bytes{reinterpret_cast<const char *>(bytes.data()), bytes.size()};
}

std::string_view trim_numeric_text(std::string_view text) {
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.front())) != 0) {
    text.remove_prefix(1);
  }
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.back())) != 0) {
    text.remove_suffix(1);
  }
  return text;
}

std::optional<std::uint64_t>
parse_lldb_integer(std::string_view text) {
  text = trim_numeric_text(text);
  bool negative = false;
  if (!text.empty() && (text.front() == '+' || text.front() == '-')) {
    negative = text.front() == '-';
    text.remove_prefix(1);
  }

  int base = 10;
  if (text.starts_with("0x") || text.starts_with("0X")) {
    text.remove_prefix(2);
    base = 16;
  } else if (text.starts_with("0b") || text.starts_with("0B")) {
    text.remove_prefix(2);
    base = 2;
  } else if (text.starts_with("0o") || text.starts_with("0O")) {
    text.remove_prefix(2);
    base = 8;
  } else if (text.size() > 1 && text.front() == '0') {
    base = 8;
  }
  if (text.empty()) {
    return std::nullopt;
  }

  std::uint64_t magnitude = 0;
  const auto [end, error] = std::from_chars(
      text.data(), text.data() + text.size(), magnitude, base);
  if (error != std::errc{} || end != text.data() + text.size()) {
    return std::nullopt;
  }
  if (!negative) {
    return magnitude;
  }
  constexpr std::uint64_t maximum_negative_magnitude =
      std::uint64_t{1} << 63U;
  if (magnitude > maximum_negative_magnitude) {
    return std::nullopt;
  }
  return std::uint64_t{0} - magnitude;
}

bool is_usable_stop(const SessionSnapshot &snapshot) {
  return snapshot.state == SessionState::Stopped && snapshot.thread_id != 0 &&
         !snapshot.stack.empty();
}

std::optional<std::uint64_t>
captured_register_numeric(const SessionSnapshot &snapshot,
                          std::string_view name) {
  name = trim_numeric_text(name);
  if (!name.empty() && name.front() == '$') {
    name.remove_prefix(1);
  }
  const auto found =
      std::find_if(snapshot.registers.begin(), snapshot.registers.end(),
                   [name](const RegisterValue &value) {
                     return value.name == name && value.has_numeric_value;
                   });
  return found == snapshot.registers.end()
             ? std::nullopt
             : std::optional<std::uint64_t>{found->numeric_value};
}

struct PythonSnapshot {
  explicit PythonSnapshot(const SessionSnapshot &snapshot)
      : state(to_string(snapshot.state)), mode(to_string(snapshot.mode)),
        revision(snapshot.revision), generation(snapshot.generation),
        stop_revision(snapshot.stop_revision), target_path(snapshot.target_path),
        target_triple(snapshot.target_triple),
        architecture(snapshot.architecture), byte_order(snapshot.byte_order),
        address_byte_size(snapshot.address_byte_size),
        supports_intel_syntax(snapshot.supports_intel_syntax),
        intel_syntax(snapshot.intel_syntax), process_id(snapshot.process_id),
        thread_id(snapshot.thread_id), pc(snapshot.pc), sp(snapshot.sp),
        stop_reason(snapshot.stop_reason), error(snapshot.error),
        exit_status(snapshot.exit_status), registers(snapshot.registers),
        instructions(snapshot.instructions), breakpoints(snapshot.breakpoints),
        threads(snapshot.threads), modules(snapshot.modules),
        patches(snapshot.patches), output(snapshot.process_output) {}

  std::string state;
  std::string mode;
  std::uint64_t revision{};
  std::uint64_t generation{};
  std::uint64_t stop_revision{};
  std::string target_path;
  std::string target_triple;
  std::string architecture;
  std::string byte_order;
  std::uint32_t address_byte_size{};
  bool supports_intel_syntax{};
  bool intel_syntax{};
  std::uint64_t process_id{};
  std::uint64_t thread_id{};
  std::uint64_t pc{};
  std::uint64_t sp{};
  std::string stop_reason;
  std::string error;
  int exit_status{};
  std::vector<RegisterValue> registers;
  std::vector<InstructionRow> instructions;
  std::vector<BreakpointInfo> breakpoints;
  std::vector<ThreadInfo> threads;
  std::vector<ModuleInfo> modules;
  std::vector<PatchInfo> patches;
  std::string output;
};

struct PythonExpressionResult {
  std::string value;
  std::string type;
  std::string summary;
  std::optional<std::uint64_t> numeric_value;
};

class PythonProcess;

class PythonDebugger final
    : public std::enable_shared_from_this<PythonDebugger> {
public:
  PythonDebugger(LldbEngine &engine,
                 std::shared_ptr<std::atomic_bool> cancellation)
      : engine_(engine), cancellation_(std::move(cancellation)) {}

  PythonSnapshot load(const std::string &executable, double timeout) {
    await(engine_.load(executable), timeout_from_seconds(timeout));
    return PythonSnapshot{engine_.snapshot()};
  }

  std::shared_ptr<PythonProcess>
  launch(const std::vector<std::string> &argv, const std::string &stop_at,
         const std::map<std::string, std::string> &environment,
         const std::string &working_directory, double timeout,
         const std::string &stdin_path);

  std::shared_ptr<PythonProcess> attach(std::uint64_t process_id,
                                        double timeout);

  std::shared_ptr<PythonProcess>
  connect_remote(const std::string &executable, const std::string &endpoint,
                 const std::string &mode, double timeout,
                 const std::string &qemu, const std::string &sysroot,
                 const std::vector<std::string> &arguments,
                 const std::string &working_directory,
                 const std::string &stdin_file);

  std::shared_ptr<PythonProcess> restart(double timeout);

  void detach(double timeout) {
    await(engine_.detach(), timeout_from_seconds(timeout));
  }

  void terminate(double timeout) {
    const SessionSnapshot current = engine_.snapshot();
    if (current.state == SessionState::Exited || current.process_id == 0) {
      return;
    }
    await(engine_.terminate(), timeout_from_seconds(timeout));
    wait_until(
        [](const SessionSnapshot &snapshot) {
          return snapshot.state == SessionState::Exited;
        },
        timeout_from_seconds(timeout), current.generation);
  }

  void continue_execution(double timeout) {
    await(engine_.continue_execution(), timeout_from_seconds(timeout));
  }

  PythonSnapshot continue_and_wait(double timeout) {
    const SessionSnapshot current = engine_.snapshot();
    await(engine_.continue_execution(), timeout_from_seconds(timeout));
    return wait_for_next_stop(current, timeout);
  }

  void interrupt(double timeout) {
    await(engine_.stop(), timeout_from_seconds(timeout));
  }

  PythonSnapshot interrupt_and_wait(double timeout) {
    const SessionSnapshot current = engine_.snapshot();
    await(engine_.stop(), timeout_from_seconds(timeout));
    return wait_for_next_stop(current, timeout, false);
  }

  PythonSnapshot step_instruction(bool step_over, double timeout) {
    const SessionSnapshot current = engine_.snapshot();
    await(engine_.step_instruction(step_over), timeout_from_seconds(timeout));
    return wait_for_next_stop(current, timeout);
  }

  PythonSnapshot run_to(std::uint64_t address, double timeout) {
    const SessionSnapshot current = engine_.snapshot();
    await(engine_.run_to_address(address), timeout_from_seconds(timeout));
    return wait_for_next_stop(current, timeout);
  }

  PythonSnapshot wait_for_stop(double timeout) {
    const SessionSnapshot current = engine_.snapshot();
    return PythonSnapshot{wait_until(
        is_usable_stop, timeout_from_seconds(timeout), current.generation)};
  }

  PythonSnapshot wait_for_exit(double timeout) {
    const SessionSnapshot current = engine_.snapshot();
    return PythonSnapshot{wait_until(
        [](const SessionSnapshot &snapshot) {
          return snapshot.state == SessionState::Exited;
        },
        timeout_from_seconds(timeout), current.generation)};
  }

  PythonSnapshot snapshot() const { return PythonSnapshot{engine_.snapshot()}; }

  PythonExpressionResult evaluate(const std::string &expression,
                                  double timeout) {
    const CommandResult result =
        await(engine_.evaluate(expression), timeout_from_seconds(timeout));
    const std::string_view trimmed_expression = trim_numeric_text(expression);
    const auto numeric_value =
        numeric_result(result, trimmed_expression.starts_with('$')
                                   ? std::optional{trimmed_expression}
                                   : std::nullopt);
    return PythonExpressionResult{
        .value = result.value,
        .type = result.type,
        .summary = result.summary,
        .numeric_value = numeric_value,
    };
  }

  std::uint64_t read_register(const std::string &name, double timeout) {
    const CommandResult result =
        await(engine_.read_register(name), timeout_from_seconds(timeout));
    if (const auto value = numeric_result(result, name)) {
      return *value;
    }
    throw std::runtime_error(
        l10n::text(l10n::Key::PythonBindingRegisterNotInteger));
  }

  void write_register(const std::string &name, std::uint64_t value,
                      double timeout) {
    await(engine_.write_register(name, value), timeout_from_seconds(timeout));
  }

  py::bytes read_memory(std::uint64_t address, std::size_t size,
                        double timeout) {
    const CommandResult result = await(engine_.read_memory(address, size),
                                       timeout_from_seconds(timeout));
    return python_bytes(result.bytes);
  }

  void write_memory(std::uint64_t address, const py::bytes &value,
                    double timeout) {
    const std::string bytes = value;
    await(engine_.write_memory(
              address, std::vector<std::uint8_t>{bytes.begin(), bytes.end()}),
          timeout_from_seconds(timeout));
  }

  void select_thread(std::uint64_t thread_id, double timeout) {
    await(engine_.select_thread(thread_id), timeout_from_seconds(timeout));
  }

  void select_frame(std::uint64_t thread_id, std::uint32_t frame_index,
                    double timeout) {
    await(engine_.select_frame(thread_id, frame_index),
          timeout_from_seconds(timeout));
  }

  std::uint32_t set_breakpoint(const std::string &specification,
                               double timeout) {
    await(engine_.set_breakpoint(specification), timeout_from_seconds(timeout));
    const SessionSnapshot current = engine_.snapshot();
    if (current.breakpoints.empty()) {
      throw std::runtime_error(
          l10n::text(l10n::Key::PythonBindingBreakpointNotCreated));
    }
    return std::ranges::max_element(current.breakpoints, {}, &BreakpointInfo::id)
        ->id;
  }

  void remove_breakpoint(std::uint32_t id, double timeout) {
    await(engine_.remove_breakpoint(id), timeout_from_seconds(timeout));
  }

  void enable_breakpoint(std::uint32_t id, bool enabled, double timeout) {
    await(engine_.set_breakpoint_enabled(id, enabled),
          timeout_from_seconds(timeout));
  }

  std::vector<BreakpointInfo> list_breakpoints() const {
    return engine_.snapshot().breakpoints;
  }

  CommandResult execute(const std::string &command, double timeout) {
    return await(engine_.execute_command(command),
                 timeout_from_seconds(timeout));
  }

  void send(const std::string &bytes, double timeout) {
    await(engine_.send_stdin(bytes), timeout_from_seconds(timeout));
  }

  SessionSnapshot wait_for_output(std::uint64_t revision,
                                  std::chrono::milliseconds timeout,
                                  std::uint64_t generation) {
    check_cancelled();
    std::optional<SessionSnapshot> update;
    {
      py::gil_scoped_release release;
      update = engine_.wait_for_update(revision, timeout);
    }
    check_cancelled();
    if (!update) {
      return engine_.snapshot();
    }
    if (update->generation != generation) {
      throw std::runtime_error(
          l10n::text(l10n::Key::PythonBindingGenerationChangedWaiting));
    }
    if (update->state == SessionState::ShuttingDown) {
      throw std::runtime_error(
          l10n::text(l10n::Key::PythonBindingDebuggerShuttingDown));
    }
    return std::move(*update);
  }

private:
  friend class PythonProcess;

  std::shared_ptr<PythonProcess> launch_process(LaunchOptions options,
                                                double timeout);

  std::optional<std::uint64_t>
  numeric_result(const CommandResult &result,
                 std::optional<std::string_view> register_name) const {
    if (result.has_numeric_value) {
      return result.numeric_value;
    }
    if (const auto parsed = parse_lldb_integer(result.value)) {
      return parsed;
    }
    if (register_name) {
      const SessionSnapshot current = engine_.snapshot();
      if (current.generation == result.generation &&
          current.stop_revision == result.stop_revision) {
        return captured_register_numeric(current, *register_name);
      }
    }
    return std::nullopt;
  }

  PythonSnapshot wait_for_next_stop(const SessionSnapshot &previous,
                                    double timeout,
                                    bool accept_exit = true) const {
    return PythonSnapshot{wait_until(
        [stop_revision = previous.stop_revision,
         accept_exit](const SessionSnapshot &snapshot) {
          return (is_usable_stop(snapshot) &&
                  snapshot.stop_revision > stop_revision) ||
                 (accept_exit && snapshot.state == SessionState::Exited);
        },
        timeout_from_seconds(timeout), previous.generation)};
  }

  void check_cancelled() const {
    if (cancellation_->load()) {
      throw std::runtime_error(
          l10n::text(l10n::Key::PythonRuntimeScriptCancelled));
    }
  }

  CommandResult await(CommandTicket ticket,
                      std::chrono::milliseconds timeout) const {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    for (;;) {
      check_cancelled();
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        throw std::runtime_error(
            l10n::text(l10n::Key::PythonBindingCommandTimedOut));
      }
      const auto slice =
          std::min(50ms, std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - now));
      bool ready = false;
      {
        py::gil_scoped_release release;
        ready = ticket.wait_for(slice);
      }
      if (ready) {
        break;
      }
    }
    check_cancelled();
    const CommandResult result = ticket.get();
    if (!result.success) {
      throw std::runtime_error(result.message);
    }
    return result;
  }

  template <typename Predicate>
  SessionSnapshot wait_until(const Predicate &predicate,
                             std::chrono::milliseconds timeout,
                             std::uint64_t generation) const {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    SessionSnapshot current = engine_.snapshot();
    for (;;) {
      check_cancelled();
      if (current.generation != generation) {
        throw std::runtime_error(
            l10n::text(l10n::Key::PythonBindingGenerationChangedWaiting));
      }
      if (predicate(current)) {
        return current;
      }
      if (current.state == SessionState::Error) {
        throw std::runtime_error(
            current.error.empty()
                ? l10n::text(l10n::Key::PythonBindingDebuggerError)
                : current.error);
      }
      if (current.state == SessionState::ShuttingDown) {
        throw std::runtime_error(
            l10n::text(l10n::Key::PythonBindingDebuggerShuttingDown));
      }
      if (current.state == SessionState::Exited) {
        throw std::runtime_error(
            l10n::text(l10n::Key::PythonBindingProcessExitedWaiting));
      }
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        throw std::runtime_error(
            l10n::text(l10n::Key::PythonBindingStateWaitTimedOut));
      }
      const auto slice =
          std::min(50ms, std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - now));
      std::optional<SessionSnapshot> update;
      {
        py::gil_scoped_release release;
        update = engine_.wait_for_update(current.revision, slice);
      }
      if (update) {
        current = std::move(*update);
      }
    }
  }

  LldbEngine &engine_;
  std::shared_ptr<std::atomic_bool> cancellation_;
  std::optional<LaunchOptions> last_launch_options_;
};

class PythonProcess final {
public:
  PythonProcess(std::shared_ptr<PythonDebugger> debugger,
                std::uint64_t generation, std::uint64_t cursor)
      : debugger_(std::move(debugger)), generation_(generation),
        cursor_(cursor) {}

  void send(const py::bytes &data, double timeout) {
    debugger_->send(static_cast<std::string>(data), timeout);
  }

  void sendline(const py::bytes &data, double timeout) {
    std::string bytes = data;
    bytes.push_back('\n');
    debugger_->send(bytes, timeout);
  }

  py::bytes recv(std::size_t size, double timeout) {
    if (size == 0) {
      return py::bytes{};
    }
    fill_pending(timeout_from_seconds(timeout), {});
    const std::size_t count = std::min(size, pending_.size());
    py::bytes result{pending_.data(), count};
    pending_.erase(0, count);
    return result;
  }

  py::bytes recvuntil(const py::bytes &delimiter, double timeout) {
    const std::string marker = delimiter;
    if (marker.empty()) {
      throw std::invalid_argument(
          l10n::text(l10n::Key::PythonBindingEmptyDelimiter));
    }
    fill_pending(timeout_from_seconds(timeout), marker);
    const std::size_t found = pending_.find(marker);
    const std::size_t count =
        found == std::string::npos ? pending_.size() : found + marker.size();
    py::bytes result{pending_.data(), count};
    pending_.erase(0, count);
    return result;
  }

private:
  void collect(const SessionSnapshot &snapshot) {
    for (const OutputChunk &chunk : snapshot.output_chunks) {
      if (chunk.sequence > cursor_) {
        pending_.append(chunk.data);
        cursor_ = chunk.sequence;
      }
    }
  }

  void fill_pending(std::chrono::milliseconds timeout,
                    std::string_view marker) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    SessionSnapshot current = debugger_->engine_.snapshot();
    for (;;) {
      if (current.generation != generation_) {
        throw std::runtime_error(
            l10n::text(l10n::Key::PythonBindingGenerationChangedReading));
      }
      collect(current);
      if ((marker.empty() ? !pending_.empty()
                          : pending_.find(marker) != std::string::npos) ||
          current.state == SessionState::Exited) {
        return;
      }
      const auto now = std::chrono::steady_clock::now();
      if (now >= deadline) {
        throw std::runtime_error(
            l10n::text(l10n::Key::PythonBindingOutputWaitTimedOut));
      }
      current = debugger_->wait_for_output(
          current.revision,
          std::min(50ms, std::chrono::duration_cast<std::chrono::milliseconds>(
                             deadline - now)),
          generation_);
    }
  }

  std::shared_ptr<PythonDebugger> debugger_;
  std::uint64_t generation_{};
  std::uint64_t cursor_{};
  std::string pending_;
};

std::shared_ptr<PythonProcess>
PythonDebugger::launch(const std::vector<std::string> &argv,
                       const std::string &stop_at,
                       const std::map<std::string, std::string> &environment,
                       const std::string &working_directory, double timeout,
                       const std::string &stdin_path) {
  if (argv.empty() || argv.front().empty()) {
    throw std::invalid_argument(
        l10n::text(l10n::Key::PythonBindingLaunchArgvRequired));
  }
  LaunchStopPolicy policy;
  if (stop_at == "main") {
    policy = LaunchStopPolicy::Main;
  } else if (stop_at == "entry") {
    policy = LaunchStopPolicy::Entry;
  } else if (stop_at == "none") {
    policy = LaunchStopPolicy::None;
  } else {
    throw std::invalid_argument(
        l10n::text(l10n::Key::PythonBindingInvalidStopPolicy));
  }

  LaunchOptions options{
      .executable = argv.front(),
      .arguments = {argv.begin() + 1, argv.end()},
      .working_directory = working_directory,
      .stop_policy = policy,
      .stdin_path = stdin_path,
  };
  options.environment.reserve(environment.size());
  for (const auto &[name, value] : environment) {
    if (name.empty() || name.find('=') != std::string::npos) {
      throw std::invalid_argument(
          l10n::text(l10n::Key::PythonBindingInvalidEnvironmentName));
    }
    options.environment.push_back(name + "=" + value);
  }
  return launch_process(std::move(options), timeout);
}

std::shared_ptr<PythonProcess>
PythonDebugger::launch_process(LaunchOptions options, double timeout) {
  const LaunchStopPolicy policy = options.stop_policy;
  last_launch_options_ = options;
  const CommandResult result =
      await(engine_.launch(std::move(options)), timeout_from_seconds(timeout));
  SessionSnapshot current = wait_until(
      [policy](const SessionSnapshot &snapshot) {
        return is_usable_stop(snapshot) ||
               snapshot.state == SessionState::Exited ||
               (policy == LaunchStopPolicy::None &&
                snapshot.state == SessionState::Running);
      },
      timeout_from_seconds(timeout), result.generation);
  return std::make_shared<PythonProcess>(shared_from_this(), current.generation,
                                         current.output_sequence);
}

std::shared_ptr<PythonProcess> PythonDebugger::attach(std::uint64_t process_id,
                                                      double timeout) {
  const CommandResult result =
      await(engine_.attach(process_id), timeout_from_seconds(timeout));
  const SessionSnapshot current = wait_until(
      is_usable_stop,
      timeout_from_seconds(timeout), result.generation);
  return std::make_shared<PythonProcess>(shared_from_this(), current.generation,
                                         current.output_sequence);
}

std::shared_ptr<PythonProcess>
PythonDebugger::connect_remote(const std::string &executable,
                               const std::string &endpoint,
                               const std::string &mode, double timeout,
                               const std::string &qemu,
                               const std::string &sysroot,
                               const std::vector<std::string> &arguments,
                               const std::string &working_directory,
                               const std::string &stdin_file) {
  if (endpoint.empty() && qemu.empty()) {
    throw std::invalid_argument(
        l10n::text(l10n::Key::PythonBindingEmptyRemoteEndpoint));
  }

  SessionMode session_mode;
  if (mode == "remote") {
    session_mode = SessionMode::Remote;
  } else if (mode == "qemu-user") {
    session_mode = SessionMode::QemuUser;
  } else if (mode == "qemu-system") {
    session_mode = SessionMode::QemuSystem;
  } else {
    throw std::invalid_argument(
        l10n::text(l10n::Key::PythonBindingInvalidRemoteMode));
  }

  const std::chrono::milliseconds timeout_duration =
      timeout_from_seconds(timeout);
  const CommandResult result =
      await(engine_.connect_remote(RemoteOptions{
                .executable = executable,
                .endpoint = endpoint,
                .mode = session_mode,
                .qemu_executable = qemu,
                .sysroot = sysroot,
                .arguments = arguments,
                .working_directory = working_directory,
                .stdin_file = stdin_file,
            }),
            timeout_duration);
  const SessionSnapshot current = wait_until(
      is_usable_stop,
      timeout_duration, result.generation);
  return std::make_shared<PythonProcess>(shared_from_this(), current.generation,
                                         current.output_sequence);
}

std::shared_ptr<PythonProcess> PythonDebugger::restart(double timeout) {
  const SessionSnapshot current = engine_.snapshot();
  if (current.mode != SessionMode::Local) {
    const l10n::Key message =
        current.mode == SessionMode::QemuUser
            ? l10n::Key::PythonBindingRestartQemuUserUnavailable
            : (current.mode == SessionMode::QemuSystem
                   ? l10n::Key::PythonBindingRestartQemuSystemUnavailable
                   : l10n::Key::PythonBindingRestartRemoteUnavailable);
    throw std::runtime_error(l10n::text(message));
  }
  LaunchOptions options;
  if (last_launch_options_) {
    options = *last_launch_options_;
  } else {
    if (current.target_path.empty()) {
      throw std::runtime_error(
          l10n::text(l10n::Key::PythonBindingRestartTargetRequired));
    }
    options.executable = current.target_path;
  }
  return launch_process(std::move(options), timeout);
}

} // namespace

PYBIND11_EMBEDDED_MODULE(_mydbg, module) {
  module.def(
      "_text", [](const std::string &key) { return l10n::text_key(key); },
      py::arg("key"));
  py::class_<InstructionRow>(module, "Instruction")
      .def_readonly("address", &InstructionRow::address)
      .def_readonly("file_address", &InstructionRow::file_address)
      .def_readonly("has_file_address", &InstructionRow::has_file_address)
      .def_property_readonly("bytes", [](const InstructionRow &instruction) {
        return python_bytes(instruction.bytes);
      })
      .def_readonly("mnemonic", &InstructionRow::mnemonic)
      .def_readonly("operands", &InstructionRow::operands)
      .def_readonly("comment", &InstructionRow::comment);
  py::class_<ModuleInfo>(module, "Module")
      .def_readonly("base", &ModuleInfo::base)
      .def_readonly("end", &ModuleInfo::end)
      .def_readonly("path", &ModuleInfo::path)
      .def_readonly("uuid", &ModuleInfo::uuid);
  py::class_<RegisterValue>(module, "RegisterValue")
      .def_readonly("name", &RegisterValue::name)
      .def_readonly("value", &RegisterValue::value);
  py::class_<StackFrameInfo>(module, "StackFrame")
      .def_readonly("thread_id", &StackFrameInfo::thread_id)
      .def_readonly("index", &StackFrameInfo::index)
      .def_readonly("selected", &StackFrameInfo::selected)
      .def_readonly("pc", &StackFrameInfo::pc)
      .def_readonly("sp", &StackFrameInfo::sp)
      .def_readonly("function", &StackFrameInfo::function)
      .def_readonly("module", &StackFrameInfo::module)
      .def_readonly("source_path", &StackFrameInfo::source_path)
      .def_readonly("source_line", &StackFrameInfo::source_line);
  py::class_<ThreadInfo>(module, "Thread")
      .def_readonly("id", &ThreadInfo::id)
      .def_readonly("index", &ThreadInfo::index)
      .def_readonly("selected", &ThreadInfo::selected)
      .def_readonly("name", &ThreadInfo::name)
      .def_readonly("stop_reason", &ThreadInfo::stop_reason)
      .def_readonly("frames", &ThreadInfo::frames);
  py::class_<BreakpointInfo>(module, "Breakpoint")
      .def_readonly("id", &BreakpointInfo::id)
      .def_readonly("enabled", &BreakpointInfo::enabled)
      .def_readonly("hit_count", &BreakpointInfo::hit_count)
      .def_readonly("description", &BreakpointInfo::description)
      .def_readonly("condition", &BreakpointInfo::condition)
      .def_readonly("addresses", &BreakpointInfo::addresses);
  py::class_<PatchInfo>(module, "Patch")
      .def_readonly("id", &PatchInfo::id)
      .def_readonly("address", &PatchInfo::address)
      .def_property_readonly("original", [](const PatchInfo &patch) {
        return python_bytes(patch.original);
      })
      .def_property_readonly("replacement", [](const PatchInfo &patch) {
        return python_bytes(patch.replacement);
      });
  py::class_<CommandResult>(module, "CommandResult")
      .def_readonly("id", &CommandResult::id)
      .def_readonly("success", &CommandResult::success)
      .def_readonly("message", &CommandResult::message)
      .def_readonly("snapshot_revision", &CommandResult::snapshot_revision)
      .def_readonly("generation", &CommandResult::generation)
      .def_readonly("stop_revision", &CommandResult::stop_revision);
  py::class_<PythonExpressionResult>(module, "ExpressionResult")
      .def_readonly("value", &PythonExpressionResult::value)
      .def_readonly("type", &PythonExpressionResult::type)
      .def_readonly("summary", &PythonExpressionResult::summary)
      .def_readonly("numeric_value", &PythonExpressionResult::numeric_value);
  py::class_<PythonSnapshot>(module, "Snapshot")
      .def_readonly("state", &PythonSnapshot::state)
      .def_readonly("mode", &PythonSnapshot::mode)
      .def_readonly("revision", &PythonSnapshot::revision)
      .def_readonly("generation", &PythonSnapshot::generation)
      .def_readonly("stop_revision", &PythonSnapshot::stop_revision)
      .def_readonly("target_path", &PythonSnapshot::target_path)
      .def_readonly("target_triple", &PythonSnapshot::target_triple)
      .def_readonly("architecture", &PythonSnapshot::architecture)
      .def_readonly("byte_order", &PythonSnapshot::byte_order)
      .def_readonly("address_byte_size", &PythonSnapshot::address_byte_size)
      .def_readonly("supports_intel_syntax",
                    &PythonSnapshot::supports_intel_syntax)
      .def_readonly("intel_syntax", &PythonSnapshot::intel_syntax)
      .def_readonly("process_id", &PythonSnapshot::process_id)
      .def_readonly("thread_id", &PythonSnapshot::thread_id)
      .def_readonly("pc", &PythonSnapshot::pc)
      .def_readonly("sp", &PythonSnapshot::sp)
      .def_readonly("stop_reason", &PythonSnapshot::stop_reason)
      .def_readonly("error", &PythonSnapshot::error)
      .def_readonly("exit_status", &PythonSnapshot::exit_status)
      .def_readonly("registers", &PythonSnapshot::registers)
      .def_readonly("instructions", &PythonSnapshot::instructions)
      .def_readonly("breakpoints", &PythonSnapshot::breakpoints)
      .def_readonly("threads", &PythonSnapshot::threads)
      .def_readonly("modules", &PythonSnapshot::modules)
      .def_readonly("patches", &PythonSnapshot::patches)
      .def_property_readonly("output", [](const PythonSnapshot &snapshot) {
        return py::bytes{snapshot.output};
      });
  py::class_<PythonProcess, std::shared_ptr<PythonProcess>>(module, "Process")
      .def("send", &PythonProcess::send, py::arg("data"),
           py::arg("timeout") = 10.0)
      .def("sendline", &PythonProcess::sendline, py::arg("data") = py::bytes{},
           py::arg("timeout") = 10.0)
      .def("recv", &PythonProcess::recv, py::arg("size") = 4096,
           py::arg("timeout") = 10.0)
      .def("recvuntil", &PythonProcess::recvuntil, py::arg("delimiter"),
           py::arg("timeout") = 10.0);
  py::class_<PythonDebugger, std::shared_ptr<PythonDebugger>>(module,
                                                              "Debugger")
      .def("load", &PythonDebugger::load, py::arg("executable"),
           py::arg("timeout") = 10.0)
      .def("launch", &PythonDebugger::launch, py::arg("argv"),
           py::arg("stop_at") = "main",
           py::arg("environment") = std::map<std::string, std::string>{},
           py::arg("cwd") = "", py::arg("timeout") = 10.0,
           py::arg("stdin_path") = "")
      .def("attach", &PythonDebugger::attach, py::arg("process_id"),
           py::arg("timeout") = 10.0)
      .def("connect_remote", &PythonDebugger::connect_remote,
           py::arg("executable"), py::arg("endpoint"),
           py::arg("mode") = "qemu-user", py::arg("timeout") = 10.0,
           py::arg("qemu") = "", py::arg("sysroot") = "",
           py::arg("arguments") = std::vector<std::string>{},
           py::arg("cwd") = "", py::arg("stdin_file") = "")
      .def("restart", &PythonDebugger::restart, py::arg("timeout") = 10.0)
      .def("detach", &PythonDebugger::detach, py::arg("timeout") = 10.0)
      .def("terminate", &PythonDebugger::terminate, py::arg("timeout") = 10.0)
      .def("continue_execution", &PythonDebugger::continue_execution,
           py::arg("timeout") = 10.0)
      .def("continue_and_wait", &PythonDebugger::continue_and_wait,
           py::arg("timeout") = 10.0)
      .def("interrupt", &PythonDebugger::interrupt, py::arg("timeout") = 10.0)
      .def("interrupt_and_wait", &PythonDebugger::interrupt_and_wait,
           py::arg("timeout") = 10.0)
      .def("step_instruction", &PythonDebugger::step_instruction,
           py::arg("step_over") = false, py::arg("timeout") = 10.0)
      .def("run_to", &PythonDebugger::run_to, py::arg("address"),
           py::arg("timeout") = 10.0)
      .def("wait_for_stop", &PythonDebugger::wait_for_stop,
           py::arg("timeout") = 10.0)
      .def("wait_for_exit", &PythonDebugger::wait_for_exit,
           py::arg("timeout") = 10.0)
      .def("snapshot", &PythonDebugger::snapshot)
      .def("evaluate", &PythonDebugger::evaluate, py::arg("expression"),
           py::arg("timeout") = 10.0)
      .def("read_register", &PythonDebugger::read_register, py::arg("name"),
           py::arg("timeout") = 10.0)
      .def("write_register", &PythonDebugger::write_register, py::arg("name"),
           py::arg("value"), py::arg("timeout") = 10.0)
      .def("read_memory", &PythonDebugger::read_memory, py::arg("address"),
           py::arg("size"), py::arg("timeout") = 10.0)
      .def("write_memory", &PythonDebugger::write_memory, py::arg("address"),
           py::arg("data"), py::arg("timeout") = 10.0)
      .def("select_thread", &PythonDebugger::select_thread,
           py::arg("thread_id"), py::arg("timeout") = 10.0)
      .def("select_frame", &PythonDebugger::select_frame, py::arg("thread_id"),
           py::arg("frame_index"), py::arg("timeout") = 10.0)
      .def("set_breakpoint", &PythonDebugger::set_breakpoint,
           py::arg("specification"), py::arg("timeout") = 10.0)
      .def("remove_breakpoint", &PythonDebugger::remove_breakpoint,
           py::arg("id"), py::arg("timeout") = 10.0)
      .def("enable_breakpoint", &PythonDebugger::enable_breakpoint,
           py::arg("id"), py::arg("enabled") = true, py::arg("timeout") = 10.0)
      .def("list_breakpoints", &PythonDebugger::list_breakpoints)
      .def("execute", &PythonDebugger::execute, py::arg("command"),
           py::arg("timeout") = 10.0);
}

py::object
make_python_debugger(LldbEngine &engine,
                     std::shared_ptr<std::atomic_bool> cancellation) {
  py::module_::import("_mydbg");
  return py::cast(
      std::make_shared<PythonDebugger>(engine, std::move(cancellation)));
}

} // namespace debugger::scripting
