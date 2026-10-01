#include "scripting/PythonDebugger.h"
#include "backend/lldb/LldbEngine.h"
#include "localization/Localization.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cmath>
#include <stdexcept>
#include <utility>

namespace py = pybind11;
using namespace std::chrono_literals;

namespace debugger::scripting::detail {
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

std::optional<std::uint64_t> parse_lldb_integer(std::string_view text) {
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
  const auto [end, error] =
      std::from_chars(text.data(), text.data() + text.size(), magnitude, base);
  if (error != std::errc{} || end != text.data() + text.size()) {
    return std::nullopt;
  }
  if (!negative) {
    return magnitude;
  }
  constexpr std::uint64_t maximum_negative_magnitude = std::uint64_t{1} << 63U;
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

} // namespace

template <typename Predicate>
SessionSnapshot PythonDebugger::wait_until(const Predicate &predicate,
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
    const auto slice = std::min(
        50ms,
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now));
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

PythonDebugger::PythonDebugger(LldbEngine &engine,
                               std::shared_ptr<std::atomic_bool> cancellation)
    : engine_(engine), cancellation_(std::move(cancellation)) {}

PythonSnapshot PythonDebugger::load(const std::string &executable,
                                    double timeout) {
  await(engine_.load(executable), timeout_from_seconds(timeout));
  return PythonSnapshot{engine_.snapshot()};
}

void PythonDebugger::detach(double timeout) {
  await(engine_.detach(), timeout_from_seconds(timeout));
}

void PythonDebugger::terminate(double timeout) {
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

void PythonDebugger::continue_execution(double timeout) {
  await(engine_.continue_execution(), timeout_from_seconds(timeout));
}

PythonSnapshot PythonDebugger::continue_and_wait(double timeout) {
  const SessionSnapshot current = engine_.snapshot();
  await(engine_.continue_execution(), timeout_from_seconds(timeout));
  return wait_for_next_stop(current, timeout);
}

void PythonDebugger::interrupt(double timeout) {
  await(engine_.stop(), timeout_from_seconds(timeout));
}

PythonSnapshot PythonDebugger::interrupt_and_wait(double timeout) {
  const SessionSnapshot current = engine_.snapshot();
  await(engine_.stop(), timeout_from_seconds(timeout));
  return wait_for_next_stop(current, timeout, false);
}

PythonSnapshot PythonDebugger::step_instruction(bool step_over,
                                                double timeout) {
  const SessionSnapshot current = engine_.snapshot();
  await(engine_.step_instruction(step_over), timeout_from_seconds(timeout));
  return wait_for_next_stop(current, timeout);
}

PythonSnapshot PythonDebugger::run_to(std::uint64_t address, double timeout) {
  const SessionSnapshot current = engine_.snapshot();
  await(engine_.run_to_address(address), timeout_from_seconds(timeout));
  return wait_for_next_stop(current, timeout);
}

// Captures up to 48 instructions at an arbitrary address into the session's
// instruction view; returns the snapshot carrying them. This is the
// script-side code-recon primitive (the console `u`/`disasm` alias is
// textual and capped at 32).
PythonSnapshot PythonDebugger::disassemble(std::uint64_t address,
                                           double timeout) {
  const SessionSnapshot current = engine_.snapshot();
  if (current.state != SessionState::Stopped) {
    throw std::runtime_error("disassembly requires a stopped session");
  }
  await(engine_.read_instructions(address), timeout_from_seconds(timeout));
  return PythonSnapshot{engine_.snapshot()};
}

PythonSnapshot PythonDebugger::wait_for_stop(double timeout) {
  const SessionSnapshot current = engine_.snapshot();
  return PythonSnapshot{wait_until(
      is_usable_stop, timeout_from_seconds(timeout), current.generation)};
}

PythonSnapshot PythonDebugger::wait_for_exit(double timeout) {
  const SessionSnapshot current = engine_.snapshot();
  return PythonSnapshot{wait_until(
      [](const SessionSnapshot &snapshot) {
        return snapshot.state == SessionState::Exited;
      },
      timeout_from_seconds(timeout), current.generation)};
}

PythonSnapshot PythonDebugger::snapshot() const {
  return PythonSnapshot{engine_.snapshot()};
}

PythonExpressionResult PythonDebugger::evaluate(const std::string &expression,
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

std::uint64_t PythonDebugger::read_register(const std::string &name,
                                            double timeout) {
  const CommandResult result =
      await(engine_.read_register(name), timeout_from_seconds(timeout));
  if (const auto value = numeric_result(result, name)) {
    return *value;
  }
  throw std::runtime_error(
      l10n::text(l10n::Key::PythonBindingRegisterNotInteger));
}

void PythonDebugger::write_register(const std::string &name,
                                    std::uint64_t value, double timeout) {
  await(engine_.write_register(name, value), timeout_from_seconds(timeout));
}

py::bytes PythonDebugger::read_memory(std::uint64_t address, std::size_t size,
                                      double timeout) {
  const CommandResult result =
      await(engine_.read_memory(address, size), timeout_from_seconds(timeout));
  return python_bytes(result.bytes);
}

void PythonDebugger::write_memory(std::uint64_t address, const py::bytes &value,
                                  double timeout) {
  const std::string bytes = value;
  await(engine_.write_memory(
            address, std::vector<std::uint8_t>{bytes.begin(), bytes.end()}),
        timeout_from_seconds(timeout));
}

void PythonDebugger::select_thread(std::uint64_t thread_id, double timeout) {
  await(engine_.select_thread(thread_id), timeout_from_seconds(timeout));
}

void PythonDebugger::select_frame(std::uint64_t thread_id,
                                  std::uint32_t frame_index, double timeout) {
  await(engine_.select_frame(thread_id, frame_index),
        timeout_from_seconds(timeout));
}

std::uint32_t PythonDebugger::set_breakpoint(const std::string &specification,
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

void PythonDebugger::remove_breakpoint(std::uint32_t id, double timeout) {
  await(engine_.remove_breakpoint(id), timeout_from_seconds(timeout));
}

void PythonDebugger::enable_breakpoint(std::uint32_t id, bool enabled,
                                       double timeout) {
  await(engine_.set_breakpoint_enabled(id, enabled),
        timeout_from_seconds(timeout));
}

std::vector<BreakpointInfo> PythonDebugger::list_breakpoints() const {
  return engine_.snapshot().breakpoints;
}

CommandResult PythonDebugger::execute(const std::string &command,
                                      double timeout) {
  return await(engine_.execute_command(command), timeout_from_seconds(timeout));
}

void PythonDebugger::send(const std::string &bytes, double timeout) {
  await(engine_.send_stdin(bytes), timeout_from_seconds(timeout));
}

SessionSnapshot
PythonDebugger::wait_for_output(std::uint64_t revision,
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

std::optional<std::uint64_t> PythonDebugger::numeric_result(
    const CommandResult &result,
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

PythonSnapshot
PythonDebugger::wait_for_next_stop(const SessionSnapshot &previous,
                                   double timeout, bool accept_exit) const {
  return PythonSnapshot{wait_until(
      [stop_revision = previous.stop_revision,
       accept_exit](const SessionSnapshot &snapshot) {
        return (is_usable_stop(snapshot) &&
                snapshot.stop_revision > stop_revision) ||
               (accept_exit && snapshot.state == SessionState::Exited);
      },
      timeout_from_seconds(timeout), previous.generation)};
}

void PythonDebugger::check_cancelled() const {
  if (cancellation_->load()) {
    throw std::runtime_error(
        l10n::text(l10n::Key::PythonRuntimeScriptCancelled));
  }
}

CommandResult PythonDebugger::await(CommandTicket ticket,
                                    std::chrono::milliseconds timeout) const {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    check_cancelled();
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
      throw std::runtime_error(
          l10n::text(l10n::Key::PythonBindingCommandTimedOut));
    }
    const auto slice = std::min(
        50ms,
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now));
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

PythonProcess::PythonProcess(std::shared_ptr<PythonDebugger> debugger,
                             std::uint64_t generation, std::uint64_t cursor)
    : debugger_(std::move(debugger)), generation_(generation), cursor_(cursor) {
}

void PythonProcess::send(const py::bytes &data, double timeout) {
  debugger_->send(static_cast<std::string>(data), timeout);
}

void PythonProcess::sendline(const py::bytes &data, double timeout) {
  std::string bytes = data;
  bytes.push_back('\n');
  debugger_->send(bytes, timeout);
}

py::bytes PythonProcess::recv(std::size_t size, double timeout) {
  if (size == 0) {
    return py::bytes{};
  }
  fill_pending(timeout_from_seconds(timeout), {});
  const std::size_t count = std::min(size, pending_.size());
  py::bytes result{pending_.data(), count};
  pending_.erase(0, count);
  return result;
}

py::bytes PythonProcess::recvuntil(const py::bytes &delimiter, double timeout) {
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

void PythonProcess::collect(const SessionSnapshot &snapshot) {
  for (const OutputChunk &chunk : snapshot.output_chunks) {
    if (chunk.sequence > cursor_) {
      pending_.append(chunk.data);
      cursor_ = chunk.sequence;
    }
  }
}

void PythonProcess::fill_pending(std::chrono::milliseconds timeout,
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
      is_usable_stop, timeout_from_seconds(timeout), result.generation);
  return std::make_shared<PythonProcess>(shared_from_this(), current.generation,
                                         current.output_sequence);
}

std::shared_ptr<PythonProcess> PythonDebugger::connect_remote(
    const std::string &executable, const std::string &endpoint,
    const std::string &mode, double timeout, const std::string &qemu,
    const std::string &sysroot, const std::vector<std::string> &arguments,
    const std::string &working_directory, const std::string &stdin_file) {
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
  const CommandResult result = await(engine_.connect_remote(RemoteOptions{
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
  const SessionSnapshot current =
      wait_until(is_usable_stop, timeout_duration, result.generation);
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

} // namespace debugger::scripting::detail
