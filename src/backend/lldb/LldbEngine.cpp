#include "backend/lldb/LldbEngine.h"
#include "backend/conditions/BreakpointCondition.h"
#include "backend/lldb/LldbEngineInternal.h"
#include "backend/lldb/LldbInstructionCapture.h"
#include "backend/lldb/LldbNativeCommands.h"
#include "backend/lldb/LldbRemoteArchitecture.h"
#include "backend/lldb/LldbSessions.h"
#include "backend/lldb/QemuProcess.h"
#include "localization/Localization.h"
#include "plugins/PluginApi.h"

namespace debugger {

using namespace lldb_detail;
using namespace std::chrono_literals;

namespace {

struct LldbRuntime {
  LldbRuntime()
      : initialization_error{lldb::SBDebugger::InitializeWithErrorHandling()} {}

  ~LldbRuntime() { lldb::SBDebugger::Terminate(); }

  lldb::SBError initialization_error;
};

const lldb::SBError &initialize_lldb_runtime() {
  static LldbRuntime runtime;
  return runtime.initialization_error;
}

const char *session_state_display(SessionState state) {
  switch (state) {
  case SessionState::Initializing:
    return l10n::text(l10n::Key::EngineStateInitializing);
  case SessionState::NoTarget:
    return l10n::text(l10n::Key::EngineStateNoTarget);
  case SessionState::TargetLoaded:
    return l10n::text(l10n::Key::EngineStateTargetLoaded);
  case SessionState::Launching:
    return l10n::text(l10n::Key::EngineStateLaunching);
  case SessionState::Connecting:
    return l10n::text(l10n::Key::EngineStateConnecting);
  case SessionState::Running:
    return l10n::text(l10n::Key::EngineStateRunning);
  case SessionState::Stopped:
    return l10n::text(l10n::Key::EngineStateStopped);
  case SessionState::Exited:
    return l10n::text(l10n::Key::EngineStateExited);
  case SessionState::Error:
    return l10n::text(l10n::Key::EngineStateError);
  case SessionState::ShuttingDown:
    return l10n::text(l10n::Key::EngineStateShuttingDown);
  }
  return l10n::text(l10n::Key::EngineStateUnknown);
}

} // namespace

const char *to_string(SessionState state) noexcept {
  switch (state) {
  case SessionState::Initializing:
    return "initializing";
  case SessionState::NoTarget:
    return "no target";
  case SessionState::TargetLoaded:
    return "target loaded";
  case SessionState::Launching:
    return "launching";
  case SessionState::Connecting:
    return "connecting";
  case SessionState::Running:
    return "running";
  case SessionState::Stopped:
    return "stopped";
  case SessionState::Exited:
    return "exited";
  case SessionState::Error:
    return "error";
  case SessionState::ShuttingDown:
    return "shutting down";
  }
  return "unknown";
}

const char *to_string(SessionMode mode) noexcept {
  switch (mode) {
  case SessionMode::Local:
    return "local";
  case SessionMode::Remote:
    return "remote gdb";
  case SessionMode::QemuUser:
    return "QEMU user";
  case SessionMode::QemuSystem:
    return "QEMU system";
  }
  return "unknown";
}

std::string target_architecture(lldb::SBTarget &target) {
  const std::string triple = safe_string(target.GetTriple());
  const std::size_t separator = triple.find('-');
  return separator == std::string::npos ? triple : triple.substr(0, separator);
}

bool CommandTicket::wait_for(std::chrono::milliseconds timeout) const {
  return result_.valid() &&
         result_.wait_for(timeout) == std::future_status::ready;
}

CommandResult CommandTicket::get() const {
  if (!result_.valid()) {
    return CommandResult{.message =
                             l10n::text(l10n::Key::EngineInvalidCommandTicket)};
  }
  return result_.get();
}

struct LldbEngine::WorkerControl {
  std::mutex mutex;
  lldb::SBDebugger debugger;
  bool remote_connection_active{};
};

LldbEngine::LldbEngine(std::shared_ptr<SessionStore> sessions)
    : sessions_(std::move(sessions)),
      worker_control_(std::make_unique<WorkerControl>()),
      worker_([this] { run(); }) {}

LldbEngine::~LldbEngine() {
  request_shutdown();
  if (worker_.joinable()) {
    worker_.join();
  }
}

CommandTicket LldbEngine::load(std::string executable) {
  return enqueue(
      Command{.kind = CommandKind::Load, .argument = std::move(executable)});
}

CommandTicket LldbEngine::launch(std::string executable) {
  return enqueue(Command{.kind = CommandKind::Launch,
                         .launch_options =
                             LaunchOptions{.executable = std::move(executable)},
                         .enabled = true});
}

CommandTicket LldbEngine::launch(LaunchOptions options) {
  return enqueue(Command{.kind = CommandKind::Launch,
                         .launch_options = std::move(options)});
}

CommandTicket LldbEngine::attach(std::uint64_t process_id) {
  return enqueue(Command{.kind = CommandKind::Attach, .value = process_id});
}

CommandTicket LldbEngine::connect_remote(RemoteOptions options) {
  return enqueue(Command{.kind = CommandKind::ConnectRemote,
                         .remote_options = std::move(options)});
}

CommandTicket LldbEngine::detach() {
  return enqueue(Command{.kind = CommandKind::Detach});
}

CommandTicket LldbEngine::continue_execution() {
  return enqueue(Command{.kind = CommandKind::Continue});
}

CommandTicket LldbEngine::stop() {
  return enqueue(Command{.kind = CommandKind::Stop});
}

CommandTicket LldbEngine::step_instruction(bool step_over) {
  return enqueue(
      Command{.kind = CommandKind::StepInstruction, .enabled = step_over});
}

CommandTicket LldbEngine::run_to_address(std::uint64_t address) {
  return enqueue(Command{.kind = CommandKind::RunToAddress, .value = address});
}

CommandTicket LldbEngine::terminate() {
  return enqueue(Command{.kind = CommandKind::Terminate});
}

CommandTicket LldbEngine::set_breakpoint(std::string specification) {
  return enqueue(Command{.kind = CommandKind::SetBreakpoint,
                         .argument = std::move(specification)});
}

CommandTicket LldbEngine::set_conditional_breakpoint(std::string specification,
                                                     std::string condition) {
  return enqueue(Command{.kind = CommandKind::SetConditionalBreakpoint,
                         .argument = std::move(specification),
                         .argument2 = std::move(condition)});
}

CommandTicket LldbEngine::remove_breakpoint(std::uint32_t id) {
  return enqueue(Command{.kind = CommandKind::RemoveBreakpoint, .value = id});
}

CommandTicket LldbEngine::set_breakpoint_enabled(std::uint32_t id,
                                                 bool enabled) {
  return enqueue(Command{
      .kind = CommandKind::EnableBreakpoint, .value = id, .enabled = enabled});
}

CommandTicket LldbEngine::set_breakpoint_script(std::uint32_t id,
                                                std::string condition) {
  return enqueue(Command{.kind = CommandKind::SetBreakpointScript,
                         .argument = std::move(condition),
                         .value = id});
}

CommandTicket LldbEngine::clear_saved_session(std::string expected_sha256) {
  return enqueue(Command{.kind = CommandKind::ClearSavedSession,
                         .argument = std::move(expected_sha256)});
}

CommandTicket LldbEngine::set_comment(std::uint64_t load_address,
                                      std::string text,
                                      std::uint64_t expected_generation) {
  return enqueue(Command{.kind = CommandKind::SetComment,
                         .argument = std::move(text),
                         .value = load_address,
                         .value2 = expected_generation,
                         .expected_session = snapshot().session});
}

CommandTicket LldbEngine::read_memory(std::uint64_t address) {
  return enqueue(Command{.kind = CommandKind::ReadMemory, .value = address});
}
CommandTicket LldbEngine::read_memory(std::uint64_t address, std::size_t size) {
  return enqueue(Command{
      .kind = CommandKind::ReadMemoryBytes, .value = address, .value2 = size});
}

CommandTicket LldbEngine::write_memory(std::uint64_t address,
                                       std::vector<std::uint8_t> bytes) {
  return enqueue(Command{.kind = CommandKind::WriteMemoryBytes,
                         .value = address,
                         .bytes = std::move(bytes)});
}

CommandTicket LldbEngine::evaluate(std::string expression) {
  return enqueue(Command{.kind = CommandKind::EvaluateExpression,
                         .argument = std::move(expression)});
}

CommandTicket LldbEngine::read_register(std::string name) {
  return enqueue(
      Command{.kind = CommandKind::ReadRegister, .argument = std::move(name)});
}

CommandTicket LldbEngine::write_register(std::string name,
                                         std::uint64_t value) {
  std::ostringstream formatted;
  formatted << "0x" << std::hex << value;
  return write_register(std::move(name), formatted.str());
}

CommandTicket LldbEngine::write_register(std::string name, std::string value) {
  return enqueue(Command{.kind = CommandKind::WriteRegister,
                         .argument = std::move(name),
                         .argument2 = std::move(value)});
}

CommandTicket LldbEngine::send_stdin(std::string bytes) {
  return enqueue(
      Command{.kind = CommandKind::SendStdin, .argument = std::move(bytes)});
}

CommandTicket LldbEngine::select_thread(std::uint64_t thread_id) {
  return enqueue(
      Command{.kind = CommandKind::SelectThread, .value = thread_id});
}

CommandTicket LldbEngine::select_frame(std::uint64_t thread_id,
                                       std::uint32_t frame_index) {
  return enqueue(Command{.kind = CommandKind::SelectFrame,
                         .value = thread_id,
                         .value2 = frame_index});
}

CommandTicket LldbEngine::read_instructions(std::uint64_t address) {
  return enqueue(
      Command{.kind = CommandKind::ReadInstructions, .value = address});
}

CommandTicket LldbEngine::execute_command(std::string command) {
  return enqueue(Command{.kind = CommandKind::ExecuteConsole,
                         .argument = std::move(command)});
}

CommandTicket LldbEngine::set_intel_syntax(bool enabled) {
  return enqueue(
      Command{.kind = CommandKind::SetDisassemblyStyle, .enabled = enabled});
}

CommandTicket LldbEngine::set_disassembly_graph_enabled(bool enabled) {
  return enqueue(Command{.kind = CommandKind::SetDisassemblyGraphEnabled,
                         .enabled = enabled});
}

CommandTicket LldbEngine::scan_binary_strings(std::uint32_t minimum_length,
                                              bool include_utf16) {
  return enqueue(Command{.kind = CommandKind::ScanBinaryStrings,
                         .value = minimum_length,
                         .enabled = include_utf16});
}

CommandTicket LldbEngine::start_value_scan(ValueScanType type,
                                           std::string value, bool unknown,
                                           bool signed_values,
                                           bool writable_only) {
  return enqueue(
      Command{.kind = CommandKind::StartValueScan,
              .argument = std::move(value),
              .value = static_cast<std::uint64_t>(type),
              .value2 = (unknown ? 1U : 0U) | (signed_values ? 2U : 0U),
              .enabled = writable_only});
}

CommandTicket LldbEngine::next_value_scan(ValueScanComparison comparison,
                                          std::string value) {
  return enqueue(Command{.kind = CommandKind::NextValueScan,
                         .argument = std::move(value),
                         .value = static_cast<std::uint64_t>(comparison)});
}

CommandTicket LldbEngine::reset_value_scan() {
  return enqueue(Command{.kind = CommandKind::ResetValueScan});
}

SessionSnapshot LldbEngine::snapshot() const {
  const std::lock_guard lock{mutex_};
  return snapshot_;
}

std::optional<SessionSnapshot>
LldbEngine::wait_for_update(std::uint64_t after_revision,
                            std::chrono::milliseconds timeout) const {
  std::unique_lock lock{mutex_};
  if (!updated_.wait_for(lock, timeout, [this, after_revision] {
        return snapshot_.revision > after_revision ||
               shutdown_requested_.load();
      })) {
    return std::nullopt;
  }
  if (snapshot_.revision <= after_revision) {
    return std::nullopt;
  }
  return snapshot_;
}

CommandTicket LldbEngine::enqueue(Command command) {
  auto completion = std::make_shared<std::promise<CommandResult>>();
  std::shared_future<CommandResult> future = completion->get_future().share();
  CommandId id = 0;
  bool accepted = false;
  {
    const std::lock_guard lock{mutex_};
    id = next_command_id_++;
    command.id = id;
    command.completion = completion;
    accepted = !shutdown_requested_.load();
    if (accepted) {
      commands_.push_back(std::move(command));
    }
  }
  if (!accepted) {
    const SessionSnapshot current = snapshot();
    completion->set_value(CommandResult{
        .id = id,
        .success = false,
        .message = l10n::text(l10n::Key::EngineEngineIsShuttingDown),
        .snapshot_revision = current.revision,
        .generation = current.generation,
        .stop_revision = current.stop_revision,
    });
  } else {
    wake_.notify_one();
  }
  return CommandTicket{id, std::move(future)};
}

void LldbEngine::request_shutdown() {
  std::deque<Command> abandoned;
  SessionSnapshot current;
  {
    const std::lock_guard lock{mutex_};
    if (shutdown_requested_.exchange(true)) {
      return;
    }
    abandoned.swap(commands_);
    commands_.push_front(Command{.kind = CommandKind::Shutdown});
    current = snapshot_;
  }
  {
    const std::lock_guard lock{worker_control_->mutex};
    if (worker_control_->remote_connection_active &&
        worker_control_->debugger.IsValid()) {
      worker_control_->debugger.RequestInterrupt();
    }
  }
  for (Command &command : abandoned) {
    command.completion->set_value(CommandResult{
        .id = command.id,
        .success = false,
        .message = l10n::text(l10n::Key::EngineEngineIsShuttingDown),
        .snapshot_revision = current.revision,
        .generation = current.generation,
        .stop_revision = current.stop_revision,
    });
  }
  wake_.notify_one();
  updated_.notify_all();
}

void LldbEngine::run() {
  SessionSnapshot state;
  QemuProcess qemu{state, qemu_pid_, qemu_stdin_fd_, qemu_stdout_fd_};
  lldb::SBTarget target;
  LldbSessions session{sessions_};
  std::optional<lldb::addr_t> instruction_view_address;
  bool disassembly_graph_enabled = false;
  SessionState published_state = SessionState::Initializing;
  std::uint64_t published_generation = 0;
  std::uint64_t published_stop_revision = 0;
  std::uint64_t published_process_id = 0;
  std::string published_target_path;
  auto publish = [this, &state, &published_state, &published_generation,
                  &published_stop_revision, &published_process_id,
                  &published_target_path, &target, &instruction_view_address,
                  &disassembly_graph_enabled, &session] {
    if (!disassembly_graph_enabled || state.state != SessionState::Stopped) {
      state.disassembly_graph.reset();
    } else if (!state.disassembly_graph && !state.instructions.empty()) {
      capture_disassembly_graph(
          target, instruction_view_address.value_or(state.pc), state);
    }
    session.annotate(target, state);
    {
      const std::lock_guard lock{mutex_};
      ++state.revision;
      snapshot_ = state;
    }
    updated_.notify_all();
    auto &registry = plugins::PluginRegistry::instance();
    if (state.target_path != published_target_path &&
        !state.target_path.empty()) {
      registry.dispatch(plugins::Event::TargetLoaded, state);
    }
    if (state.process_id != 0 && (state.process_id != published_process_id ||
                                  state.generation != published_generation)) {
      registry.dispatch(plugins::Event::ProcessStarted, state);
    }
    if (state.state == SessionState::Stopped &&
        (published_state != SessionState::Stopped ||
         state.stop_revision != published_stop_revision)) {
      registry.dispatch(plugins::Event::ProcessStopped, state);
    } else if (state.state == SessionState::Running &&
               published_state != SessionState::Running) {
      registry.dispatch(plugins::Event::ProcessContinued, state);
    } else if (state.state == SessionState::Exited &&
               published_state != SessionState::Exited) {
      registry.dispatch(plugins::Event::ProcessExited, state);
    }
    registry.dispatch(plugins::Event::SnapshotUpdated, state);
    published_state = state.state;
    published_generation = state.generation;
    published_stop_revision = state.stop_revision;
    published_process_id = state.process_id;
    published_target_path = state.target_path;
  };

  const lldb::SBError &initialize_error = initialize_lldb_runtime();
  if (initialize_error.Fail()) {
    state.state = SessionState::Error;
    state.error = error_text(initialize_error);
    publish();
    std::deque<Command> failed;
    {
      const std::lock_guard lock{mutex_};
      shutdown_requested_.store(true);
      failed.swap(commands_);
    }
    for (Command &command : failed) {
      command.completion->set_value(CommandResult{
          .id = command.id,
          .success = false,
          .message = state.error,
          .snapshot_revision = state.revision,
          .generation = state.generation,
          .stop_revision = state.stop_revision,
      });
    }
    return;
  }

  lldb::SBDebugger debugger = lldb::SBDebugger::Create(false);
  {
    const std::lock_guard lock{worker_control_->mutex};
    worker_control_->debugger = debugger;
  }
  debugger.SkipLLDBInitFiles(true);
  debugger.SkipAppInitFiles(true);
  debugger.SetAsync(true);
  lldb::SBListener listener = debugger.GetListener();
  lldb::SBProcess process;
  std::uint32_t active_process_id = 0;
  std::uint64_t active_process_generation = 0;
  std::optional<lldb::addr_t> memory_view_address;
  struct WatchSpec {
    bool execute{};
    std::string expression;
  };
  std::vector<std::string> launch_arguments;
  std::string launch_working_directory;
  std::vector<SessionSymbol> persistent_symbols;
  lldb::SBTarget session_target;
  std::string session_target_path;
  std::vector<std::string> context_sections{
      "regs", "disasm", "insight", "stack", "backtrace", "threads", "crash"};
  std::vector<WatchSpec> watch_specs;
  std::vector<std::pair<std::string, std::uint64_t>> custom_symbols;
  PatchCommands patch_commands;
  struct ScriptConditionState {
    std::string source;
    conditions::CompiledCondition compiled;
    std::string last_error;
  };
  std::unordered_map<std::uint32_t, ScriptConditionState> script_conditions;
  std::unordered_map<std::uint32_t, std::uint32_t> frameless_breakpoint_hits;
  std::uint64_t counted_frameless_stop_revision = 0;
  auto refresh_breakpoint_state = [&] {
    refresh_breakpoints(target, state);
    const bool new_frameless_stop =
        is_frameless_qemu_mips_stop(process, state) &&
        state.stop_revision != counted_frameless_stop_revision;
    if (new_frameless_stop) {
      counted_frameless_stop_revision = state.stop_revision;
      for (const BreakpointInfo &breakpoint : state.breakpoints) {
        if (breakpoint.enabled &&
            std::ranges::find(breakpoint.addresses, state.pc) !=
                breakpoint.addresses.end()) {
          ++frameless_breakpoint_hits[breakpoint.id];
        }
      }
    }
    for (BreakpointInfo &breakpoint : state.breakpoints) {
      if (const auto hit = frameless_breakpoint_hits.find(breakpoint.id);
          hit != frameless_breakpoint_hits.end()) {
        breakpoint.hit_count = std::max(breakpoint.hit_count, hit->second);
      }
      const auto script = script_conditions.find(breakpoint.id);
      if (script != script_conditions.end()) {
        breakpoint.script_condition = script->second.source;
        breakpoint.script_error = script->second.last_error;
      }
    }
    std::erase_if(script_conditions, [&state](const auto &entry) {
      return std::none_of(state.breakpoints.begin(), state.breakpoints.end(),
                          [&entry](const BreakpointInfo &breakpoint) {
                            return breakpoint.id == entry.first;
                          });
    });
    std::erase_if(frameless_breakpoint_hits, [&state](const auto &entry) {
      return std::none_of(state.breakpoints.begin(), state.breakpoints.end(),
                          [&entry](const BreakpointInfo &breakpoint) {
                            return breakpoint.id == entry.first;
                          });
    });
  };

  auto apply_launch_intent = [&] {
    if (!target.IsValid())
      return;
    auto info = target.GetLaunchInfo();
    std::vector<const char *> arguments;
    arguments.reserve(launch_arguments.size() + 1);
    for (const auto &argument : launch_arguments)
      arguments.push_back(argument.c_str());
    arguments.push_back(nullptr);
    info.SetArguments(arguments.data(), false);
    info.SetWorkingDirectory(launch_working_directory.c_str());
    target.SetLaunchInfo(info);
  };
  auto read_launch_intent = [&] {
    if (!target.IsValid())
      return;
    auto info = target.GetLaunchInfo();
    launch_arguments.clear();
    for (std::uint32_t i = 0; i < info.GetNumArguments(); ++i)
      launch_arguments.emplace_back(safe_string(info.GetArgumentAtIndex(i)));
    launch_working_directory = safe_string(info.GetWorkingDirectory());
  };
  auto save_session = [&] {
    if (!sessions_ || !target.IsValid())
      return;
    SessionDebuggerState authored;
    authored.arguments = launch_arguments;
    authored.working_directory = launch_working_directory;
    authored.symbols = persistent_symbols;
    for (const auto &watch : watch_specs) {
      if (!watch.execute)
        authored.watches.push_back(watch.expression);
      else
        session.notice(state, l10n::text(l10n::Key::LldbSessionUnsafeSkipped));
    }
    session.save(
        target, std::move(authored),
        [&](std::uint32_t id) {
          const auto found = script_conditions.find(id);
          return found == script_conditions.end() ? std::string{}
                                                  : found->second.source;
        },
        state);
  };
  auto restore_pending_session = [&] {
    for (auto &[id, source] : session.restore(target, state)) {
      if (source.empty())
        continue;
      auto compiled = conditions::compile(source);
      if (compiled)
        script_conditions.insert_or_assign(
            id, ScriptConditionState{.source = std::move(source),
                                     .compiled = std::move(compiled.condition),
                                     .last_error = {}});
    }
    if (sessions_) {
      for (const auto &symbol : persistent_symbols) {
        auto address = session.resolve(target, symbol.address);
        const auto load = address.GetLoadAddress(target);
        auto existing =
            std::find_if(custom_symbols.begin(), custom_symbols.end(),
                         [&](const auto &candidate) {
                           return candidate.first == symbol.name;
                         });
        if (address.IsValid() && load != LLDB_INVALID_ADDRESS) {
          if (existing == custom_symbols.end())
            custom_symbols.emplace_back(symbol.name, load);
          else
            existing->second = load;
        } else if (existing != custom_symbols.end()) {
          custom_symbols.erase(existing);
        }
      }
    }
    refresh_breakpoint_state();
  };
  auto reset_target_session = [&] {
    save_session();
    script_conditions.clear();
    session.reset(state);
    session_target = {};
    session_target_path.clear();
    if (sessions_) {
      watch_specs.clear();
      state.watches.clear();
      custom_symbols.clear();
      persistent_symbols.clear();
      launch_arguments.clear();
      launch_working_directory.clear();
    }
  };
  auto open_target_session = [&] {
    if (!target.IsValid())
      return;
    const std::string path =
        !state.local_symbol_path.empty()
            ? state.local_symbol_path
            : (state.process_is_remote ? std::string{} : state.target_path);
    if (session_target.IsValid() && session_target == target &&
        session_target_path == path)
      return;
    if (session_target.IsValid() && session_target != target)
      reset_target_session();
    script_conditions.clear();
    session_target = target;
    session_target_path = path;
    listener.StartListeningForEvents(
        target.GetBroadcaster(),
        lldb::SBTarget::eBroadcastBitBreakpointChanged |
            lldb::SBTarget::eBroadcastBitModulesLoaded);
    if (auto saved = session.open(target, path, state)) {
      launch_arguments = std::move(saved->arguments);
      launch_working_directory = std::move(saved->working_directory);
      watch_specs.clear();
      state.watches.clear();
      persistent_symbols = std::move(saved->symbols);
      for (auto &expression : saved->watches) {
        watch_specs.push_back(WatchSpec{false, expression});
        state.watches.push_back(WatchInfo{
            .expression = std::move(expression), .value = {}, .error = {}});
      }
      apply_launch_intent();
      restore_pending_session();
    }
  };

  std::vector<ValueScanCandidate> value_scan_candidates;
  std::uint64_t value_scan_generation = 0;
  auto reset_value_scan_state = [&] {
    value_scan_candidates.clear();
    value_scan_generation = 0;
    state.value_scan_results.clear();
    state.value_scan_match_count = 0;
    state.value_scan_active = false;
    state.value_scan_truncated = false;
    state.value_scan_error.clear();
    ++state.value_scan_revision;
  };
  auto reset_binary_string_state = [&] {
    state.binary_strings.clear();
    state.binary_string_count = 0;
    state.binary_strings_truncated = false;
    state.binary_strings_error.clear();
  };
  auto begin_generation = [&] {
    ++state.generation;
    state.stop_revision = 0;
    frameless_breakpoint_hits.clear();
    counted_frameless_stop_revision = 0;
    process = lldb::SBProcess{};
    active_process_id = 0;
    active_process_generation = 0;
    state.process_id = 0;
    state.process_is_remote = false;
    state.thread_id = 0;
    state.pc = 0;
    state.pc_file_address = 0;
    state.pc_module_load_bias = 0;
    state.has_pc_file_address = false;
    state.pc_module_path.clear();
    state.sp = 0;
    state.memory_base = 0;
    state.memory.clear();
    state.registers.clear();
    state.instructions.clear();
    state.disassembly_graph.reset();
    state.threads.clear();
    state.memory_regions.clear();
    state.modules.clear();
    state.stack.clear();
    state.heap_chunks.clear();
    state.heap_error.clear();
    state.patches.clear();
    state.crash = {};
    state.stop_reason.clear();
    state.process_output.clear();
    state.output_chunks.clear();
    state.output_chunk_bytes = 0;
    state.exit_status = 0;
    memory_view_address.reset();
    instruction_view_address.reset();
    reset_value_scan_state();
    reset_binary_string_state();
  };
  auto replace_target = [&] {
    qemu.stop();
    reset_target_session();
    if (process.IsValid() && should_destroy(process.GetState())) {
      process.Destroy();
    }
    if (target.IsValid()) {
      debugger.DeleteTarget(target);
    }
    begin_generation();
  };
  auto refresh_target_architecture = [&] {
    state.target_triple = safe_string(target.GetTriple());
    state.architecture = target_architecture(target);
    state.byte_order = byte_order_name(target.GetByteOrder());
    state.address_byte_size = target.GetAddressByteSize();
    state.supports_intel_syntax = is_x86_architecture(state.architecture);
  };
  auto process_is_remote = [](lldb::SBProcess candidate) {
    if (!candidate.IsValid()) {
      return false;
    }
    const std::string plugin =
        lowercase(safe_string(candidate.GetPluginName()));
    return plugin.find("remote") != std::string::npos;
  };
  auto adopt_process = [&](lldb::SBProcess candidate,
                           std::optional<bool> remote_hint = std::nullopt) {
    process = candidate;
    if (!process.IsValid()) {
      active_process_id = 0;
      active_process_generation = 0;
      state.process_id = 0;
      state.process_is_remote = false;
      return;
    }
    active_process_id = process.GetUniqueID();
    active_process_generation = state.generation;
    state.process_id = process.GetProcessID();
    state.process_is_remote = remote_hint.value_or(process_is_remote(process));
    if (state.process_is_remote && state.mode == SessionMode::Local) {
      state.mode = SessionMode::Remote;
    } else if (!state.process_is_remote) {
      state.mode = SessionMode::Local;
    }
  };
  auto connect_remote_process = [&](const std::string &endpoint,
                                    lldb::SBError &error) {
    lldb::SBProcess connected;
    {
      const std::lock_guard lock{worker_control_->mutex};
      worker_control_->remote_connection_active = true;
    }
    if (!shutdown_requested_.load()) {
      connected =
          target.ConnectRemote(listener, endpoint.c_str(), "gdb-remote", error);
    }
    {
      const std::lock_guard lock{worker_control_->mutex};
      worker_control_->remote_connection_active = false;
    }
    adopt_process(connected, true);
  };
  auto refresh_value_scan_results = [&] {
    constexpr std::size_t maximum_visible_results = 10'000;
    const bool big_endian = target.GetByteOrder() == lldb::eByteOrderBig;
    state.value_scan_match_count = value_scan_candidates.size();
    state.value_scan_truncated =
        value_scan_candidates.size() > maximum_visible_results;
    state.value_scan_results.clear();
    state.value_scan_results.reserve(
        std::min(value_scan_candidates.size(), maximum_visible_results));
    for (const ValueScanCandidate &candidate : value_scan_candidates) {
      if (state.value_scan_results.size() == maximum_visible_results) {
        break;
      }
      const MemoryRegionInfo *region =
          region_containing(state, candidate.address);
      state.value_scan_results.push_back(ValueScanResult{
          .address = candidate.address,
          .previous_value =
              format_scan_value(candidate.previous, state.value_scan_type,
                                state.value_scan_signed, big_endian),
          .current_value =
              format_scan_value(candidate.current, state.value_scan_type,
                                state.value_scan_signed, big_endian),
          .region = region == nullptr ? std::string{} : region->name,
      });
    }
  };
  auto scan_binary_strings_impl = [&](std::size_t minimum_length,
                                      bool include_utf16) {
    reset_binary_string_state();
    if (state.local_symbol_path.empty()) {
      state.binary_strings_error =
          l10n::text(l10n::Key::EngineNoLocalSymbolImageIsAvailable);
      return;
    }
    if (minimum_length == 0 || minimum_length > 4096) {
      state.binary_strings_error =
          l10n::text(l10n::Key::EngineMinimumStringLengthMustBeBetween1And4096);
      return;
    }
    std::string error;
    const auto image = read_binary_image(state.local_symbol_path, error);
    if (!image) {
      state.binary_strings_error = std::move(error);
      return;
    }
    state.binary_strings = extract_binary_strings(
        *image, minimum_length, include_utf16, state.binary_string_count,
        state.binary_strings_truncated);
    if (target.IsValid()) {
      for (BinaryStringInfo &result : state.binary_strings) {
        if (!result.has_file_address) {
          continue;
        }
        const lldb::SBAddress address =
            target.ResolveFileAddress(result.file_address);
        const lldb::addr_t load_address = address.GetLoadAddress(target);
        if (load_address != LLDB_INVALID_ADDRESS) {
          result.load_address = load_address;
          result.has_load_address = true;
        }
      }
    }
  };
  auto start_value_scan_impl = [&](ValueScanType type, std::string_view value,
                                   bool unknown, bool signed_values,
                                   bool writable_only) {
    constexpr std::size_t maximum_candidates = 2'000'000;
    constexpr std::size_t read_chunk_size = 1024 * 1024;
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      state.value_scan_error =
          l10n::text(l10n::Key::EngineValueScanningRequiresAStoppedProcess);
      return;
    }
    const std::size_t width = value_scan_width(type);
    if (width == 0) {
      state.value_scan_error =
          l10n::text(l10n::Key::EngineUnsupportedValueType);
      return;
    }
    const bool big_endian = target.GetByteOrder() == lldb::eByteOrderBig;
    std::optional<ScanValueBytes> exact;
    if (!unknown) {
      std::string error;
      exact = parse_scan_value(value, type, signed_values, big_endian, error);
      if (!exact) {
        state.value_scan_error = std::move(error);
        return;
      }
    }

    std::size_t possible_candidates = 0;
    for (const MemoryRegionInfo &region : state.memory_regions) {
      if (!region.readable || (writable_only && !region.writable) ||
          region.end <= region.start) {
        continue;
      }
      const std::uint64_t remainder = region.start % width;
      const std::uint64_t adjustment = remainder == 0 ? 0 : width - remainder;
      if (adjustment > region.end - region.start) {
        continue;
      }
      const std::uint64_t aligned_start = region.start + adjustment;
      if (aligned_start > region.end || width > region.end - aligned_start) {
        continue;
      }
      const std::uint64_t count =
          1 + (region.end - aligned_start - width) / width;
      if (count > maximum_candidates - possible_candidates) {
        possible_candidates = maximum_candidates + 1;
        break;
      }
      possible_candidates += static_cast<std::size_t>(count);
    }
    if (unknown && possible_candidates > maximum_candidates) {
      state.value_scan_error =
          l10n::text(l10n::Key::EngineUnknownValueScanCandidateLimit);
      return;
    }

    std::vector<ValueScanCandidate> candidates;
    if (unknown) {
      candidates.reserve(possible_candidates);
    }
    bool limit_reached = false;
    for (const MemoryRegionInfo &region : state.memory_regions) {
      if (!region.readable || (writable_only && !region.writable) ||
          region.end <= region.start) {
        continue;
      }
      const std::uint64_t remainder = region.start % width;
      const std::uint64_t adjustment = remainder == 0 ? 0 : width - remainder;
      if (adjustment > region.end - region.start) {
        continue;
      }
      std::uint64_t chunk_address = region.start + adjustment;
      while (chunk_address < region.end &&
             width <= region.end - chunk_address) {
        const std::uint64_t remaining = region.end - chunk_address;
        const std::size_t requested = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, read_chunk_size));
        std::vector<std::uint8_t> bytes(requested);
        lldb::SBError read_error;
        const std::size_t bytes_read = process.ReadMemory(
            chunk_address, bytes.data(), bytes.size(), read_error);
        for (std::size_t offset = 0; offset + width <= bytes_read;
             offset += width) {
          ScanValueBytes current{};
          std::copy_n(bytes.data() + offset, width, current.begin());
          if (unknown || std::equal(current.begin(), current.begin() + width,
                                    exact->begin())) {
            if (candidates.size() == maximum_candidates) {
              limit_reached = true;
              break;
            }
            candidates.push_back(ValueScanCandidate{
                .address = chunk_address + offset,
                .previous = current,
                .current = current,
            });
          }
        }
        if (limit_reached) {
          break;
        }
        chunk_address += requested;
      }
      if (limit_reached) {
        break;
      }
    }
    if (limit_reached) {
      reset_value_scan_state();
      state.value_scan_error = l10n::text(l10n::Key::EngineValueScanMatchLimit);
      return;
    }
    value_scan_candidates = std::move(candidates);
    value_scan_generation = state.generation;
    state.value_scan_type = type;
    state.value_scan_signed = signed_values;
    state.value_scan_writable_only = writable_only;
    state.value_scan_active = true;
    state.value_scan_error.clear();
    ++state.value_scan_revision;
    refresh_value_scan_results();
  };
  auto next_value_scan_impl = [&](ValueScanComparison comparison,
                                  std::string_view value) {
    constexpr std::size_t read_chunk_size = 1024 * 1024;
    if (!state.value_scan_active || value_scan_generation != state.generation) {
      state.value_scan_error =
          l10n::text(l10n::Key::EngineStartANewValueScanFirst);
      return;
    }
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      state.value_scan_error =
          l10n::text(l10n::Key::EngineNextScanRequiresAStoppedProcess);
      return;
    }
    const std::size_t width = value_scan_width(state.value_scan_type);
    const bool big_endian = target.GetByteOrder() == lldb::eByteOrderBig;
    std::optional<ScanValueBytes> exact;
    if (comparison == ValueScanComparison::Exact) {
      std::string error;
      exact = parse_scan_value(value, state.value_scan_type,
                               state.value_scan_signed, big_endian, error);
      if (!exact) {
        state.value_scan_error = std::move(error);
        return;
      }
    }

    std::vector<ValueScanCandidate> filtered;
    filtered.reserve(value_scan_candidates.size());
    std::size_t candidate_index = 0;
    while (candidate_index < value_scan_candidates.size()) {
      const ValueScanCandidate &first = value_scan_candidates[candidate_index];
      const MemoryRegionInfo *region = region_containing(state, first.address);
      if (region == nullptr || !region->readable ||
          width > region->end - first.address) {
        ++candidate_index;
        continue;
      }
      const std::uint64_t chunk_end =
          first.address +
          std::min<std::uint64_t>(region->end - first.address, read_chunk_size);
      const std::size_t requested =
          static_cast<std::size_t>(chunk_end - first.address);
      std::vector<std::uint8_t> bytes(requested);
      lldb::SBError read_error;
      const std::size_t bytes_read = process.ReadMemory(
          first.address, bytes.data(), bytes.size(), read_error);
      const std::uint64_t available_end = first.address + bytes_read;
      while (candidate_index < value_scan_candidates.size() &&
             value_scan_candidates[candidate_index].address < chunk_end) {
        ValueScanCandidate candidate = value_scan_candidates[candidate_index++];
        if (candidate.address > available_end ||
            width > available_end - candidate.address) {
          continue;
        }
        ScanValueBytes current{};
        const std::size_t offset =
            static_cast<std::size_t>(candidate.address - first.address);
        std::copy_n(bytes.data() + offset, width, current.begin());
        bool matches = false;
        switch (comparison) {
        case ValueScanComparison::Exact:
          matches = std::equal(current.begin(), current.begin() + width,
                               exact->begin());
          break;
        case ValueScanComparison::Changed:
          matches = !std::equal(current.begin(), current.begin() + width,
                                candidate.current.begin());
          break;
        case ValueScanComparison::Unchanged:
          matches = std::equal(current.begin(), current.begin() + width,
                               candidate.current.begin());
          break;
        case ValueScanComparison::Increased:
          matches = compare_scan_values(
                        current, candidate.current, state.value_scan_type,
                        state.value_scan_signed, big_endian) > 0;
          break;
        case ValueScanComparison::Decreased:
          matches = compare_scan_values(
                        current, candidate.current, state.value_scan_type,
                        state.value_scan_signed, big_endian) < 0;
          break;
        }
        if (matches) {
          candidate.previous = candidate.current;
          candidate.current = current;
          filtered.push_back(std::move(candidate));
        }
      }
    }
    value_scan_candidates = std::move(filtered);
    state.value_scan_error.clear();
    ++state.value_scan_revision;
    refresh_value_scan_results();
  };

  bool native_response_failed = false;
  bool external_console_response = false;
  NativeCommandStatus command_status{native_response_failed};

  auto set_breakpoint_impl = [&](std::string_view specification,
                                 std::string_view script = {}) {
    specification = trim(specification);
    if (!target.IsValid()) {
      state.error = l10n::text(l10n::Key::EngineNoTargetIsLoaded);
      return std::string{command_status.error_response(
          l10n::text(l10n::Key::EngineErrorNoTargetIsLoaded))};
    }
    if (specification.empty()) {
      state.error =
          l10n::text(l10n::Key::EngineBreakpointRequiresAnAddressOrSymbol);
      return std::string{
          l10n::text(l10n::Key::EngineUsageBpAddressRegisterSymbol)};
    }
    script = trim(script);
    std::optional<conditions::CompiledCondition> compiled_script;
    if (!script.empty()) {
      conditions::CompileResult compiled = conditions::compile(script);
      if (!compiled) {
        state.error = compiled.error;
        return command_status.error_detail(state.error);
      }
      compiled_script = std::move(compiled.condition);
    }

    std::optional<lldb::addr_t> address = parse_integer(specification);
    if (!address && specification.starts_with("*")) {
      std::string failure;
      address = resolve_address(specification.substr(1), process, failure);
      if (!address) {
        state.error = failure;
        return command_status.error_detail(failure);
      }
    }
    if (!address && process.IsValid() &&
        is_inspectable_stop(process.GetState())) {
      std::string register_name{specification};
      if (!register_name.empty() && register_name.front() == '$') {
        register_name.erase(0, 1);
      }
      lldb::SBFrame frame = selected_frame(process);
      lldb::SBValue register_value =
          frame.IsValid() ? frame.FindRegister(register_name.c_str())
                          : lldb::SBValue{};
      if (register_value.IsValid()) {
        lldb::SBError register_error;
        const std::uint64_t register_address =
            register_value.GetValueAsUnsigned(register_error);
        if (register_error.Success()) {
          address = register_address;
        }
      }
    }

    lldb::SBBreakpoint breakpoint;
    if (address) {
      breakpoint = target.BreakpointCreateByAddress(*address);
    } else {
      const std::string symbol{specification};
      breakpoint = target.BreakpointCreateByName(symbol.c_str());
      // Remote/qemu sessions can stop at the dynamic loader where LLDB cannot
      // resolve main-image symbols (and LLDB 21 never binds pending
      // breakpoints over gdb-remote). Fall back to the engine's own ELF
      // symbol table; non-PIE values are runtime addresses.
      if (breakpoint.IsValid() && breakpoint.GetNumLocations() == 0 &&
          (state.mode == SessionMode::Remote ||
           state.mode == SessionMode::QemuUser ||
           state.mode == SessionMode::QemuSystem)) {
        if (main_symbols_path_ != state.local_symbol_path ||
            main_symbols_.empty()) {
          main_symbols_.clear();
          for (const ElfSymbol &elf_symbol :
               read_elf_symbols(state.local_symbol_path)) {
            main_symbols_.emplace_back(elf_symbol.name, elf_symbol.value);
          }
          main_symbols_path_ = state.local_symbol_path;
        }
        const auto found = std::ranges::find_if(
            main_symbols_, [symbol](const auto &candidate) {
              return candidate.first == symbol;
            });
        if (found != main_symbols_.end() && found->second != 0) {
          target.BreakpointDelete(breakpoint.GetID());
          script_conditions.erase(breakpoint.GetID());
          breakpoint = target.BreakpointCreateByAddress(
              static_cast<lldb::addr_t>(found->second));
        }
      }
    }
    if (!breakpoint.IsValid()) {
      state.error = l10n::text(l10n::Key::EngineLLDBRejectedTheBreakpoint);
      return std::string{command_status.error_response(
          l10n::text(l10n::Key::EngineErrorLLDBRejectedTheBreakpoint))};
    }

    if (compiled_script) {
      const std::uint32_t id = static_cast<std::uint32_t>(breakpoint.GetID());
      script_conditions.insert_or_assign(
          id, ScriptConditionState{.source = std::string{script},
                                   .compiled = std::move(*compiled_script),
                                   .last_error = {}});
    }
    refresh_breakpoint_state();
    state.error.clear();
    const auto id = static_cast<unsigned int>(breakpoint.GetID());
    const auto locations = breakpoint.GetNumLocations();
    if (locations == 0) {
      return l10n::format(l10n::Key::EngineBreakpointSetPending, id);
    }
    return locations == 1
               ? l10n::format(l10n::Key::EngineBreakpointSetLocation, id,
                              locations)
               : l10n::format(l10n::Key::EngineBreakpointSetLocations, id,
                              locations);
  };

  auto remove_breakpoint_impl = [&](std::uint32_t id) {
    if (!target.IsValid() ||
        !target.BreakpointDelete(static_cast<lldb::break_id_t>(id))) {
      state.error = l10n::format(l10n::Key::EngineBreakpointNotFound, id);
      return command_status.error_detail(state.error);
    }
    script_conditions.erase(id);
    refresh_breakpoint_state();
    state.error.clear();
    return l10n::format(l10n::Key::EngineBreakpointDeleted, id);
  };

  auto enable_breakpoint_impl = [&](std::uint32_t id, bool enabled) {
    lldb::SBBreakpoint breakpoint =
        target.IsValid()
            ? target.FindBreakpointByID(static_cast<lldb::break_id_t>(id))
            : lldb::SBBreakpoint{};
    if (!breakpoint.IsValid()) {
      state.error = l10n::format(l10n::Key::EngineBreakpointNotFound, id);
      return command_status.error_detail(state.error);
    }
    breakpoint.SetEnabled(enabled);
    refresh_breakpoint_state();
    state.error.clear();
    return enabled ? l10n::format(l10n::Key::EngineBreakpointEnabled, id)
                   : l10n::format(l10n::Key::EngineBreakpointDisabled, id);
  };

  auto set_breakpoint_script_impl = [&](std::uint32_t id,
                                        std::string_view source) {
    lldb::SBBreakpoint breakpoint =
        target.IsValid()
            ? target.FindBreakpointByID(static_cast<lldb::break_id_t>(id))
            : lldb::SBBreakpoint{};
    if (!breakpoint.IsValid()) {
      state.error = l10n::format(l10n::Key::EngineBreakpointNotFound, id);
      return command_status.error_detail(state.error);
    }
    source = trim(source);
    if (source.empty()) {
      script_conditions.erase(id);
      refresh_breakpoint_state();
      state.error.clear();
      return l10n::format(l10n::Key::EngineBreakpointScriptRemoved, id);
    }
    conditions::CompileResult compiled = conditions::compile(source);
    if (!compiled) {
      state.error = compiled.error;
      return command_status.error_detail(state.error);
    }
    script_conditions.insert_or_assign(
        id, ScriptConditionState{.source = std::string{source},
                                 .compiled = std::move(compiled.condition),
                                 .last_error = {}});
    refresh_breakpoint_state();
    state.error.clear();
    return l10n::format(l10n::Key::EngineBreakpointScriptSet, id);
  };

  auto scripted_breakpoint_should_continue = [&] {
    struct EvaluationData {
      lldb::SBFrame frame;
      lldb::SBProcess process;
    };
    const auto read_register = [](void *opaque, std::string_view name,
                                  std::uint64_t &value, std::string &error) {
      auto &data = *static_cast<EvaluationData *>(opaque);
      const std::string owned_name{name};
      lldb::SBValue register_value =
          data.frame.FindRegister(owned_name.c_str());
      if (!register_value.IsValid()) {
        error =
            l10n::format(l10n::Key::EngineUnknownRegister, owned_name.c_str());
        return false;
      }
      lldb::SBError register_error;
      value = register_value.GetValueAsUnsigned(register_error);
      if (register_error.Fail()) {
        error = error_text(register_error);
        return false;
      }
      return true;
    };
    const auto read_condition_memory = [](void *opaque, std::uint64_t address,
                                          std::span<std::uint8_t> bytes,
                                          std::string &error) {
      auto &data = *static_cast<EvaluationData *>(opaque);
      lldb::SBError read_error;
      const std::size_t read =
          data.process.ReadMemory(static_cast<lldb::addr_t>(address),
                                  bytes.data(), bytes.size(), read_error);
      if (read_error.Fail()) {
        error = error_text(read_error);
        return false;
      }
      if (read != bytes.size()) {
        error = l10n::format(l10n::Key::EngineShortMemoryRead, address);
        return false;
      }
      return true;
    };

    std::unordered_set<std::uint32_t> evaluated;
    bool saw_scripted_breakpoint = false;
    const std::uint32_t thread_count = process.GetNumThreads();
    for (std::uint32_t thread_index = 0; thread_index < thread_count;
         ++thread_index) {
      lldb::SBThread thread = process.GetThreadAtIndex(thread_index);
      if (!thread.IsValid() ||
          thread.GetStopReason() != lldb::eStopReasonBreakpoint) {
        continue;
      }
      const std::size_t reason_words = thread.GetStopReasonDataCount();
      for (std::size_t word = 0; word + 1 < reason_words; word += 2) {
        const auto id = static_cast<std::uint32_t>(
            thread.GetStopReasonDataAtIndex(static_cast<std::uint32_t>(word)));
        if (!evaluated.insert(id).second) {
          continue;
        }
        const auto script = script_conditions.find(id);
        if (script == script_conditions.end()) {
          return false;
        }
        saw_scripted_breakpoint = true;
        EvaluationData data{.frame = thread.GetFrameAtIndex(0),
                            .process = process};
        conditions::EvaluationContext context{.user_data = &data,
                                              .read_register = read_register,
                                              .read_memory =
                                                  read_condition_memory};
        conditions::EvaluationResult result =
            conditions::evaluate(script->second.compiled, context);
        script->second.last_error = result.error;
        if (!result) {
          state.error = l10n::format(l10n::Key::EngineBreakpointConditionError,
                                     id, result.error.c_str());
          return false;
        }
        if (result.matched) {
          return false;
        }
      }
    }
    return saw_scripted_breakpoint;
  };

  auto step_instruction_impl = [&](bool step_over) {
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      state.error =
          l10n::text(l10n::Key::EngineSteppingRequiresAStoppedProcess);
      return command_status.error_detail(state.error);
    }
    if (is_frameless_qemu_mips_stop(process, state)) {
      if (step_over) {
        state.error = l10n::text(
            l10n::Key::
                EngineInstructionStepOverIsUnavailableForThisRemoteTarget);
        return command_status.error_detail(state.error);
      }
      const std::uint64_t previous_pc = state.pc;
      const std::uint64_t previous_stop_revision = state.stop_revision;
      std::string failure;
      if (!step_frameless_qemu_mips_at_breakpoint(target, state, failure)) {
        state.error = std::move(failure);
        return command_status.error_detail(state.error);
      }
      instruction_view_address.reset();
      capture_stop(target, process, memory_view_address,
                   instruction_view_address, state);
      if (state.pc != previous_pc &&
          state.stop_revision <= previous_stop_revision) {
        state.stop_revision = previous_stop_revision + 1;
        record_stop_history(state);
      }
      refresh_breakpoint_state();
      state.error.clear();
      return std::string{l10n::text(l10n::Key::EngineSteppedInto)};
    }

    lldb::SBThread thread = process.GetSelectedThread();
    if (!thread.IsValid()) {
      state.error = l10n::text(l10n::Key::EngineNoSelectedThread);
      return command_status.error_detail(state.error);
    }
    lldb::SBError step_error;
    thread.StepInstruction(step_over, step_error);
    if (step_error.Fail()) {
      state.error = error_text(step_error);
      return command_status.error_detail(state.error);
    }
    state.state = SessionState::Running;
    state.crash = {};
    state.error.clear();
    return step_over ? std::string{l10n::text(l10n::Key::EngineSteppingOver)}
                     : std::string{l10n::text(l10n::Key::EngineSteppingInto)};
  };

  auto dump_memory_impl = [&](lldb::addr_t address) {
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      state.error = l10n::text(
          l10n::Key::EngineMemoryCanOnlyBeReadWhileTheProcessIsStopped);
      return command_status.error_detail(state.error);
    }
    memory_view_address = address;
    capture_memory(process, address, state);
    if (!state.error.empty()) {
      return command_status.error_detail(state.error);
    }
    return l10n::format(l10n::Key::EngineDumpingMemory, state.memory.size(),
                        static_cast<std::uint64_t>(address));
  };

  auto read_instructions_impl = [&](lldb::addr_t address) {
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      state.error = l10n::text(
          l10n::Key::EngineInstructionsCanOnlyBeReadWhileTheProcessIsStopped);
      return;
    }
    instruction_view_address = address;
    capture_instructions(target, address, state);
    if (state.instructions.empty()) {
      state.error =
          l10n::text(l10n::Key::EngineNoInstructionsFoundAtTheRequestedAddress);
    } else {
      state.error.clear();
    }
  };

  std::uint64_t native_command_revision = 0;
  std::uint64_t synchronized_command_revision = 0;
  auto execute_lldb_command = [&](std::string_view command_text,
                                  bool console_response = true) {
    external_console_response |= console_response;
    lldb::SBCommandReturnObject result;
    const std::string owned_command{command_text};
    lldb::SBCommandReturnObject expanded;
    lldb::SBTarget command_target = debugger.GetSelectedTarget();
    std::uint32_t previous_breakpoint_id = 0;
    struct IgnoreSample {
      lldb::SBBreakpoint breakpoint;
      std::uint32_t count;
      std::uint32_t hits;
    };
    std::vector<IgnoreSample> ignore_samples;
    if (sessions_ && command_target.IsValid()) {
      for (std::uint32_t i = 0; i < command_target.GetNumBreakpoints(); ++i) {
        auto breakpoint = command_target.GetBreakpointAtIndex(i);
        previous_breakpoint_id =
            std::max(previous_breakpoint_id,
                     static_cast<std::uint32_t>(breakpoint.GetID()));
        ignore_samples.push_back({breakpoint, breakpoint.GetIgnoreCount(),
                                  breakpoint.GetHitCount()});
      }
      debugger.GetCommandInterpreter().ResolveCommand(owned_command.c_str(),
                                                      expanded);
    }
    debugger.GetCommandInterpreter().HandleCommand(owned_command.c_str(),
                                                   result, true);
    ++native_command_revision;
    for (auto &sample : ignore_samples) {
      if (sample.breakpoint.IsValid() &&
          sample.breakpoint.GetHitCount() == sample.hits &&
          sample.breakpoint.GetIgnoreCount() != sample.count)
        session.ignore_count_changed(sample.breakpoint, true);
    }
    if (sessions_ && result.Succeeded() && command_target.IsValid() &&
        command_target == debugger.GetSelectedTarget())
      session.remember_exception_command(command_target,
                                         expanded.Succeeded()
                                             ? safe_string(expanded.GetOutput())
                                             : owned_command,
                                         previous_breakpoint_id);
    std::string output = safe_string(result.GetOutput());
    output += safe_string(result.GetError());
    return output;
  };

  auto synchronize_after_lldb_command = [&](std::optional<bool> remote_hint =
                                                std::nullopt,
                                            bool local_target_hint = false) {
    synchronized_command_revision = native_command_revision;
    lldb::SBTarget selected_target = debugger.GetSelectedTarget();
    lldb::SBProcess selected_process = selected_target.IsValid()
                                           ? selected_target.GetProcess()
                                           : lldb::SBProcess{};
    const bool target_changed =
        selected_target.IsValid() != target.IsValid() ||
        (selected_target.IsValid() && selected_target != target);
    const bool process_changed =
        selected_process.IsValid() &&
        (target_changed || active_process_generation != state.generation ||
         selected_process.GetUniqueID() != active_process_id);
    if (target_changed || process_changed) {
      begin_generation();
    }

    if (target_changed) {
      reset_target_session();
      target = selected_target;
      state.target_path.clear();
      state.local_symbol_path.clear();
      state.security = {};
      state.breakpoints.clear();
      script_conditions.clear();
    } else if (selected_target.IsValid()) {
      target = selected_target;
    }

    if (selected_process.IsValid()) {
      adopt_process(selected_process,
                    process_changed
                        ? remote_hint
                        : std::optional<bool>{state.process_is_remote});
    } else if (target_changed || !target.IsValid()) {
      adopt_process(lldb::SBProcess{});
    }

    if (target.IsValid()) {
      std::array<char, 4096> path{};
      target.GetExecutable().GetPath(path.data(), path.size());
      const std::string selected_path = safe_string(path.data());
      if (!selected_path.empty() &&
          (state.mode == SessionMode::Local || state.target_path.empty())) {
        // Local sessions always follow the launched binary; remote
        // sessions (gdbserver, qemu-user) report the stub's own
        // executable (qemu), which is not the image under analysis.
        state.target_path = selected_path;
        if (local_target_hint ||
            (!state.process_is_remote && state.local_symbol_path.empty() &&
             process.IsValid())) {
          state.local_symbol_path = selected_path;
        }
      }
      state.security = state.local_symbol_path.empty()
                           ? ElfSecurityInfo{}
                           : inspect_elf_security(state.local_symbol_path);
      refresh_target_architecture();
      capture_modules(target, state);
      open_target_session();
      restore_pending_session();
    } else {
      state.target_triple.clear();
      state.architecture.clear();
      state.byte_order.clear();
      state.address_byte_size = 0;
      state.supports_intel_syntax = false;
    }

    const lldb::StateType process_state =
        process.IsValid() ? process.GetState() : lldb::eStateInvalid;
    if (is_inspectable_stop(process_state)) {
      instruction_view_address.reset();
      capture_stop(target, process, memory_view_address,
                   instruction_view_address, state);
    } else if (process_state == lldb::eStateRunning ||
               process_state == lldb::eStateStepping ||
               process_state == lldb::eStateLaunching ||
               process_state == lldb::eStateAttaching ||
               process_state == lldb::eStateConnected) {
      state.state = SessionState::Running;
      state.crash = {};
      state.error.clear();
    } else if (process_state == lldb::eStateExited) {
      state.state = SessionState::Exited;
      state.exit_status = process.GetExitStatus();
    } else if (target.IsValid()) {
      state.state = SessionState::TargetLoaded;
    } else {
      state.state = SessionState::NoTarget;
    }
  };

  auto refresh_watches = [&] {
    state.watches.clear();
    lldb::SBFrame frame = selected_frame(process);
    for (const WatchSpec &watch : watch_specs) {
      WatchInfo result;
      result.expression = watch.expression;
      if (watch.execute) {
        result.value = execute_lldb_command(watch.expression, false);
      } else if (!frame.IsValid()) {
        result.error = l10n::text(l10n::Key::EngineNoSelectedFrame);
      } else {
        lldb::SBValue value =
            frame.EvaluateExpression(watch.expression.c_str());
        const lldb::SBError error = value.GetError();
        if (error.Fail()) {
          result.error = error_text(error);
        } else {
          lldb::SBStream description;
          value.GetDescription(description);
          result.value = safe_string(description.GetData());
          if (result.value.empty()) {
            result.value = safe_string(value.GetValue());
          }
        }
      }
      state.watches.push_back(std::move(result));
    }
  };

  auto context_impl = [&](std::string_view requested_section) {
    refresh_watches();
    return render_console_context(state, context_sections, requested_section);
  };

  auto execute_prompt = [&](const std::string &command_line) -> std::string {
    const std::string_view text = trim(command_line);
    if (text.empty()) {
      return {};
    }

    const std::size_t separator = text.find_first_of(" \t");
    const std::string command = lowercase(text.substr(0, separator));
    const std::string_view arguments = separator == std::string_view::npos
                                           ? std::string_view{}
                                           : trim(text.substr(separator + 1));
    std::string response;
    std::optional<std::string> handled;

    if ((handled = patch_commands.execute(command, arguments, target, process,
                                          state, native_response_failed))) {
      response = std::move(*handled);
    } else if ((handled = execute_inspection_command(command, arguments, target,
                                                     process, state,
                                                     native_response_failed))) {
      response = std::move(*handled);
    } else if ((handled =
                    execute_heap_command(command, arguments, target, process,
                                         state, native_response_failed))) {
      response = std::move(*handled);
    } else if ((handled =
                    execute_flow_command(command, arguments, target, process,
                                         state, native_response_failed))) {
      response = std::move(*handled);
    } else if (command == "help" || command == "h") {
      response = l10n::text(l10n::Key::EngineCommandHelp);
    } else if (command == "u" || command == "disasm") {
      response =
          execute_lldb_command(std::string{"disassemble --start-address "} +
                               std::string{arguments} + " --count 32");
    } else if (command == "k" || command == "kp" || command == "backtrace") {
      response = execute_lldb_command("thread backtrace all");
    } else if (command == "ln" || command == "symbol") {
      response = execute_lldb_command(std::string{"image lookup --address "} +
                                      std::string{arguments});
    } else if (command == "x" &&
               arguments.find('!') != std::string_view::npos) {
      const std::size_t symbol_separator = arguments.find('!');
      response = execute_lldb_command(
          "image lookup --regex --name " +
          std::string{arguments.substr(symbol_separator + 1)});
    } else if (command == "da" || command == "du" || command == "db" ||
               command == "dc" || command == "dw" || command == "dd" ||
               command == "dq" || command == "dps" || command == "dds" ||
               command == "dqs" || command == "dpa" || command == "dpc" ||
               command == "dpp" || command == "dsu") {
      std::uint32_t item_size = 1;
      std::string format = "x";
      if (command == "dw" || command == "du") {
        item_size = 2;
      } else if (command == "dd" || command == "dds") {
        item_size = 4;
      } else if (command == "dq" || command == "dqs" || command == "dps" ||
                 command == "dpa" || command == "dpc" || command == "dpp" ||
                 command == "dsu") {
        item_size = std::max<std::uint32_t>(1, state.address_byte_size);
      }
      if (command == "da") {
        format = "c-string";
      } else if (command == "dps" || command == "dds" || command == "dqs" ||
                 command == "dpa" || command == "dpc" || command == "dpp" ||
                 command == "dsu") {
        format = "address";
      }
      response = execute_lldb_command("memory read --format " + format +
                                      " --size " + std::to_string(item_size) +
                                      " --count 32 " + std::string{arguments});
    } else if (command == "eb" || command == "ew" || command == "ed" ||
               command == "eq") {
      const std::uint32_t item_size = command == "eb"   ? 1
                                      : command == "ew" ? 2
                                      : command == "ed" ? 4
                                                        : 8;
      response = execute_lldb_command("memory write --size " +
                                      std::to_string(item_size) + ' ' +
                                      std::string{arguments});
      synchronize_after_lldb_command();
    } else if (command == "dumpargs") {
      response = execute_lldb_command("frame variable --show-types --scope");
    } else if (command == "aslr") {
      if (arguments.empty()) {
        response = execute_lldb_command("settings show target.disable-aslr");
      } else {
        const std::string setting = lowercase(arguments);
        if (setting != "on" && setting != "off") {
          response = l10n::text(l10n::Key::EngineUsageAslrOnOff);
        } else {
          response = execute_lldb_command(
              std::string{"settings set target.disable-aslr "} +
              (setting == "on" ? "false" : "true"));
        }
      }
    } else if (command == "pwndbg") {
      response = l10n::text(l10n::Key::EnginePwndbgHelp);
    } else if (command == "config") {
      std::ostringstream configuration;
      configuration << "architecture=" << state.architecture << '\n'
                    << "session.mode=" << to_string(state.mode) << '\n'
                    << "disassembly.syntax="
                    << (state.supports_intel_syntax
                            ? (state.intel_syntax ? "intel" : "att")
                            : "architecture")
                    << '\n'
                    << "theme=" << (state.theme_dark ? "dark" : "light") << '\n'
                    << "search.max-results=256\n"
                    << "heap.max-chunks=256\n"
                    << "launch.args=";
      for (const std::string &argument : launch_arguments) {
        configuration << argument << ' ';
      }
      configuration << "\ncontext.sections=";
      for (const std::string &section : context_sections) {
        configuration << section << ' ';
      }
      configuration << "\ncontext.watches=" << watch_specs.size();
      response = configuration.str();
    } else if (command == "theme") {
      if (arguments.empty()) {
        response =
            std::string{"theme="} + (state.theme_dark ? "dark" : "light");
      } else {
        const std::string requested = lowercase(arguments);
        if (requested != "dark" && requested != "light") {
          response = l10n::text(l10n::Key::EngineUsageThemeDarkLight);
        } else {
          state.theme_dark = requested == "dark";
          response = std::string{"theme="} + requested;
        }
      }
    } else if (command == "tip") {
      response = l10n::text(l10n::Key::EngineCommandTips);
      if (arguments == "--all") {
        response += l10n::text(l10n::Key::EngineAdditionalCommandTips);
      }
    } else if (command == "context" || command == "ctx") {
      response =
          state.state == SessionState::Stopped
              ? context_impl(arguments)
              : command_status.error_response(l10n::text(
                    l10n::Key::EngineErrorContextRequiresAStoppedProcess));
    } else if (command == "set" &&
               (arguments == "context-sections" ||
                arguments.starts_with("context-sections "))) {
      const std::string_view section_text = arguments.size() == 16
                                                ? std::string_view{}
                                                : trim(arguments.substr(16));
      if (section_text.empty()) {
        response = l10n::text(l10n::Key::EngineUsageSetContextSectionsSection);
      } else {
        context_sections = split_arguments(section_text);
        response = l10n::text(l10n::Key::EngineContextSectionsUpdated);
      }
    } else if (command == "ctx-watch") {
      const std::size_t action_end = arguments.find_first_of(" \t");
      const std::string action = lowercase(arguments.substr(0, action_end));
      const std::string_view watch_expression =
          action_end == std::string_view::npos
              ? std::string_view{}
              : trim(arguments.substr(action_end + 1));
      if ((action == "eval" || action == "execute") &&
          !watch_expression.empty()) {
        watch_specs.push_back(WatchSpec{
            .execute = action == "execute",
            .expression = std::string{watch_expression},
        });
        refresh_watches();
        response = l10n::text(l10n::Key::EngineContextWatchAdded);
      } else if (action == "delete") {
        const auto index = parse_integer(watch_expression);
        if (!index || *index >= watch_specs.size()) {
          response = command_status.error_response(
              l10n::text(l10n::Key::EngineErrorContextWatchIndexNotFound));
        } else {
          watch_specs.erase(watch_specs.begin() +
                            static_cast<std::ptrdiff_t>(*index));
          refresh_watches();
          response = l10n::text(l10n::Key::EngineContextWatchDeleted);
        }
      } else if (action == "clear") {
        watch_specs.clear();
        state.watches.clear();
        response = l10n::text(l10n::Key::EngineContextWatchesCleared);
      } else if (arguments.empty()) {
        std::ostringstream watches;
        for (std::size_t index = 0; index < watch_specs.size(); ++index) {
          watches << index << ' '
                  << (watch_specs[index].execute ? "execute " : "eval ")
                  << watch_specs[index].expression << '\n';
        }
        response = watches.str();
      } else {
        response = l10n::text(
            l10n::Key::
                EngineUsageCtxWatchEvalExecuteExpressionDeleteIndexClear);
      }
    } else if (command == "cymbol") {
      const std::vector<std::string> values = split_arguments(arguments);
      if (values.empty() || values[0] == "-l") {
        std::ostringstream symbols;
        for (const auto &[name, address] : custom_symbols) {
          symbols << name << " = 0x" << std::hex << address << '\n';
        }
        response = symbols.str();
        if (response.empty()) {
          response = l10n::text(l10n::Key::EngineNoCustomSymbols);
        }
      } else if (values[0] == "-d" && values.size() == 2) {
        const auto symbol =
            std::find_if(custom_symbols.begin(), custom_symbols.end(),
                         [&values](const auto &candidate) {
                           return candidate.first == values[1];
                         });
        const bool saved_symbol = std::any_of(
            persistent_symbols.begin(), persistent_symbols.end(),
            [&](const auto &candidate) { return candidate.name == values[1]; });
        if (symbol == custom_symbols.end() && !saved_symbol) {
          response = command_status.error_response(
              l10n::text(l10n::Key::EngineErrorCustomSymbolNotFound));
        } else {
          if (symbol != custom_symbols.end())
            custom_symbols.erase(symbol);
          std::erase_if(persistent_symbols, [&](const auto &saved) {
            return saved.name == values[1];
          });
          response = l10n::text(l10n::Key::EngineCustomSymbolDeleted);
        }
      } else if (values.size() == 2) {
        std::string failure;
        const auto address = resolve_address(values[1], process, failure);
        if (!address) {
          response = command_status.error_detail(failure);
        } else {
          const auto existing =
              std::find_if(custom_symbols.begin(), custom_symbols.end(),
                           [&values](const auto &candidate) {
                             return candidate.first == values[0];
                           });
          if (existing == custom_symbols.end()) {
            custom_symbols.emplace_back(values[0], *address);
          } else {
            existing->second = *address;
          }
          if (sessions_) {
            try {
              auto saved = session.address(target.ResolveLoadAddress(*address));
              std::erase_if(persistent_symbols, [&](const auto &candidate) {
                return candidate.name == values[0];
              });
              if (saved)
                persistent_symbols.push_back(
                    SessionSymbol{values[0], std::move(*saved)});
              else
                session.notice(state,
                               l10n::text(l10n::Key::LldbSessionUnsafeAddress));
            } catch (const std::exception &error) {
              session.notice(state, error.what());
            }
          }
          response = values[0] + " = 0x";
          std::ostringstream address_text;
          address_text << std::hex << *address;
          response += address_text.str();
        }
      } else if (values.size() == 1) {
        const auto symbol =
            std::find_if(custom_symbols.begin(), custom_symbols.end(),
                         [&values](const auto &candidate) {
                           return candidate.first == values[0];
                         });
        if (symbol == custom_symbols.end()) {
          response = command_status.error_response(
              l10n::text(l10n::Key::EngineErrorCustomSymbolNotFound));
        } else {
          std::ostringstream address_text;
          address_text << values[0] << " = 0x" << std::hex << symbol->second;
          response = address_text.str();
        }
      } else {
        response = l10n::text(l10n::Key::EngineUsageCymbolLDNameNameAddress);
      }
    } else if (command == "cstruct" || command == "dt") {
      const std::vector<std::string> values = split_arguments(arguments);
      if (values.size() != 2) {
        response = l10n::text(l10n::Key::EngineUsageCstructTypeAddress);
      } else {
        std::string failure;
        const auto address = resolve_address(values[1], process, failure);
        if (!address) {
          response = command_status.error_detail(failure);
        } else {
          std::ostringstream expression;
          expression << "expression -- *(" << values[0] << "*)0x" << std::hex
                     << *address;
          response = execute_lldb_command(expression.str());
        }
      }
    } else if (command == "elfsections") {
      response = execute_lldb_command(
          arguments.empty()
              ? "image dump sections"
              : std::string{"image dump sections "} + std::string{arguments});
    } else if (command == "start" || command == "sstart") {
      if (!arguments.empty())
        launch_arguments = split_arguments(arguments);
      apply_launch_intent();
      session.remove_transients(target);
      auto initial = target.BreakpointCreateByName(
          command == "sstart" ? "__libc_start_main" : "main");
      if (initial.IsValid()) {
        initial.SetOneShot(true);
        session.transient(initial);
      }
      response += execute_lldb_command("run");
      synchronize_after_lldb_command();
    } else if (command == "attachp") {
      const auto process_id = parse_integer(arguments);
      if (!process_id) {
        response = l10n::text(l10n::Key::EngineUsageAttachpPid);
      } else if (!target.IsValid()) {
        response = command_status.error_response(l10n::text(
            l10n::Key::EngineErrorSelectTheProcessExecutableBeforeAttach));
      } else {
        lldb::SBError attach_error;
        process = target.AttachToProcessWithID(
            listener, static_cast<lldb::pid_t>(*process_id), attach_error);
        if (attach_error.Fail() || !process.IsValid()) {
          state.error = error_text(attach_error);
          response = command_status.error_detail(state.error);
        } else {
          response =
              l10n::format(l10n::Key::EngineAttachedToProcess, *process_id);
          synchronize_after_lldb_command();
          state.error.clear();
        }
      }
    } else if (command == "breakrva" ||
               (command == "pie" && arguments.starts_with("breakpoint "))) {
      const std::string_view offset_text =
          command == "breakrva" ? arguments : trim(arguments.substr(11));
      const auto offset = parse_integer(offset_text);
      if (!offset || target.GetNumModules() == 0) {
        response =
            l10n::text(l10n::Key::EngineUsageBreakrvaOffsetPieBreakpointOffset);
      } else {
        lldb::SBModule module = target.GetModuleAtIndex(0);
        const lldb::addr_t base =
            module.GetObjectFileHeaderAddress().GetLoadAddress(target);
        if (base == LLDB_INVALID_ADDRESS) {
          response = command_status.error_response(
              l10n::text(l10n::Key::EngineErrorExecutableIsNotLoaded));
        } else {
          std::ostringstream specification;
          specification << "0x" << std::hex << (base + *offset);
          response = set_breakpoint_impl(specification.str());
        }
      }
    } else if (command == "argv") {
      std::ostringstream listing;
      for (std::size_t index = 0; index < launch_arguments.size(); ++index) {
        listing << index << ": " << launch_arguments[index] << '\n';
      }
      response = listing.str();
      if (response.empty()) {
        response = l10n::text(l10n::Key::EngineNoConfiguredLaunchArguments);
      }
    } else if (command == "file") {
      const std::vector<std::string> paths = split_arguments(arguments);
      if (paths.size() != 1) {
        response = l10n::text(l10n::Key::EngineUsageFilePath);
      } else if (process.IsValid() &&
                 process.GetState() != lldb::eStateExited &&
                 process.GetState() != lldb::eStateDetached &&
                 process.GetState() != lldb::eStateInvalid) {
        response = command_status.error_response(l10n::text(
            l10n::Key::
                EngineErrorTerminateTheCurrentProcessBeforeSelectingATarget));
      } else {
        reset_target_session();
        if (target.IsValid()) {
          debugger.DeleteTarget(target);
        }
        begin_generation();
        lldb::SBError target_error;
        target = debugger.CreateTarget(paths.front().c_str(), nullptr, nullptr,
                                       true, target_error);
        if (target_error.Fail() || !target.IsValid()) {
          state.error = error_text(target_error);
          response = command_status.error_detail(state.error);
        } else {
          response = l10n::format(l10n::Key::EngineTargetCreated,
                                  paths.front().c_str());
          state.mode = SessionMode::Local;
          state.target_path = paths.front();
          state.local_symbol_path = paths.front();
          state.breakpoints.clear();
          synchronize_after_lldb_command(std::nullopt, true);
          state.error.clear();
        }
      }
    } else if (command == "run") {
      if (!arguments.empty())
        launch_arguments = split_arguments(arguments);
      apply_launch_intent();
      response += execute_lldb_command("run");
      synchronize_after_lldb_command();
    } else if (command == "starti" || command == "entry") {
      if (!arguments.empty())
        launch_arguments = split_arguments(arguments);
      apply_launch_intent();
      std::string launch_command{"process launch --stop-at-entry"};
      if (!arguments.empty()) {
        launch_command += " -- ";
        launch_command += arguments;
      }
      response = execute_lldb_command(launch_command);
      synchronize_after_lldb_command();
    } else if (command == "set" &&
               (arguments == "args" || arguments.starts_with("args "))) {
      const std::string_view argument_text = arguments.size() == 4
                                                 ? std::string_view{}
                                                 : trim(arguments.substr(4));
      launch_arguments = split_arguments(argument_text);
      apply_launch_intent();
    } else if (command == "threads") {
      response = execute_lldb_command("thread list");
      synchronize_after_lldb_command();
    } else if (command == "info") {
      const std::string topic = lowercase(arguments);
      if (topic == "breakpoints") {
        response = execute_lldb_command("breakpoint list");
      } else if (topic == "threads") {
        response = execute_lldb_command("thread list");
      } else if (topic == "regs" || topic == "registers") {
        response = execute_lldb_command("register read");
      } else {
        response = l10n::text(l10n::Key::EngineUsageInfoBreakpointsThreadsRegs);
      }
      synchronize_after_lldb_command();
    } else if (command == "finish") {
      response = execute_lldb_command("thread step-out");
      synchronize_after_lldb_command();
    } else if (command == "print") {
      response = arguments.empty()
                     ? l10n::text(l10n::Key::EngineUsagePrintExpression)
                     : execute_lldb_command(std::string{"expression -- "} +
                                            std::string{arguments});
      synchronize_after_lldb_command();
    } else if (command.starts_with("x/")) {
      response = execute_lldb_command(text);
      synchronize_after_lldb_command();
    } else if (command == "bt") {
      response = execute_lldb_command("thread backtrace");
      synchronize_after_lldb_command();
    } else if (command == "up" || command == "down") {
      response = execute_lldb_command(command == "up" ? "frame select -r 1"
                                                      : "frame select -r -1");
      synchronize_after_lldb_command();
    } else if (command == "watch" || command == "rwatch" ||
               command == "awatch") {
      const char *access = command == "watch"    ? "write"
                           : command == "rwatch" ? "read"
                                                 : "read_write";
      response =
          execute_lldb_command(std::string{"watchpoint set expression -w "} +
                               access + " -- " + std::string{arguments});
    } else if (command == "script-condition") {
      const std::size_t expression_start = arguments.find_first_of(" \t");
      if (expression_start == std::string_view::npos) {
        response = l10n::text(
            l10n::Key::EngineUsageScriptConditionBreakpointIdExpression);
      } else {
        const auto id = parse_integer(arguments.substr(0, expression_start));
        response =
            id ? set_breakpoint_script_impl(
                     static_cast<std::uint32_t>(*id),
                     trim(arguments.substr(expression_start + 1)))
               : l10n::text(
                     l10n::Key::
                         EngineUsageScriptConditionBreakpointIdExpression);
      }
    } else if (command == "condition" || command == "ignore") {
      const std::size_t value_end = arguments.find_first_of(" \t");
      if (value_end == std::string_view::npos) {
        response = l10n::format(l10n::Key::EngineBreakpointModifyUsage,
                                command.c_str());
      } else {
        const std::string_view id = arguments.substr(0, value_end);
        const std::string_view value = trim(arguments.substr(value_end + 1));
        response = execute_lldb_command(
            std::string{"breakpoint modify "} +
            (command == "condition" ? "--condition " : "--ignore-count ") +
            std::string{value} + ' ' + std::string{id});
      }
    } else if (command == "tbreak" || command == "tb") {
      response = execute_lldb_command("breakpoint set --one-shot true --name " +
                                      std::string{arguments});
    } else if (command == "rbreak") {
      response = execute_lldb_command("breakpoint set --func-regex " +
                                      std::string{arguments});
    } else if (command == "hbreak" || command == "thbreak") {
      response = set_breakpoint_impl(arguments);
    } else if (command == "jump") {
      response = execute_lldb_command("thread jump --address " +
                                      std::string{arguments});
      synchronize_after_lldb_command();
    } else if (command == "signal") {
      response =
          execute_lldb_command("process signal " + std::string{arguments});
      synchronize_after_lldb_command();
    } else if (command == "display") {
      if (arguments.empty()) {
        response = l10n::text(l10n::Key::EngineUsageDisplayExpression);
      } else {
        watch_specs.push_back(WatchSpec{
            .execute = false,
            .expression = std::string{arguments},
        });
        refresh_watches();
        response = l10n::text(l10n::Key::EngineDisplayExpressionAdded);
      }
    } else if (command == "undisplay") {
      const auto index = parse_integer(arguments);
      if (!index || *index >= watch_specs.size()) {
        response = command_status.error_response(
            l10n::text(l10n::Key::EngineErrorDisplayIndexNotFound));
      } else {
        watch_specs.erase(watch_specs.begin() +
                          static_cast<std::ptrdiff_t>(*index));
        refresh_watches();
        response = l10n::text(l10n::Key::EngineDisplayExpressionRemoved);
      }
    } else if (command == "bp" || command == "b" || command == "break" ||
               command == "brk" || command == "bnew") {
      response = set_breakpoint_impl(arguments);
    } else if (command == "bl") {
      refresh_breakpoint_state();
      std::ostringstream listing;
      if (state.breakpoints.empty()) {
        listing << l10n::text(l10n::Key::EngineNoBreakpoints);
      }
      for (const BreakpointInfo &breakpoint : state.breakpoints) {
        listing << breakpoint.id << ' '
                << (breakpoint.enabled ? l10n::text(l10n::Key::EngineEnabled)
                                       : l10n::text(l10n::Key::EngineDisabled))
                << l10n::text(l10n::Key::EngineHits) << breakpoint.hit_count
                << ' ' << breakpoint.description << '\n';
      }
      response = listing.str();
    } else if (command == "bc" || command == "delete") {
      const auto id = parse_integer(arguments);
      response = id ? remove_breakpoint_impl(static_cast<std::uint32_t>(*id))
                    : l10n::text(l10n::Key::EngineUsageBcBreakpointId);
    } else if (command == "be" || command == "bd") {
      const auto id = parse_integer(arguments);
      response = id ? enable_breakpoint_impl(static_cast<std::uint32_t>(*id),
                                             command == "be")
                    : l10n::text(l10n::Key::EngineUsageBeBdBreakpointId);
    } else if (command == "dump" || command == "x") {
      std::string failure;
      const auto address = resolve_address(arguments, process, failure);
      response = address ? dump_memory_impl(*address)
                         : command_status.error_detail(failure);
    } else if (command == "r" || command == "reg" || command == "regs" ||
               command == "registers") {
      if (state.state != SessionState::Stopped || !process.IsValid()) {
        response = command_status.error_response(
            l10n::text(l10n::Key::EngineErrorRegistersRequireAStoppedProcess));
      } else if (arguments.empty()) {
        std::ostringstream registers;
        for (const RegisterValue &value : state.registers) {
          registers << value.name << " = " << value.value << '\n';
        }
        response = registers.str();
      } else {
        std::size_t value_separator = arguments.find('=');
        if (value_separator == std::string_view::npos) {
          value_separator = arguments.find_first_of(" \t");
        }
        std::string name{trim(arguments.substr(0, value_separator))};
        if (!name.empty() && name.front() == '$') {
          name.erase(0, 1);
        }
        const std::string_view new_value =
            value_separator == std::string_view::npos
                ? std::string_view{}
                : trim(arguments.substr(value_separator + 1));
        lldb::SBFrame frame = selected_frame(process);
        lldb::SBValue value = frame.IsValid() ? frame.FindRegister(name.c_str())
                                              : lldb::SBValue{};
        if (!value.IsValid()) {
          response = command_status.error_response(
              l10n::text(l10n::Key::EngineErrorRegisterNotFound));
        } else if (new_value.empty()) {
          response = name + " = " + safe_string(value.GetValue());
        } else {
          lldb::SBError write_error;
          const std::string value_text{new_value};
          if (!value.SetValueFromCString(value_text.c_str(), write_error)) {
            response = command_status.error_detail(error_text(write_error));
          } else {
            capture_stop(target, process, memory_view_address,
                         instruction_view_address, state);
            response = name + " = " +
                       safe_string(frame.FindRegister(name.c_str()).GetValue());
          }
        }
      }
    } else if (command == "syntax") {
      const std::string syntax = lowercase(arguments);
      if (syntax != "intel" && syntax != "att") {
        response = l10n::text(l10n::Key::EngineUsageSyntaxIntelAtt);
      } else if (target.IsValid() && !state.supports_intel_syntax) {
        response = command_status.error_response(l10n::text(
            l10n::Key::EngineErrorIntelATTSyntaxAppliesOnlyToX86Targets));
      } else {
        state.intel_syntax = syntax == "intel";
        if (state.state == SessionState::Stopped && process.IsValid()) {
          capture_stop(target, process, memory_view_address,
                       instruction_view_address, state);
        }
        response =
            l10n::format(l10n::Key::EngineDisassemblySyntax, syntax.c_str());
      }
    } else if (command == "process" &&
               (arguments == "connect" || arguments.starts_with("connect "))) {
      std::string endpoint{
          arguments.substr(std::string_view{"connect"}.size())};
      while (!endpoint.empty() &&
             std::isspace(static_cast<unsigned char>(endpoint.front())) != 0) {
        endpoint.erase(endpoint.begin());
      }
      if (endpoint.empty()) {
        response = command_status.error_response(
            l10n::text(l10n::Key::EngineErrorProcessConnectRequiresAnEndpoint));
      } else if (!target.IsValid()) {
        response = command_status.error_response(
            l10n::text(l10n::Key::EngineErrorProcessConnectRequiresATarget));
      } else {
        if (endpoint.find("://") == std::string::npos) {
          endpoint.insert(0, "connect://");
        }
        begin_generation();
        state.mode = SessionMode::Remote;
        state.state = SessionState::Connecting;
        state.error.clear();
        publish();
        lldb::SBError connect_error;
        connect_remote_process(endpoint, connect_error);
        if (shutdown_requested_.load()) {
          state.error = l10n::text(l10n::Key::EngineRemoteConnectionCancelled);
          response = command_status.error_detail(state.error);
        } else if (connect_error.Fail() || !process.IsValid()) {
          state.state = SessionState::Error;
          state.error = error_text(connect_error);
          response = command_status.error_detail(state.error);
        } else {
          synchronize_after_lldb_command(true);
          state.error.clear();
          response = l10n::text(l10n::Key::EngineConnected);
        }
      }
    } else if (const auto plugin_response =
                   plugins::PluginRegistry::instance().execute(
                       command, arguments, state, native_response_failed)) {
      response = *plugin_response;
      external_console_response = !native_response_failed;
    } else {
      const bool local_target =
          command == "target" &&
          (arguments == "create" || arguments.starts_with("create "));
      response = execute_lldb_command(text);
      synchronize_after_lldb_command(std::nullopt, local_target);
    }

    // Command watches and raw scripts may have changed the selected target.
    if (native_command_revision != synchronized_command_revision ||
        debugger.GetSelectedTarget() != target)
      synchronize_after_lldb_command();
    read_launch_intent();
    save_session();
    refresh_breakpoint_state();
    append_console(state, text, response);
    publish();
    return response;
  };

  state.state = SessionState::NoTarget;
  publish();

  auto read_frameless_register_result = [&](Command &command,
                                            std::string &failure) {
    const auto numeric = read_frameless_qemu_mips_register(
        target, state, command.argument, failure);
    if (!numeric) {
      state.error = std::move(failure);
    } else {
      std::ostringstream formatted;
      formatted << "0x" << std::hex << *numeric;
      command.result_value = formatted.str();
      command.result_numeric_value = *numeric;
      command.has_result_numeric_value = true;
      state.error.clear();
    }
  };

  auto complete_command = [&state](Command &command, bool success,
                                   std::string message) {
    if (!command.completion) {
      return;
    }
    command.completion->set_value(CommandResult{
        .id = command.id,
        .success = success,
        .message = std::move(message),
        .snapshot_revision = state.revision,
        .generation = state.generation,
        .stop_revision = state.stop_revision,
        .bytes = std::move(command.bytes),
        .value = std::move(command.result_value),
        .type = std::move(command.result_type),
        .summary = std::move(command.result_summary),
        .numeric_value = command.result_numeric_value,
        .has_numeric_value = command.has_result_numeric_value,
    });
  };

  bool shutdown = false;
  while (!shutdown) {
    std::deque<Command> pending;
    {
      const std::lock_guard lock{mutex_};
      pending.swap(commands_);
    }

    for (Command &command : pending) {
      if (shutdown_requested_.load() && command.kind != CommandKind::Shutdown) {
        complete_command(command, false,
                         l10n::text(l10n::Key::EngineEngineIsShuttingDown));
        continue;
      }
      state.error.clear();
      native_response_failed = false;
      external_console_response = false;
      std::string command_message;
      switch (command.kind) {
      case CommandKind::Load: {
        if (command.argument.empty()) {
          state.state = SessionState::Error;
          state.error = l10n::text(l10n::Key::EngineLoadRequiresAnExecutable);
          publish();
          break;
        }
        replace_target();
        state.mode = SessionMode::Local;
        state.target_path = std::move(command.argument);
        state.local_symbol_path = state.target_path;
        state.breakpoints.clear();
        lldb::SBError target_error;
        target = debugger.CreateTarget(state.target_path.c_str(), nullptr,
                                       nullptr, true, target_error);
        if (target_error.Fail() || !target.IsValid()) {
          state.state = SessionState::Error;
          state.error = error_text(target_error);
          publish();
          break;
        }
        state.state = SessionState::TargetLoaded;
        refresh_target_architecture();
        state.security = inspect_elf_security(state.local_symbol_path);
        capture_modules(target, state);
        open_target_session();
        publish();
        command_message = l10n::text(l10n::Key::EngineLoaded);
        break;
      }
      case CommandKind::Launch: {
        LaunchOptions options = std::move(command.launch_options);
        if (options.executable.empty()) {
          state.state = SessionState::Error;
          state.error = l10n::text(l10n::Key::EngineLaunchRequiresAnExecutable);
          publish();
          break;
        }
        replace_target();
        state.mode = SessionMode::Local;
        state.target_path = options.executable;
        state.local_symbol_path = options.executable;
        state.security = inspect_elf_security(state.local_symbol_path);
        state.target_triple.clear();
        state.architecture.clear();
        state.byte_order.clear();
        state.address_byte_size = 0;
        state.breakpoints.clear();
        state.error.clear();

        lldb::SBError target_error;
        target = debugger.CreateTarget(state.target_path.c_str(), nullptr,
                                       nullptr, true, target_error);
        if (target_error.Fail() || !target.IsValid()) {
          state.state = SessionState::Error;
          state.error = error_text(target_error);
          publish();
          break;
        }

        state.state = SessionState::TargetLoaded;
        refresh_target_architecture();
        open_target_session();
        if (command.enabled) {
          options.arguments = launch_arguments;
          options.working_directory = launch_working_directory;
        }
        launch_arguments = options.arguments;
        launch_working_directory = options.working_directory;
        apply_launch_intent();
        save_session();
        publish();

        if (options.stop_policy == LaunchStopPolicy::Main) {
          lldb::SBBreakpoint main_breakpoint =
              target.BreakpointCreateByName("main");
          if (!main_breakpoint.IsValid()) {
            state.state = SessionState::Error;
            state.error = l10n::text(
                l10n::Key::EngineFailedToCreateTheInitialBreakpointAtMain);
            publish();
            break;
          }
          main_breakpoint.SetOneShot(true);
          session.transient(main_breakpoint);
          refresh_breakpoint_state();
        }

        state.state = SessionState::Launching;
        publish();
        lldb::SBLaunchInfo launch_info(static_cast<const char **>(nullptr));
        launch_info.SetListener(listener);
        // target.input-path redirects the inferior's stdin; the setting is
        // cleared for launches that do not ask for it so later launches read
        // from the usual channel.
        debugger.HandleCommand(
            (std::string{"settings set target.input-path "} +
             (options.stdin_path.empty() ? std::string{"\"\""}
                                         : options.stdin_path))
                .c_str());
        std::vector<const char *> argument_pointers;
        argument_pointers.reserve(options.arguments.size() + 1);
        for (const std::string &argument : options.arguments) {
          argument_pointers.push_back(argument.c_str());
        }
        argument_pointers.push_back(nullptr);
        launch_info.SetArguments(argument_pointers.data(), false);
        if (!options.environment.empty()) {
          std::vector<const char *> environment_pointers;
          environment_pointers.reserve(options.environment.size() + 1);
          for (const std::string &entry : options.environment) {
            environment_pointers.push_back(entry.c_str());
          }
          environment_pointers.push_back(nullptr);
          launch_info.SetEnvironmentEntries(environment_pointers.data(), true);
        }
        if (!options.working_directory.empty()) {
          launch_info.SetWorkingDirectory(options.working_directory.c_str());
        }
        if (options.stop_policy == LaunchStopPolicy::Entry) {
          launch_info.SetLaunchFlags(launch_info.GetLaunchFlags() |
                                     lldb::eLaunchFlagStopAtEntry);
        }
        lldb::SBError launch_error;
        adopt_process(target.Launch(launch_info, launch_error), false);
        if (launch_error.Fail() || !process.IsValid()) {
          state.state = SessionState::Error;
          state.error = error_text(launch_error);
          publish();
          break;
        }
        const lldb::StateType process_state = process.GetState();
        if (is_inspectable_stop(process_state) &&
            process.GetNumThreads() != 0) {
          instruction_view_address.reset();
          capture_stop(target, process, memory_view_address,
                       instruction_view_address, state);
          refresh_breakpoint_state();
        } else {
          state.state = SessionState::Running;
          state.crash = {};
        }
        publish();
        command_message = l10n::text(l10n::Key::EngineLaunched);
        break;
      }
      case CommandKind::Attach: {
        if (command.value == 0) {
          state.error =
              l10n::text(l10n::Key::EngineAttachRequiresANonZeroProcessID);
          publish();
          break;
        }
        replace_target();
        state.mode = SessionMode::Local;
        state.target_path.clear();
        state.local_symbol_path.clear();
        state.breakpoints.clear();
        lldb::SBError target_error;
        target = debugger.CreateTarget(nullptr, nullptr, nullptr, true,
                                       target_error);
        if (target_error.Fail() || !target.IsValid()) {
          state.state = SessionState::Error;
          state.error = error_text(target_error);
          publish();
          break;
        }
        lldb::SBError attach_error;
        adopt_process(target.AttachToProcessWithID(
                          listener, static_cast<lldb::pid_t>(command.value),
                          attach_error),
                      false);
        if (attach_error.Fail() || !process.IsValid()) {
          state.state = SessionState::Error;
          state.error = error_text(attach_error);
          publish();
          break;
        }
        synchronize_after_lldb_command();
        publish();
        command_message = l10n::text(l10n::Key::EngineAttached);
        break;
      }
      case CommandKind::ConnectRemote: {
        RemoteOptions options = std::move(command.remote_options);
        if (options.endpoint.empty() && options.qemu_executable.empty()) {
          state.error =
              l10n::text(l10n::Key::EngineRemoteConnectionRequiresAnEndpoint);
          publish();
          break;
        }
        if (options.mode != SessionMode::Remote &&
            options.mode != SessionMode::QemuUser &&
            options.mode != SessionMode::QemuSystem) {
          state.error = l10n::text(
              l10n::Key::EngineRemoteConnectionRequiresARemoteSessionMode);
          publish();
          break;
        }
        replace_target();
        state.mode = options.mode;
        state.target_path = options.executable;
        state.local_symbol_path = options.executable;
        state.security = state.local_symbol_path.empty()
                             ? ElfSecurityInfo{}
                             : inspect_elf_security(state.local_symbol_path);
        state.target_triple.clear();
        state.architecture.clear();
        state.byte_order.clear();
        state.address_byte_size = 0;
        state.breakpoints.clear();
        state.error.clear();

        lldb::SBError target_error;
        target = debugger.CreateTarget(
            state.target_path.empty() ? nullptr : state.target_path.c_str(),
            nullptr, nullptr, true, target_error);
        if (target_error.Fail() || !target.IsValid()) {
          state.state = SessionState::Error;
          state.error = error_text(target_error);
          publish();
          break;
        }
        open_target_session();

        std::string endpoint = std::move(options.endpoint);
        if (options.qemu_executable.empty() &&
            endpoint.find("://") == std::string::npos) {
          endpoint.insert(0, "connect://");
        }
        if (!options.qemu_executable.empty() &&
            !qemu.start(options, endpoint, state.error)) {
          state.state = SessionState::Error;
          publish();
          break;
        }
        state.state = SessionState::Connecting;
        publish();
        lldb::SBError connect_error;
        connect_remote_process(endpoint, connect_error);
        if (shutdown_requested_.load()) {
          qemu.stop();
          state.error = l10n::text(l10n::Key::EngineRemoteConnectionCancelled);
          break;
        }
        if (connect_error.Fail() || !process.IsValid()) {
          qemu.stop();
          state.state = SessionState::Error;
          state.error = error_text(connect_error);
          publish();
          break;
        }
        synchronize_after_lldb_command();
        publish();
        command_message = l10n::text(l10n::Key::EngineConnected);
        break;
      }
      case CommandKind::Detach: {
        if (!process.IsValid() || state.state == SessionState::Exited) {
          state.error = l10n::text(l10n::Key::EngineNoLiveProcessToDetach);
          publish();
          break;
        }
        const lldb::SBError detach_error = process.Detach();
        if (detach_error.Fail()) {
          state.error = error_text(detach_error);
          publish();
          break;
        }
        qemu.stop();
        adopt_process(lldb::SBProcess{});
        state.state = target.IsValid() ? SessionState::TargetLoaded
                                       : SessionState::NoTarget;
        state.process_id = 0;
        state.thread_id = 0;
        state.stop_reason.clear();
        state.error.clear();
        publish();
        command_message = l10n::text(l10n::Key::EngineDetached);
        break;
      }
      case CommandKind::Continue:
        continue_process(target, process, state, native_response_failed);
        publish();
        break;
      case CommandKind::Stop:
        pause_process(process, state, native_response_failed);
        publish();
        break;
      case CommandKind::StepInstruction:
        step_instruction_impl(command.enabled);
        publish();
        break;
      case CommandKind::RunToAddress:
        lldb_detail::run_to_address(command.value, process, state,
                                    native_response_failed);
        publish();
        break;
      case CommandKind::Terminate:
        terminate_process(process, state, native_response_failed);
        qemu.stop();
        publish();
        break;
      case CommandKind::SetConditionalBreakpoint:
        set_breakpoint_impl(command.argument, command.argument2);
        publish();
        break;
      case CommandKind::SetBreakpoint:
        set_breakpoint_impl(command.argument);
        publish();
        break;
      case CommandKind::RemoveBreakpoint:
        remove_breakpoint_impl(static_cast<std::uint32_t>(command.value));
        publish();
        break;
      case CommandKind::EnableBreakpoint:
        enable_breakpoint_impl(static_cast<std::uint32_t>(command.value),
                               command.enabled);
        publish();
        break;
      case CommandKind::SetBreakpointScript:
        set_breakpoint_script_impl(static_cast<std::uint32_t>(command.value),
                                   command.argument);
        publish();
        break;
      case CommandKind::ClearSavedSession:
        try {
          if (!target.IsValid() || (state.state != SessionState::TargetLoaded &&
                                    state.state != SessionState::Stopped &&
                                    state.state != SessionState::Exited))
            throw std::runtime_error(
                l10n::text(l10n::Key::LldbSessionClearWhileRunning));
          session.clear(command.argument, state);
          for (std::uint32_t i = target.GetNumBreakpoints(); i > 0; --i) {
            auto breakpoint = target.GetBreakpointAtIndex(i - 1);
            if (!breakpoint.IsInternal()) {
              session.transient(breakpoint);
              if (!target.BreakpointDelete(breakpoint.GetID()))
                state.error =
                    l10n::text(l10n::Key::LldbSessionClearNativeFailed);
            }
          }
          script_conditions.clear();
          watch_specs.clear();
          state.watches.clear();
          persistent_symbols.clear();
          custom_symbols.clear();
          launch_arguments.clear();
          launch_working_directory.clear();
          apply_launch_intent();
          refresh_breakpoint_state();
        } catch (const std::exception &error) {
          state.error = error.what();
        }
        publish();
        break;
      case CommandKind::SetComment:
        try {
          if (command.value2 != state.generation ||
              command.expected_session != state.session ||
              state.state != SessionState::Stopped || !target.IsValid())
            throw std::runtime_error(
                l10n::text(l10n::Key::LldbSessionStaleAddress));
          session.comment(target, command.value, command.argument, state);
        } catch (const std::exception &error) {
          state.error = error.what();
        }
        publish();
        break;
      case CommandKind::SelectThread: {
        lldb::SBThread thread = process.GetThreadByID(command.value);
        if (state.state != SessionState::Stopped || !thread.IsValid() ||
            !process.SetSelectedThread(thread)) {
          state.error = l10n::text(l10n::Key::EngineUnableToSelectThread);
        } else {
          thread.SetSelectedFrame(0);
          instruction_view_address.reset();
          capture_stop(target, process, memory_view_address,
                       instruction_view_address, state);
          state.error.clear();
          plugins::PluginRegistry::instance().dispatch(
              plugins::Event::ThreadSelected, state);
        }
        publish();
        break;
      }
      case CommandKind::SelectFrame: {
        lldb::SBThread thread = process.GetThreadByID(command.value);
        const bool synthetic_frameless_frame =
            state.state == SessionState::Stopped &&
            command.value == state.thread_id && command.value2 == 0 &&
            is_frameless_qemu_mips_stop(process, state);
        lldb::SBFrame frame =
            thread.IsValid() && !synthetic_frameless_frame
                ? thread.SetSelectedFrame(
                      static_cast<std::uint32_t>(command.value2))
                : lldb::SBFrame{};
        if (synthetic_frameless_frame) {
          state.error.clear();
          plugins::PluginRegistry::instance().dispatch(
              plugins::Event::FrameSelected, state);
        } else if (state.state != SessionState::Stopped || !thread.IsValid() ||
                   !frame.IsValid() || !process.SetSelectedThread(thread)) {
          state.error = l10n::text(l10n::Key::EngineUnableToSelectStackFrame);
        } else {
          instruction_view_address.reset();
          capture_stop(target, process, memory_view_address,
                       instruction_view_address, state);
          state.error.clear();
          plugins::PluginRegistry::instance().dispatch(
              plugins::Event::FrameSelected, state);
        }
        publish();
        break;
      }
      case CommandKind::ReadMemory:
        dump_memory_impl(command.value);
        publish();
        break;
      case CommandKind::ReadMemoryBytes: {
        constexpr std::uint64_t maximum_read_size = 16U * 1024U * 1024U;
        if (state.state != SessionState::Stopped || !process.IsValid()) {
          state.error = l10n::text(
              l10n::Key::EngineMemoryCanOnlyBeReadWhileTheProcessIsStopped);
        } else if (command.value2 == 0 || command.value2 > maximum_read_size) {
          state.error = l10n::text(
              l10n::Key::EngineMemoryReadSizeMustBeBetween1And16777216Bytes);
        } else {
          std::string failure;
          auto bytes = read_memory_bytes(
              process, command.value, static_cast<std::size_t>(command.value2),
              failure);
          if (!bytes) {
            state.error = std::move(failure);
          } else {
            command.bytes = std::move(*bytes);
            state.error.clear();
          }
        }
        publish();
        break;
      }
      case CommandKind::WriteMemoryBytes: {
        constexpr std::size_t maximum_write_size = 16U * 1024U * 1024U;
        if (command.bytes.empty() ||
            command.bytes.size() > maximum_write_size) {
          command_message = command_status.error_response(l10n::text(
              l10n::Key::
                  EngineErrorMemoryWriteSizeMustBeBetween1And16777216Bytes));
        } else {
          command_message = patch_commands.apply_patch(
              command.value, command.bytes, target, process, state,
              native_response_failed);
        }
        publish();
        break;
      }
      case CommandKind::EvaluateExpression: {
        lldb::SBFrame frame = selected_frame(process);
        if (state.state != SessionState::Stopped) {
          state.error = l10n::text(
              l10n::Key::EngineExpressionEvaluationRequiresAStoppedFrame);
        } else if (frame.IsValid()) {
          lldb::SBValue value;
          const std::string_view expression = trim(command.argument);
          if (expression.size() > 1 && expression.front() == '$') {
            const std::string_view name = expression.substr(1);
            const bool bare_register =
                (std::isalpha(static_cast<unsigned char>(name.front())) ||
                 name.front() == '_') &&
                std::all_of(name.begin(), name.end(), [](unsigned char c) {
                  return std::isalnum(c) || c == '_';
                });
            if (bare_register) {
              // Read register references without importing their bytes into
              // LLDB's expression evaluator, which can use the host byte order.
              const std::string register_name{name};
              value = frame.FindRegister(register_name.c_str());
            }
          }
          if (!value.IsValid()) {
            value = frame.EvaluateExpression(command.argument.c_str());
          }
          const lldb::SBError expression_error = value.GetError();
          if (expression_error.Fail() || !value.IsValid()) {
            state.error = error_text(expression_error);
          } else {
            command.result_value = safe_string(value.GetValue());
            command.result_type = safe_string(value.GetTypeName());
            command.result_summary = safe_string(value.GetSummary());
            if (const auto numeric = register_value_as_unsigned(value)) {
              command.result_numeric_value = *numeric;
              command.has_result_numeric_value = true;
            }
            state.error.clear();
          }
        } else if (is_frameless_qemu_mips_stop(process, state) &&
                   trim(command.argument).starts_with('$')) {
          std::string failure;
          read_frameless_register_result(command, failure);
        } else {
          state.error = l10n::text(
              l10n::Key::EngineExpressionEvaluationRequiresAStoppedFrame);
        }
        publish();
        break;
      }
      case CommandKind::ReadRegister: {
        if (!command.argument.empty() && command.argument.front() == '$') {
          command.argument.erase(0, 1);
        }
        lldb::SBFrame frame = selected_frame(process);
        if (state.state != SessionState::Stopped) {
          state.error = l10n::text(
              l10n::Key::EngineRegisterNotFoundInTheSelectedStoppedFrame);
        } else if (frame.IsValid()) {
          lldb::SBValue value = frame.FindRegister(command.argument.c_str());
          if (!value.IsValid()) {
            state.error = l10n::text(
                l10n::Key::EngineRegisterNotFoundInTheSelectedStoppedFrame);
          } else {
            command.result_value = register_value_text(value);
            if (const auto numeric = register_value_as_unsigned(value)) {
              command.result_numeric_value = *numeric;
              command.has_result_numeric_value = true;
            }
            state.error.clear();
          }
        } else if (is_frameless_qemu_mips_stop(process, state)) {
          std::string failure;
          read_frameless_register_result(command, failure);
        } else {
          state.error = l10n::text(
              l10n::Key::EngineRegisterNotFoundInTheSelectedStoppedFrame);
        }
        publish();
        break;
      }
      case CommandKind::WriteRegister: {
        if (!command.argument.empty() && command.argument.front() == '$') {
          command.argument.erase(0, 1);
        }
        lldb::SBFrame frame = selected_frame(process);
        if (state.state != SessionState::Stopped) {
          state.error = l10n::text(
              l10n::Key::EngineRegisterNotFoundInTheSelectedStoppedFrame);
        } else if (frame.IsValid()) {
          lldb::SBValue value = frame.FindRegister(command.argument.c_str());
          if (!value.IsValid()) {
            state.error = l10n::text(
                l10n::Key::EngineRegisterNotFoundInTheSelectedStoppedFrame);
          } else {
            const std::string &formatted_value = command.argument2;
            lldb::SBError write_error;
            if (!value.SetValueFromCString(formatted_value.c_str(),
                                           write_error)) {
              state.error = error_text(write_error);
            } else {
              bool pc_refreshed = true;
              // Register writes can leave LLDB's cached frame PC unchanged.
              // SetPC invalidates that cache, including writes through aliases.
              if (const auto pc =
                      register_value_as_unsigned(frame.FindRegister("pc"));
                  pc && *pc != frame.GetPC()) {
                pc_refreshed = frame.SetPC(*pc);
              }
              capture_stop(target, process, memory_view_address,
                           instruction_view_address, state);
              lldb::SBValue updated =
                  frame.FindRegister(command.argument.c_str());
              command.result_value = register_value_text(updated);
              if (const auto numeric = register_value_as_unsigned(updated)) {
                command.result_numeric_value = *numeric;
                command.has_result_numeric_value = true;
              }
              state.error =
                  pc_refreshed
                      ? ""
                      : l10n::text(
                            l10n::Key::
                                EngineRegisterWrittenButFramePCRefreshFailed);
            }
          }
        } else if (is_frameless_qemu_mips_stop(process, state)) {
          std::string failure;
          const auto requested_value = parse_integer(command.argument2);
          if (!requested_value) {
            state.error =
                l10n::text(l10n::Key::EngineExpectedAnIntegerRegisterValue);
          } else if (!write_frameless_qemu_mips_register(
                         target, state, command.argument, *requested_value,
                         failure)) {
            state.error = std::move(failure);
          } else {
            capture_stop(target, process, memory_view_address,
                         instruction_view_address, state);
            read_frameless_register_result(command, failure);
          }
        } else {
          state.error = l10n::text(
              l10n::Key::EngineRegisterNotFoundInTheSelectedStoppedFrame);
        }
        publish();
        break;
      }
      case CommandKind::SendStdin: {
        if (qemu.owns_stdin()) {
          qemu.send_stdin(command.argument, state.error);
          if (state.error.empty()) {
            command_message = l10n::format(l10n::Key::EngineSentInputBytes,
                                           command.argument.size());
          }
          publish();
          break;
        }
        if (!process.IsValid() || state.state == SessionState::Exited) {
          state.error = l10n::text(l10n::Key::EngineNoLiveProcessAcceptsStdin);
        } else {
          process.PutSTDIN(command.argument.data(), command.argument.size());
          state.error.clear();
          command_message = l10n::format(l10n::Key::EngineSentInputBytes,
                                         command.argument.size());
        }
        publish();
        break;
      }
      case CommandKind::ReadInstructions:
        read_instructions_impl(command.value);
        publish();
        break;
      case CommandKind::ExecuteConsole:
        command_message = execute_prompt(command.argument);
        break;
      case CommandKind::SetDisassemblyStyle:
        state.intel_syntax = command.enabled;
        if (state.state == SessionState::Stopped && process.IsValid()) {
          capture_stop(target, process, memory_view_address,
                       instruction_view_address, state);
          refresh_breakpoint_state();
        }
        publish();
        break;
      case CommandKind::SetDisassemblyGraphEnabled:
        disassembly_graph_enabled = command.enabled;
        state.error.clear();
        publish();
        break;
      case CommandKind::ScanBinaryStrings:
        scan_binary_strings_impl(static_cast<std::size_t>(command.value),
                                 command.enabled);
        publish();
        break;
      case CommandKind::StartValueScan:
        start_value_scan_impl(static_cast<ValueScanType>(command.value),
                              command.argument, (command.value2 & 1U) != 0,
                              (command.value2 & 2U) != 0, command.enabled);
        publish();
        break;
      case CommandKind::NextValueScan:
        next_value_scan_impl(static_cast<ValueScanComparison>(command.value),
                             command.argument);
        publish();
        break;
      case CommandKind::ResetValueScan:
        reset_value_scan_state();
        publish();
        break;
      case CommandKind::Shutdown:
        shutdown = true;
        break;
      }
      if (command.kind == CommandKind::SetBreakpoint ||
          command.kind == CommandKind::SetConditionalBreakpoint ||
          command.kind == CommandKind::RemoveBreakpoint ||
          command.kind == CommandKind::EnableBreakpoint ||
          command.kind == CommandKind::SetBreakpointScript) {
        save_session();
        publish();
      }
      if (command.kind != CommandKind::Shutdown) {
        // Only external command output retains the legacy error-prefix
        // protocol.
        const bool response_failed =
            native_response_failed || (external_console_response &&
                                       command_message.starts_with("error:"));
        const bool success = !response_failed &&
                             (!command_message.empty() || state.error.empty());
        if (command_message.empty()) {
          command_message =
              success ? std::string{session_state_display(state.state)}
                      : state.error;
        }
        complete_command(command, success, std::move(command_message));
      }
    }

    lldb::SBEvent event;
    while (listener.GetNextEvent(event)) {
      if (!lldb::SBProcess::EventIsProcessEvent(event)) {
        if (lldb::SBBreakpoint::EventIsBreakpointEvent(event)) {
          auto breakpoint = lldb::SBBreakpoint::GetBreakpointFromEvent(event);
          if (breakpoint.IsValid() && breakpoint.GetTarget() == target) {
            // Events are drained after commands, never during temporary step
            // disabling. Observe the settled native state, not the event delta.
            if (lldb::SBBreakpoint::GetBreakpointEventTypeFromEvent(event) &
                lldb::eBreakpointEventTypeIgnoreChanged)
              session.ignore_count_changed(breakpoint);
            refresh_breakpoint_state();
            save_session();
            publish();
          }
        } else if (lldb::SBTarget::EventIsTargetEvent(event) &&
                   lldb::SBTarget::GetTargetFromEvent(event) == target) {
          restore_pending_session();
          publish();
        }
        continue;
      }
      lldb::SBProcess event_process =
          lldb::SBProcess::GetProcessFromEvent(event);
      if (!event_process.IsValid() || !process.IsValid() ||
          active_process_generation != state.generation ||
          active_process_id == 0 ||
          event_process.GetUniqueID() != active_process_id ||
          !target.IsValid() || event_process.GetTarget() != target) {
        continue;
      }
      const lldb::StateType event_state =
          lldb::SBProcess::GetStateFromEvent(event);
      append_process_output(process, state);

      if (event_state == lldb::eStateStopped && process.GetNumThreads() == 0) {
        state.state = SessionState::Running;
        state.crash = {};
        state.error.clear();
        publish();
        continue;
      }
      if (is_inspectable_stop(event_state)) {
        if (scripted_breakpoint_should_continue()) {
          refresh_breakpoint_state();
          lldb::SBError continue_error = process.Continue();
          if (continue_error.Fail()) {
            state.state = SessionState::Stopped;
            state.error = error_text(continue_error);
          } else {
            state.state = SessionState::Running;
            state.crash = {};
            state.error.clear();
            append_console(
                state, l10n::text(l10n::Key::EngineBreakpointCondition),
                l10n::text(l10n::Key::EngineConditionWasFalseContinuing));
          }
        } else {
          const std::uint64_t previous_stop_revision = state.stop_revision;
          instruction_view_address.reset();
          capture_stop(target, process, memory_view_address,
                       instruction_view_address, state);
          if (is_frameless_qemu_mips_stop(process, state) &&
              state.stop_revision <= previous_stop_revision) {
            state.stop_revision = previous_stop_revision + 1;
            record_stop_history(state);
          }
          refresh_breakpoint_state();
        }
      } else if (event_state == lldb::eStateRunning ||
                 event_state == lldb::eStateStepping) {
        state.state = SessionState::Running;
        state.crash = {};
        state.error.clear();
      } else if (event_state == lldb::eStateExited) {
        state.state = SessionState::Exited;
        state.exit_status = process.GetExitStatus();
        state.stop_reason = safe_string(process.GetExitDescription());
        state.error.clear();
        qemu.drain_output();
      }
      publish();
    }

    if (append_process_output(process, state)) {
      publish();
    }
    qemu.drain_output();
    publish();

    std::unique_lock lock{mutex_};
    wake_.wait_for(lock, 10ms, [this] { return !commands_.empty(); });
  }

  save_session();
  qemu.stop();
  state.state = SessionState::ShuttingDown;
  publish();
  if (process.IsValid() && should_destroy(process.GetState())) {
    process.Destroy();
  }
  if (target.IsValid()) {
    debugger.DeleteTarget(target);
  }
  {
    const std::lock_guard lock{worker_control_->mutex};
    worker_control_->remote_connection_active = false;
    worker_control_->debugger = lldb::SBDebugger{};
  }
  lldb::SBDebugger::Destroy(debugger);
}

} // namespace debugger
