#include "backend/lldb/LldbEngineInternal.h"
#include "backend/lldb/LldbSessions.h"
#include "localization/Localization.h"

namespace debugger {

using namespace lldb_detail;
using namespace std::chrono_literals;

namespace {

struct LldbRuntime {
  LldbRuntime()
      : initialization_error{
            lldb::SBDebugger::InitializeWithErrorHandling()} {}

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
  std::uint32_t next_patch_id = 1;
  struct ScriptConditionState {
    std::string source;
    conditions::CompiledCondition compiled;
    std::string last_error;
  };
  std::unordered_map<std::uint32_t, ScriptConditionState> script_conditions;
  std::unordered_map<std::uint32_t, std::uint32_t>
      frameless_breakpoint_hits;
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
        state.watches.push_back(WatchInfo{.expression = std::move(expression)});
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
    state.process_is_remote =
        remote_hint.value_or(process_is_remote(process));
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
      connected = target.ConnectRemote(listener, endpoint.c_str(),
                                       "gdb-remote", error);
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
  auto error_response = [&](const char *message) {
    native_response_failed = true;
    return message;
  };
  auto error_detail = [&](const std::string &message) {
    native_response_failed = true;
    return l10n::format(l10n::Key::EngineErrorDetail, message.c_str());
  };

  auto set_breakpoint_impl = [&](std::string_view specification,
                                 std::string_view script = {}) {
    specification = trim(specification);
    if (!target.IsValid()) {
      state.error = l10n::text(l10n::Key::EngineNoTargetIsLoaded);
      return std::string{
          error_response(l10n::text(l10n::Key::EngineErrorNoTargetIsLoaded))};
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
        return error_detail(state.error);
      }
      compiled_script = std::move(compiled.condition);
    }

    std::optional<lldb::addr_t> address = parse_integer(specification);
    if (!address && specification.starts_with("*")) {
      std::string failure;
      address = resolve_address(specification.substr(1), process, failure);
      if (!address) {
        state.error = failure;
        return error_detail(failure);
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
    }
    if (!breakpoint.IsValid()) {
      state.error = l10n::text(l10n::Key::EngineLLDBRejectedTheBreakpoint);
      return std::string{error_response(
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
      return error_detail(state.error);
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
      return error_detail(state.error);
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
      return error_detail(state.error);
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
      return error_detail(state.error);
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

  auto step_frameless_mips = [&](std::string &failure) {
    std::vector<lldb::SBBreakpoint> disabled;
    for (const BreakpointInfo &breakpoint : state.breakpoints) {
      if (!breakpoint.enabled ||
          std::ranges::find(breakpoint.addresses, state.pc) ==
              breakpoint.addresses.end()) {
        continue;
      }
      lldb::SBBreakpoint native = target.FindBreakpointByID(breakpoint.id);
      if (native.IsValid()) {
        native.SetEnabled(false);
        disabled.push_back(native);
      }
    }

    const bool stepped = step_frameless_qemu_mips(target, failure);
    for (lldb::SBBreakpoint &breakpoint : disabled) {
      breakpoint.SetEnabled(true);
    }
    return stepped;
  };

  auto continue_impl = [&] {
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      state.error = l10n::text(
          l10n::Key::EngineContinueIsOnlyValidWhileTheProcessIsStopped);
      return error_detail(state.error);
    }

    if (is_frameless_qemu_mips_stop(process, state)) {
      const bool at_breakpoint =
          std::ranges::any_of(state.breakpoints,
                              [&state](const BreakpointInfo &breakpoint) {
                                return breakpoint.enabled &&
                                       std::ranges::find(
                                           breakpoint.addresses, state.pc) !=
                                           breakpoint.addresses.end();
                              });
      if (at_breakpoint) {
        std::string failure;
        if (!step_frameless_mips(failure)) {
          state.error = std::move(failure);
          return error_detail(state.error);
        }
      }
    }

    lldb::SBError continue_error = process.Continue();
    if (continue_error.Fail()) {
      state.error = error_text(continue_error);
      return error_detail(state.error);
    }
    state.state = SessionState::Running;
    state.crash = {};
    state.error.clear();
    return std::string{l10n::text(l10n::Key::EngineRunning)};
  };

  auto stop_impl = [&] {
    if (state.state != SessionState::Running || !process.IsValid()) {
      state.error =
          l10n::text(l10n::Key::EnginePauseIsOnlyValidWhileTheProcessIsRunning);
      return error_detail(state.error);
    }
    lldb::SBError stop_error = process.Stop();
    if (stop_error.Fail()) {
      state.error = error_text(stop_error);
      return error_detail(state.error);
    }
    state.error.clear();
    return std::string{l10n::text(l10n::Key::EnginePauseRequested)};
  };

  auto step_instruction_impl = [&](bool step_over) {
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      state.error =
          l10n::text(l10n::Key::EngineSteppingRequiresAStoppedProcess);
      return error_detail(state.error);
    }
    if (is_frameless_qemu_mips_stop(process, state)) {
      if (step_over) {
        state.error = l10n::text(
            l10n::Key::
                EngineInstructionStepOverIsUnavailableForThisRemoteTarget);
        return error_detail(state.error);
      }
      const std::uint64_t previous_pc = state.pc;
      const std::uint64_t previous_stop_revision = state.stop_revision;
      std::string failure;
      if (!step_frameless_mips(failure)) {
        state.error = std::move(failure);
        return error_detail(state.error);
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
      return error_detail(state.error);
    }
    lldb::SBError step_error;
    thread.StepInstruction(step_over, step_error);
    if (step_error.Fail()) {
      state.error = error_text(step_error);
      return error_detail(state.error);
    }
    state.state = SessionState::Running;
    state.crash = {};
    state.error.clear();
    return step_over ? std::string{l10n::text(l10n::Key::EngineSteppingOver)}
                     : std::string{l10n::text(l10n::Key::EngineSteppingInto)};
  };

  auto run_to_address_impl = [&](lldb::addr_t address) {
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      state.error =
          l10n::text(l10n::Key::EngineRunToCursorRequiresAStoppedProcess);
      return error_detail(state.error);
    }
    lldb::SBThread thread = process.GetSelectedThread();
    if (!thread.IsValid()) {
      state.error = l10n::text(l10n::Key::EngineNoSelectedThread);
      return error_detail(state.error);
    }
    lldb::SBError run_error;
    thread.RunToAddress(address, run_error);
    if (run_error.Fail()) {
      state.error = error_text(run_error);
      return error_detail(state.error);
    }
    state.state = SessionState::Running;
    state.crash = {};
    state.error.clear();
    return l10n::format(l10n::Key::EngineRunningToAddress,
                        static_cast<std::uint64_t>(address));
  };

  auto terminate_impl = [&] {
    if (!process.IsValid() || state.state == SessionState::Exited) {
      state.error = l10n::text(l10n::Key::EngineNoLiveProcessToTerminate);
      return error_detail(state.error);
    }
    lldb::SBError kill_error = process.Kill();
    if (kill_error.Fail()) {
      state.error = error_text(kill_error);
      return error_detail(state.error);
    }
    state.error.clear();
    return std::string{l10n::text(l10n::Key::EngineProcessTerminated)};
  };

  auto dump_memory_impl = [&](lldb::addr_t address) {
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      state.error = l10n::text(
          l10n::Key::EngineMemoryCanOnlyBeReadWhileTheProcessIsStopped);
      return error_detail(state.error);
    }
    memory_view_address = address;
    capture_memory(process, address, state);
    if (!state.error.empty()) {
      return error_detail(state.error);
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

  auto synchronize_after_lldb_command =
      [&](std::optional<bool> remote_hint = std::nullopt,
          bool local_target_hint = false) {
        synchronized_command_revision = native_command_revision;
        lldb::SBTarget selected_target = debugger.GetSelectedTarget();
        lldb::SBProcess selected_process =
            selected_target.IsValid() ? selected_target.GetProcess()
                                      : lldb::SBProcess{};
        const bool target_changed =
            selected_target.IsValid() != target.IsValid() ||
            (selected_target.IsValid() && selected_target != target);
        const bool process_changed =
            selected_process.IsValid() &&
            (target_changed ||
             active_process_generation != state.generation ||
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
          adopt_process(
              selected_process,
              process_changed ? remote_hint
                              : std::optional<bool>{state.process_is_remote});
        } else if (target_changed || !target.IsValid()) {
          adopt_process(lldb::SBProcess{});
        }

        if (target.IsValid()) {
          std::array<char, 4096> path{};
          target.GetExecutable().GetPath(path.data(), path.size());
          const std::string selected_path = safe_string(path.data());
          if (!selected_path.empty()) {
            state.target_path = selected_path;
            if (local_target_hint ||
                (!state.process_is_remote &&
                 state.local_symbol_path.empty() && process.IsValid())) {
              state.local_symbol_path = selected_path;
            }
          }
          state.security =
              state.local_symbol_path.empty()
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
    const std::vector<std::string> sections =
        requested_section.empty()
            ? context_sections
            : std::vector<std::string>{lowercase(trim(requested_section))};
    const auto enabled = [&sections](std::string_view section) {
      return std::find(sections.begin(), sections.end(), section) !=
             sections.end();
    };
    const auto write_pointer_chain =
        [](std::ostringstream &stream,
           const std::vector<PointerChainEntry> &chain) {
          for (const PointerChainEntry &entry : chain) {
            stream << " -> ";
            if (!entry.error.empty()) {
              stream << '<' << entry.error << '>';
              break;
            }
            stream << "0x" << std::hex << entry.value;
            if (!entry.symbol.empty()) {
              stream << " (" << entry.symbol << ')';
            } else if (!entry.mapping.empty()) {
              stream << " (" << entry.mapping << ')';
            }
          }
        };

    std::ostringstream output;
    if (enabled("regs")) {
      output << l10n::text(l10n::Key::EngineRegisters);
      for (const RegisterValue &value : state.registers) {
        output << value.name << '=' << value.value;
        if (value.changed) {
          output << l10n::format(l10n::Key::EnginePreviousRegisterValue,
                                 value.previous_value.c_str());
        }
        write_pointer_chain(output, value.pointer_chain);
        output << '\n';
      }
      output << '\n';
    }
    if (enabled("disasm")) {
      output << l10n::text(l10n::Key::EngineDisassembly);
      for (const InstructionRow &instruction : state.instructions) {
        if (instruction.address + 64 < state.pc ||
            instruction.address > state.pc + 64) {
          continue;
        }
        output << (instruction.address == state.pc ? "=> " : "   ") << "0x"
               << std::hex << instruction.address << ' ' << instruction.mnemonic
               << ' ' << instruction.operands << '\n';
      }
    }
    if (enabled("insight") || enabled("operands") || enabled("args")) {
      output << l10n::text(l10n::Key::EngineInstructionInsight);
      const auto current =
          std::find_if(state.instructions.begin(), state.instructions.end(),
                       [&state](const InstructionRow &instruction) {
                         return instruction.address == state.pc;
                       });
      if (current == state.instructions.end()) {
        output << l10n::text(
            l10n::Key::EngineUnavailableCurrentInstructionWasNotCaptured);
      } else {
        for (const ResolvedOperandInfo &operand : current->resolved_operands) {
          output << operand_role_display(operand.role) << ' '
                 << operand.expression;
          if (!operand.error.empty()) {
            output << " = <" << operand.error << ">\n";
            continue;
          }
          if (operand.has_value) {
            output << " = 0x" << std::hex << operand.value;
            write_pointer_chain(output, operand.pointer_chain);
          }
          output << '\n';
        }
        if (current->branch.conditional) {
          output << l10n::text(l10n::Key::EngineBranch);
          if (current->branch.available) {
            output << (current->branch.taken
                           ? l10n::text(l10n::Key::EngineTAKEN)
                           : l10n::text(l10n::Key::EngineNOTTAKEN));
          } else {
            output << l10n::text(l10n::Key::EngineUNKNOWN);
          }
          output << " (" << current->branch.explanation << ") -> 0x" << std::hex
                 << (current->branch.taken ? current->branch.taken_target
                                           : current->branch.fallthrough_target)
                 << '\n';
        }
        if (!current->arguments.empty()) {
          output << (current->flow_kind == InstructionFlowKind::Syscall
                         ? l10n::text(l10n::Key::EngineSyscallArguments)
                         : l10n::text(l10n::Key::EngineCallArguments));
          for (const AbiArgumentInfo &argument : current->arguments) {
            output << "  " << argument.name << " = ";
            if (!argument.error.empty()) {
              output << '<' << argument.error << '>';
            } else {
              output << "0x" << std::hex << argument.value;
              write_pointer_chain(output, argument.pointer_chain);
            }
            output << '\n';
          }
        }
      }
    }
    if (enabled("stack")) {
      output << l10n::text(l10n::Key::EngineStack);
      for (const StackEntry &entry : state.stack) {
        output << "0x" << std::hex << entry.address << "  0x" << entry.value;
        if (!entry.symbol.empty()) {
          output << "  " << entry.symbol;
        }
        write_pointer_chain(output, entry.pointer_chain);
        output << '\n';
      }
    }
    if (enabled("backtrace")) {
      output << l10n::text(l10n::Key::EngineBacktrace);
      for (const ThreadInfo &thread : state.threads) {
        if (!thread.selected) {
          continue;
        }
        for (const StackFrameInfo &frame : thread.frames) {
          output << '#' << std::dec << frame.index << " 0x" << std::hex
                 << frame.pc << ' ' << frame.function << '\n';
        }
      }
    }
    if (enabled("threads")) {
      output << l10n::text(l10n::Key::EngineThreads);
      for (const ThreadInfo &thread : state.threads) {
        output << (thread.selected ? "* " : "  ") << std::dec << thread.index
               << " tid=0x" << std::hex << thread.id << ' ' << thread.name
               << ' ' << thread.stop_reason << '\n';
      }
    }
    if (enabled("expressions") || enabled("watches")) {
      output << l10n::text(l10n::Key::EngineExpressions);
      for (const WatchInfo &watch : state.watches) {
        output << watch.expression << " = "
               << (watch.error.empty() ? watch.value : watch.error) << '\n';
      }
    }
    if (enabled("history")) {
      output << l10n::text(l10n::Key::EngineStopHistory);
      for (const StopHistoryEntry &entry : state.stop_history) {
        output << l10n::format(l10n::Key::EngineStopHistoryEntry,
                               entry.generation, entry.stop_revision,
                               entry.thread_id, entry.pc, entry.sp,
                               entry.stop_reason.c_str());
      }
    }
    if (enabled("crash")) {
      output << l10n::text(l10n::Key::EngineCrash);
      if (!state.crash.crashed) {
        output << l10n::text(l10n::Key::EngineNotCrashed);
      } else {
        output << state.crash.summary << '\n'
               << l10n::text(l10n::Key::EngineStackExecutable)
               << (state.crash.stack_executable
                       ? l10n::text(l10n::Key::EngineYes)
                       : l10n::text(l10n::Key::EngineNo))
               << '\n';
        for (const CyclicMatch &match : state.crash.cyclic_matches) {
          output << cyclic_source_display(match.source);
          if (match.has_address) {
            output << " @ 0x" << std::hex << match.address;
          }
          output << l10n::text(l10n::Key::EngineCyclicOffset) << std::dec
                 << match.offset << " (" << match.bytes << ")\n";
        }
      }
    }
    if (enabled("ghidra")) {
      output << l10n::text(l10n::Key::EngineGhidra)
             << l10n::text(l10n::Key::EngineSeeTheSynchronizedDecompilerPanel);
    }
    return output.str();
  };

  auto apply_patch = [&](lldb::addr_t address,
                         const std::vector<std::uint8_t> &replacement) {
    if (state.state != SessionState::Stopped || !process.IsValid()) {
      return std::string{error_response(
          l10n::text(l10n::Key::EngineErrorPatchingRequiresAStoppedProcess))};
    }
    if (replacement.empty() ||
        replacement.size() >
            std::numeric_limits<std::uint64_t>::max() - address) {
      return std::string{error_response(
          l10n::text(l10n::Key::EngineErrorPatchBytesAreEmptyOrOutOfRange))};
    }

    std::uint64_t merged_start = address;
    std::uint64_t merged_end = address + replacement.size();
    std::vector<std::uint32_t> merged_ids;
    bool found_overlap = true;
    while (found_overlap) {
      found_overlap = false;
      for (const PatchInfo &patch : state.patches) {
        if (std::find(merged_ids.begin(), merged_ids.end(), patch.id) !=
            merged_ids.end()) {
          continue;
        }
        const std::uint64_t patch_end =
            patch.address + patch.replacement.size();
        if (merged_start < patch_end && patch.address < merged_end) {
          merged_ids.push_back(patch.id);
          merged_start = std::min(merged_start, patch.address);
          merged_end = std::max(merged_end, patch_end);
          found_overlap = true;
        }
      }
    }

    std::string failure;
    const std::size_t merged_size =
        static_cast<std::size_t>(merged_end - merged_start);
    auto current =
        read_memory_bytes(process, merged_start, merged_size, failure);
    if (!current) {
      return error_detail(failure);
    }
    std::vector<std::uint8_t> original = *current;
    for (const PatchInfo &patch : state.patches) {
      if (std::find(merged_ids.begin(), merged_ids.end(), patch.id) ==
          merged_ids.end()) {
        continue;
      }
      const std::size_t offset =
          static_cast<std::size_t>(patch.address - merged_start);
      std::copy(patch.original.begin(), patch.original.end(),
                original.begin() + static_cast<std::ptrdiff_t>(offset));
    }
    const std::size_t replacement_offset =
        static_cast<std::size_t>(address - merged_start);
    std::copy(replacement.begin(), replacement.end(),
              current->begin() +
                  static_cast<std::ptrdiff_t>(replacement_offset));

    lldb::SBError write_error;
    const std::size_t written = process.WriteMemory(
        merged_start, current->data(), current->size(), write_error);
    state.disassembly_graph.reset();
    if (write_error.Fail() || written != current->size()) {
      return error_detail(error_text(write_error));
    }

    const std::uint32_t id =
        merged_ids.empty()
            ? next_patch_id++
            : *std::min_element(merged_ids.begin(), merged_ids.end());
    std::erase_if(state.patches, [&merged_ids](const PatchInfo &patch) {
      return std::find(merged_ids.begin(), merged_ids.end(), patch.id) !=
             merged_ids.end();
    });
    const bool restored = *current == original;
    if (!restored) {
      state.patches.push_back(PatchInfo{
          .id = id,
          .address = merged_start,
          .original = std::move(original),
          .replacement = std::move(*current),
      });
    }
    if (!state.memory.empty()) {
      capture_memory(process, state.memory_base, state);
    }
    if (!state.instructions.empty()) {
      capture_instructions(target, state.instructions.front().address, state);
    }

    if (restored) {
      return l10n::format(l10n::Key::EnginePatchRestored, id);
    }
    return l10n::format(l10n::Key::EnginePatchWritten, id, replacement.size(),
                        static_cast<std::uint64_t>(address));
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

    if (command == "help" || command == "h") {
      response = l10n::text(l10n::Key::EngineCommandHelp);
    } else if (command == "u" || command == "disasm") {
      response =
          execute_lldb_command(std::string{"disassemble --start-address "} +
                               std::string{arguments} + " --count 32");
    } else if (command == "k" || command == "kp" || command == "backtrace") {
      response = execute_lldb_command("thread backtrace all");
    } else if (command == "lm" || command == "modules" ||
               command == "linkmap") {
      std::ostringstream modules;
      for (const ModuleInfo &module : state.modules) {
        modules << "0x" << std::hex << module.base << "-0x" << module.end << ' '
                << module.path << '\n';
      }
      response = modules.str();
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
    } else if (command == "pid") {
      response = state.process_id == 0 ? l10n::text(l10n::Key::EngineNoProcess)
                                       : std::to_string(state.process_id);
    } else if (command == "argc") {
      lldb::SBFrame frame = selected_frame(process);
      lldb::SBValue argc_value = frame.FindVariable("argc");
      if (!argc_value.IsValid()) {
        argc_value = frame.EvaluateExpression("(int)argc");
      }
      response =
          argc_value.IsValid() && argc_value.GetError().Success()
              ? safe_string(argc_value.GetValue())
              : l10n::text(
                    l10n::Key::EngineArgcIsUnavailableInTheSelectedFrame);
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
    } else if (command == "syscalls") {
      struct SyscallEntry {
        int number;
        const char *name;
      };
      constexpr std::array<SyscallEntry, 20> x86_64_syscalls{{
          {0, "read"},         {1, "write"},    {2, "open"},
          {3, "close"},        {9, "mmap"},     {10, "mprotect"},
          {11, "munmap"},      {12, "brk"},     {16, "ioctl"},
          {39, "getpid"},      {56, "clone"},   {57, "fork"},
          {58, "vfork"},       {59, "execve"},  {60, "exit"},
          {61, "wait4"},       {62, "kill"},    {158, "arch_prctl"},
          {231, "exit_group"}, {257, "openat"},
      }};
      constexpr std::array<SyscallEntry, 16> generic_syscalls{{
          {29, "ioctl"},
          {56, "openat"},
          {57, "close"},
          {63, "read"},
          {64, "write"},
          {93, "exit"},
          {94, "exit_group"},
          {129, "kill"},
          {172, "getpid"},
          {198, "socket"},
          {214, "brk"},
          {215, "munmap"},
          {220, "clone"},
          {221, "execve"},
          {222, "mmap"},
          {226, "mprotect"},
      }};
      const bool x86 = state.architecture.find("x86_64") != std::string::npos;
      std::ostringstream listing;
      const auto append_matching = [&](const auto &entries) {
        for (const SyscallEntry &entry : entries) {
          if (!arguments.empty() && arguments != entry.name &&
              arguments != std::to_string(entry.number)) {
            continue;
          }
          listing << std::dec << entry.number << ' ' << entry.name << '\n';
        }
      };
      if (x86) {
        append_matching(x86_64_syscalls);
      } else {
        append_matching(generic_syscalls);
      }
      response = listing.str();
      if (response.empty()) {
        response =
            l10n::text(l10n::Key::EngineSystemCallNotFoundInBuiltInTable);
      }
    } else if (command == "sigreturn") {
      const bool x86 = state.architecture.find("x86_64") != std::string::npos;
      std::ostringstream frame;
      frame << l10n::format(l10n::Key::EngineSigreturnSnapshot, x86 ? 15 : 139,
                            state.sp);
      for (const RegisterValue &value : state.registers) {
        frame << value.name << '=' << value.value << ' ';
      }
      frame << l10n::text(
          l10n::Key::EngineInspectionOnlyNoReturnFrameWasWritten);
      response = frame.str();
    } else if (command == "nop" || command == "syscall") {
      const std::vector<std::string> values = split_arguments(arguments);
      if (values.empty()) {
        response = l10n::text(
            l10n::Key::EngineUsageNopAddressInstructionCountSyscallAddress);
      } else {
        std::string failure;
        const auto address = resolve_address(values[0], process, failure);
        const auto count = values.size() > 1 ? parse_integer(values[1])
                                             : std::optional<std::uint64_t>{1};
        if (!address || !count) {
          response = error_response(
              l10n::text(l10n::Key::EngineErrorInvalidAddressOrCount));
        } else {
          std::vector<std::uint8_t> instruction;
          if (state.architecture.find("x86") != std::string::npos) {
            instruction = command == "nop"
                              ? std::vector<std::uint8_t>{0x90}
                              : std::vector<std::uint8_t>{0x0f, 0x05};
          } else if (state.architecture.find("aarch64") != std::string::npos) {
            instruction =
                command == "nop"
                    ? std::vector<std::uint8_t>{0x1f, 0x20, 0x03, 0xd5}
                    : std::vector<std::uint8_t>{0x01, 0x00, 0x00, 0xd4};
          } else if (state.architecture.find("riscv") != std::string::npos) {
            instruction =
                command == "nop"
                    ? std::vector<std::uint8_t>{0x13, 0x00, 0x00, 0x00}
                    : std::vector<std::uint8_t>{0x73, 0x00, 0x00, 0x00};
          }
          if (instruction.empty()) {
            response = error_response(l10n::text(
                l10n::Key::EngineErrorNoInstructionEncodingForTarget));
          } else {
            std::vector<std::uint8_t> replacement;
            const std::size_t repetitions = static_cast<std::size_t>(
                std::clamp<std::uint64_t>(*count, 1, 256));
            replacement.reserve(instruction.size() * repetitions);
            for (std::size_t index = 0; index < repetitions; ++index) {
              replacement.insert(replacement.end(), instruction.begin(),
                                 instruction.end());
            }
            response = apply_patch(*address, replacement);
          }
        }
      }
    } else if (command == "pwndbg") {
      response = l10n::text(l10n::Key::EnginePwndbgHelp);
    } else if (command == "config") {
      std::ostringstream configuration;
      configuration
          << "architecture=" << state.architecture << '\n'
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
              : error_response(l10n::text(
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
          response = error_response(
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
    } else if (command == "hexdump") {
      const std::vector<std::string> values = split_arguments(arguments);
      if (values.empty()) {
        response = l10n::text(l10n::Key::EngineUsageHexdumpAddressCount);
      } else {
        std::string failure;
        const auto address = resolve_address(values[0], process, failure);
        const auto parsed_count = values.size() > 1
                                      ? parse_integer(values[1])
                                      : std::optional<std::uint64_t>{128};
        if (!address || !parsed_count) {
          response = error_detail(
              failure.empty()
                  ? std::string{l10n::text(l10n::Key::EngineInvalidByteCount)}
                  : failure);
        } else {
          const std::size_t count = static_cast<std::size_t>(
              std::clamp<std::uint64_t>(*parsed_count, 1, 4096));
          const auto bytes =
              read_memory_bytes(process, *address, count, failure);
          response =
              bytes ? format_hexdump(*address, *bytes) : error_detail(failure);
        }
      }
    } else if (command == "telescope" || command == "teles" ||
               command == "tel") {
      const std::vector<std::string> values = split_arguments(arguments);
      std::string failure;
      const auto address = values.empty()
                               ? std::optional<lldb::addr_t>{state.sp}
                               : resolve_address(values[0], process, failure);
      const auto parsed_count = values.size() > 1
                                    ? parse_integer(values[1])
                                    : std::optional<std::uint64_t>{8};
      if (!address || !parsed_count) {
        response = error_detail(
            failure.empty() ? std::string{l10n::text(
                                  l10n::Key::EngineInvalidTelescopeCount)}
                            : failure);
      } else {
        const std::uint32_t pointer_size =
            std::max<std::uint32_t>(1, state.address_byte_size);
        const std::size_t count = static_cast<std::size_t>(
            std::clamp<std::uint64_t>(*parsed_count, 1, 64));
        std::ostringstream chain;
        for (std::size_t index = 0; index < count; ++index) {
          const lldb::addr_t slot = *address + index * pointer_size;
          const auto bytes =
              read_memory_bytes(process, slot, pointer_size, failure);
          if (!bytes) {
            chain << "0x" << std::hex << slot << " <" << failure << ">\n";
            break;
          }
          const std::uint64_t value = decode_pointer(
              bytes->data(), pointer_size, target.GetByteOrder());
          chain << "0x" << std::hex << slot << " -> 0x" << value;
          const std::string symbol = symbol_for_address(target, value);
          if (!symbol.empty()) {
            chain << " (" << symbol << ')';
          }
          if (const MemoryRegionInfo *pointed = region_containing(state, value);
              pointed != nullptr && pointed->readable) {
            lldb::SBError string_error;
            char text_buffer[65]{};
            const std::size_t bytes_read = process.ReadMemory(
                value, text_buffer, sizeof(text_buffer) - 1, string_error);
            std::size_t printable = 0;
            while (printable < bytes_read && text_buffer[printable] != '\0' &&
                   std::isprint(static_cast<unsigned char>(
                       text_buffer[printable])) != 0) {
              ++printable;
            }
            if (printable >= 4) {
              chain << " \"" << std::string_view{text_buffer, printable} << '"';
            }
          }
          chain << '\n';
        }
        response = chain.str();
      }
    } else if (command == "p2p") {
      const std::vector<std::string> values = split_arguments(arguments);
      if (values.empty()) {
        response = l10n::text(l10n::Key::EngineUsageP2pAddressDepth);
      } else {
        std::string failure;
        auto current = resolve_address(values[0], process, failure);
        const auto parsed_depth = values.size() > 1
                                      ? parse_integer(values[1])
                                      : std::optional<std::uint64_t>{5};
        if (!current || !parsed_depth) {
          response = error_response(
              l10n::text(l10n::Key::EngineErrorInvalidAddressOrDepth));
        } else {
          const std::uint32_t pointer_size =
              std::max<std::uint32_t>(1, state.address_byte_size);
          std::vector<std::uint64_t> visited;
          std::ostringstream chain;
          const std::size_t depth = static_cast<std::size_t>(
              std::clamp<std::uint64_t>(*parsed_depth, 1, 32));
          for (std::size_t level = 0; level < depth; ++level) {
            chain << "0x" << std::hex << *current;
            if (std::find(visited.begin(), visited.end(), *current) !=
                visited.end()) {
              chain << l10n::text(l10n::Key::EngineCycle);
              break;
            }
            visited.push_back(*current);
            const auto bytes =
                read_memory_bytes(process, *current, pointer_size, failure);
            if (!bytes) {
              chain << " <" << failure << '>';
              break;
            }
            const std::uint64_t next = decode_pointer(
                bytes->data(), pointer_size, target.GetByteOrder());
            chain << " -> ";
            current = next;
          }
          response = chain.str();
        }
      }
    } else if (command == "cyclic") {
      const std::vector<std::string> values = split_arguments(arguments);
      if (values.size() == 2 &&
          (values[0] == "-l" || values[0] == "--lookup")) {
        std::string query = values[1];
        if (const auto numeric = parse_integer(query)) {
          query.clear();
          for (std::size_t index = 0; index < 8; ++index) {
            const char byte =
                static_cast<char>((*numeric >> (index * 8)) & 0xff);
            if (byte == '\0') {
              break;
            }
            query.push_back(byte);
          }
        }
        const std::string pattern = cyclic_pattern(456976);
        std::size_t offset = pattern.find(query);
        if (offset == std::string::npos && query.size() > 4) {
          offset = pattern.find(query.substr(0, 4));
        }
        response = offset == std::string::npos
                       ? l10n::text(l10n::Key::EngineCyclicValueNotFound)
                       : std::to_string(offset);
      } else {
        const auto length = values.empty() ? std::optional<std::uint64_t>{100}
                                           : parse_integer(values[0]);
        response =
            length ? cyclic_pattern(static_cast<std::size_t>(
                         std::min<std::uint64_t>(*length, 456976)))
                   : l10n::text(l10n::Key::EngineUsageCyclicLengthCyclicLValue);
      }
    } else if (command == "stack_explore") {
      std::ostringstream candidates;
      for (const StackEntry &entry : state.stack) {
        const MemoryRegionInfo *destination =
            region_containing(state, entry.value);
        if (destination == nullptr || !destination->executable) {
          continue;
        }
        candidates << "0x" << std::hex << entry.address << " -> 0x"
                   << entry.value << ' '
                   << symbol_for_address(target, entry.value) << ' '
                   << destination->name << '\n';
      }
      response = candidates.str();
      if (response.empty()) {
        response = l10n::text(
            l10n::Key::EngineNoExecutablePointersInCapturedStackWindow);
      }
    } else if (command == "valist") {
      std::string failure;
      const auto address = resolve_address(arguments, process, failure);
      if (!address) {
        response = l10n::text(l10n::Key::EngineUsageValistVaListAddress);
      } else {
        const auto bytes = read_memory_bytes(process, *address, 24, failure);
        if (!bytes) {
          response = error_detail(failure);
        } else if (state.architecture.find("x86_64") != std::string::npos) {
          const std::uint64_t gp_offset =
              decode_pointer(bytes->data(), 4, target.GetByteOrder());
          const std::uint64_t fp_offset =
              decode_pointer(bytes->data() + 4, 4, target.GetByteOrder());
          const std::uint64_t overflow =
              decode_pointer(bytes->data() + 8, state.address_byte_size,
                             target.GetByteOrder());
          const std::uint64_t register_save =
              decode_pointer(bytes->data() + 16, state.address_byte_size,
                             target.GetByteOrder());
          std::ostringstream value;
          value << "gp_offset=" << std::dec << gp_offset
                << " fp_offset=" << fp_offset << " overflow_arg_area=0x"
                << std::hex << overflow << " reg_save_area=0x" << register_save;
          response = value.str();
        } else {
          response = format_hexdump(*address, *bytes);
        }
      }
    } else if (command == "search") {
      const std::vector<std::string> values = split_arguments(arguments);
      std::vector<std::uint8_t> needle;
      std::string mapping_filter;
      if (!values.empty() && values[0] == "-x") {
        if (values.size() < 2) {
          response = l10n::text(l10n::Key::EngineUsageSearchXAABBMapping);
        } else {
          const auto parsed = parse_hex_bytes(values[1]);
          if (parsed) {
            needle = *parsed;
          }
          if (values.size() > 2) {
            mapping_filter = values[2];
          }
        }
      } else if (values.size() >= 3 && values[0] == "-t") {
        const std::string type = lowercase(values[1]);
        if (type == "string" || type == "str") {
          needle.assign(values[2].begin(), values[2].end());
        } else {
          const auto numeric = parse_integer(values[2]);
          std::size_t width = 0;
          if (type == "byte" || type == "u8") {
            width = 1;
          } else if (type == "short" || type == "u16") {
            width = 2;
          } else if (type == "int" || type == "u32") {
            width = 4;
          } else if (type == "long" || type == "pointer" || type == "u64") {
            width = type == "pointer" ? state.address_byte_size : 8;
          }
          if (numeric && width != 0) {
            needle.resize(width);
            for (std::size_t index = 0; index < width; ++index) {
              const std::size_t byte_index =
                  target.GetByteOrder() == lldb::eByteOrderBig
                      ? width - 1 - index
                      : index;
              needle[byte_index] =
                  static_cast<std::uint8_t>((*numeric >> (index * 8)) & 0xff);
            }
          }
        }
        if (values.size() > 3) {
          mapping_filter = values[3];
        }
      } else if (!values.empty()) {
        needle.assign(values[0].begin(), values[0].end());
        if (values.size() > 1) {
          mapping_filter = values[1];
        }
      }

      if (response.empty() && needle.empty()) {
        response = l10n::text(l10n::Key::EngineSearchUsage);
      } else if (response.empty()) {
        constexpr std::size_t chunk_size = 64 * 1024;
        constexpr std::uint64_t scan_limit = 256ULL * 1024 * 1024;
        constexpr std::size_t result_limit = 256;
        std::uint64_t scanned = 0;
        std::size_t result_count = 0;
        std::ostringstream matches;
        bool truncated = false;
        for (const MemoryRegionInfo &region : state.memory_regions) {
          if (!region.readable ||
              (!mapping_filter.empty() &&
               region.name.find(mapping_filter) == std::string::npos)) {
            continue;
          }
          std::vector<std::uint8_t> carry;
          for (std::uint64_t address = region.start; address < region.end;) {
            if (scanned >= scan_limit || result_count >= result_limit) {
              truncated = true;
              break;
            }
            const std::size_t count = static_cast<std::size_t>(
                std::min<std::uint64_t>(chunk_size, region.end - address));
            std::vector<std::uint8_t> buffer(carry.size() + count);
            std::copy(carry.begin(), carry.end(), buffer.begin());
            lldb::SBError read_error;
            const std::size_t bytes_read = process.ReadMemory(
                address, buffer.data() + carry.size(), count, read_error);
            if (bytes_read == 0) {
              break;
            }
            buffer.resize(carry.size() + bytes_read);
            auto cursor = buffer.begin();
            while (cursor != buffer.end()) {
              cursor = std::search(cursor, buffer.end(), needle.begin(),
                                   needle.end());
              if (cursor == buffer.end()) {
                break;
              }
              const std::uint64_t match_address =
                  address - carry.size() +
                  static_cast<std::uint64_t>(
                      std::distance(buffer.begin(), cursor));
              matches << "0x" << std::hex << match_address << ' ' << region.name
                      << '\n';
              ++result_count;
              if (result_count >= result_limit) {
                truncated = true;
                break;
              }
              ++cursor;
            }
            const std::size_t carry_size =
                std::min<std::size_t>(needle.size() - 1, buffer.size());
            carry.assign(buffer.end() - static_cast<std::ptrdiff_t>(carry_size),
                         buffer.end());
            address += bytes_read;
            scanned += bytes_read;
          }
          if (truncated) {
            break;
          }
        }
        if (result_count == 0) {
          matches << l10n::text(l10n::Key::EnginePatternNotFound);
        }
        if (truncated) {
          matches << l10n::format(l10n::Key::EngineSearchTruncated,
                                  result_count, scanned);
        }
        response = matches.str();
      }
    } else if (command == "xuntil" || command == "stepuntilasm" ||
               command == "nextcall" || command == "nextproginstr" ||
               command == "nextbranch" || command == "nextjmp" ||
               command == "nextret" || command == "stepret" ||
               command == "nextsyscall" || command == "stepsyscall") {
      const std::vector<std::string> values = split_arguments(arguments);
      std::size_t instruction_limit = 256;
      if ((command == "xuntil" || command == "stepuntilasm") &&
          values.size() > 1) {
        if (const auto parsed = parse_integer(values[1])) {
          instruction_limit = static_cast<std::size_t>(
              std::clamp<std::uint64_t>(*parsed, 1, 4096));
        }
      }
      if ((command == "xuntil" || command == "stepuntilasm") &&
          values.empty()) {
        response =
            l10n::text(l10n::Key::EngineUsageXuntilMnemonicMaxInstructions);
      } else {
        lldb::SBInstructionList instructions = target.ReadInstructions(
            target.ResolveLoadAddress(state.pc),
            static_cast<std::uint32_t>(instruction_limit));
        std::optional<lldb::addr_t> destination;
        for (std::size_t index = 1; index < instructions.GetSize(); ++index) {
          lldb::SBInstruction instruction = instructions.GetInstructionAtIndex(
              static_cast<std::uint32_t>(index));
          const std::string mnemonic =
              lowercase(safe_string(instruction.GetMnemonic(target)));
          bool matches = false;
          if (command == "xuntil" || command == "stepuntilasm") {
            matches = mnemonic.find(lowercase(values[0])) != std::string::npos;
          } else if (command == "nextproginstr") {
            matches = true;
          } else if (command == "nextcall") {
            matches = mnemonic.starts_with("call") || mnemonic == "bl" ||
                      mnemonic == "blr" || mnemonic == "jal" ||
                      mnemonic == "jalr";
          } else if (command == "nextjmp" || command == "nextbranch") {
            matches = mnemonic.starts_with("j") || mnemonic.starts_with("b") ||
                      mnemonic == "cbz" || mnemonic == "cbnz";
          } else if (command == "nextret" || command == "stepret") {
            matches =
                mnemonic.starts_with("ret") ||
                (mnemonic == "jr" &&
                 safe_string(instruction.GetOperands(target)).find("ra") !=
                     std::string::npos);
          } else {
            matches = mnemonic == "syscall" || mnemonic == "sysenter" ||
                      mnemonic == "int" || mnemonic == "svc" ||
                      mnemonic == "ecall";
          }
          if (matches) {
            destination = instruction.GetAddress().GetLoadAddress(target);
            break;
          }
        }
        response =
            destination
                ? run_to_address_impl(*destination)
                : l10n::format(l10n::Key::EngineMatchingInstructionNotFound,
                               instruction_limit);
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
          response = error_response(
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
          response = error_detail(failure);
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
          response = error_response(
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
          response = error_detail(failure);
        } else {
          std::ostringstream expression;
          expression << "expression -- *(" << values[0] << "*)0x" << std::hex
                     << *address;
          response = execute_lldb_command(expression.str());
        }
      }
    } else if (command == "plist") {
      const std::vector<std::string> values = split_arguments(arguments);
      if (values.empty()) {
        response = l10n::text(
            l10n::Key::EngineUsagePlistHeadAddressNextPointerOffsetMaxNodes);
      } else {
        std::string failure;
        auto current = resolve_address(values[0], process, failure);
        const auto offset = values.size() > 1 ? parse_integer(values[1])
                                              : std::optional<std::uint64_t>{0};
        const auto maximum = values.size() > 2
                                 ? parse_integer(values[2])
                                 : std::optional<std::uint64_t>{32};
        if (!current || !offset || !maximum) {
          response = error_response(l10n::text(
              l10n::Key::EngineErrorInvalidListAddressOffsetOrCount));
        } else {
          const std::uint32_t pointer_size =
              std::max<std::uint32_t>(1, state.address_byte_size);
          std::vector<std::uint64_t> visited;
          std::ostringstream nodes;
          for (std::uint64_t index = 0;
               index < std::min<std::uint64_t>(*maximum, 256) && *current != 0;
               ++index) {
            nodes << index << ": 0x" << std::hex << *current << '\n';
            if (std::find(visited.begin(), visited.end(), *current) !=
                visited.end()) {
              nodes << l10n::text(l10n::Key::EngineCycleDetected);
              break;
            }
            visited.push_back(*current);
            const auto bytes = read_memory_bytes(process, *current + *offset,
                                                 pointer_size, failure);
            if (!bytes) {
              nodes << l10n::format(l10n::Key::EngineErrorDetail,
                                    failure.c_str())
                    << '\n';
              break;
            }
            current = decode_pointer(bytes->data(), pointer_size,
                                     target.GetByteOrder());
          }
          response = nodes.str();
        }
      }
    } else if (command == "heap_config") {
      std::ostringstream configuration;
      const auto libc_module = std::find_if(
          state.modules.begin(), state.modules.end(),
          [](const ModuleInfo &module) {
            return module.path.find("libc.so") != std::string::npos;
          });
      configuration << "allocator=glibc\n"
                    << "pointer-size=" << state.address_byte_size << '\n'
                    << "byte-order=" << state.byte_order << '\n'
                    << "safe-linking-decode=enabled\n"
                    << "heap-chunk-limit=256\n"
                    << "libc="
                    << (libc_module == state.modules.end()
                            ? l10n::text(l10n::Key::EngineNotDetected)
                            : libc_module->path)
                    << "\nwalk-status="
                    << (state.heap_error.empty()
                            ? l10n::text(l10n::Key::EngineOk)
                            : state.heap_error);
      response = configuration.str();
    } else if (command == "heap" || command == "vis_heap_chunks" ||
               command == "malloc_chunk" || command == "bins" ||
               command == "fastbins" || command == "tcachebins" ||
               command == "unsortedbin" || command == "smallbins" ||
               command == "largebins") {
      std::optional<std::uint64_t> requested_address;
      if (!arguments.empty() && command != "vis_heap_chunks") {
        std::string failure;
        requested_address = resolve_address(arguments, process, failure);
        if (!requested_address && command == "malloc_chunk") {
          response = error_detail(failure);
        }
      }
      if (response.empty()) {
        std::ostringstream chunks;
        const std::uint64_t fast_max =
            state.address_byte_size == 4 ? 0x50 : 0x90;
        const std::uint64_t small_max =
            state.address_byte_size == 4 ? 0x200 : 0x400;
        for (const HeapChunkInfo &chunk : state.heap_chunks) {
          if (requested_address &&
              (*requested_address < chunk.address ||
               *requested_address >= chunk.address + chunk.size)) {
            continue;
          }
          if (command == "fastbins" &&
              (chunk.in_use || chunk.size > fast_max)) {
            continue;
          }
          if (command == "tcachebins" &&
              (chunk.in_use || chunk.size > small_max)) {
            continue;
          }
          if (command == "unsortedbin" &&
              (chunk.in_use || chunk.size <= fast_max)) {
            continue;
          }
          if (command == "smallbins" &&
              (chunk.in_use || chunk.size <= fast_max ||
               chunk.size > small_max)) {
            continue;
          }
          if (command == "largebins" &&
              (chunk.in_use || chunk.size <= small_max)) {
            continue;
          }
          chunks << "0x" << std::hex << chunk.address
                 << l10n::text(l10n::Key::EngineSizeAddress) << chunk.size
                 << l10n::text(l10n::Key::EnginePrevSizeAddress)
                 << chunk.previous_size << l10n::text(l10n::Key::EngineFlags)
                 << ((chunk.flags & 1U) != 0 ? 'P' : '-')
                 << ((chunk.flags & 2U) != 0 ? 'M' : '-')
                 << ((chunk.flags & 4U) != 0 ? 'A' : '-') << ' '
                 << (chunk.in_use ? l10n::text(l10n::Key::EngineInUse)
                                  : l10n::text(l10n::Key::EngineFree));
          if (!chunk.in_use) {
            const std::uint64_t user_address =
                chunk.address + state.address_byte_size * 2;
            chunks << l10n::text(l10n::Key::EngineFdAddress) << chunk.forward
                   << l10n::text(l10n::Key::EngineSafeFdAddress)
                   << (chunk.forward ^ (user_address >> 12))
                   << l10n::text(l10n::Key::EngineBkAddress) << chunk.backward;
          }
          chunks << '\n';
          if (command == "vis_heap_chunks") {
            chunks << l10n::text(l10n::Key::EngineNextAddress)
                   << (chunk.address + chunk.size) << '\n';
          }
        }
        if (!state.heap_error.empty()) {
          chunks << '[' << state.heap_error << "]\n";
        }
        response = chunks.str();
        if (response.empty()) {
          response = l10n::text(l10n::Key::EngineNoMatchingGlibcHeapChunks);
        }
      }
    } else if (command == "arena" || command == "arenas" || command == "mp") {
      std::ostringstream allocator;
      std::size_t used = 0;
      std::size_t free = 0;
      std::uint64_t bytes = 0;
      for (const HeapChunkInfo &chunk : state.heap_chunks) {
        bytes += chunk.size;
        if (chunk.in_use) {
          ++used;
        } else {
          ++free;
        }
      }
      allocator << l10n::format(l10n::Key::EngineHeapSummary,
                                state.heap_chunks.size(), used, free, bytes);
      if (const auto heap = std::find_if(state.memory_regions.begin(),
                                         state.memory_regions.end(),
                                         [](const MemoryRegionInfo &region) {
                                           return region.name == "[heap]";
                                         });
          heap != state.memory_regions.end()) {
        allocator << l10n::format(l10n::Key::EngineArenaMapping, heap->start,
                                  heap->end);
      }
      if (!state.heap_error.empty()) {
        allocator << state.heap_error;
      }
      response = allocator.str();
    } else if (command == "find_fake_fast") {
      std::string failure;
      const auto target_address = resolve_address(arguments, process, failure);
      if (!target_address) {
        response = l10n::text(l10n::Key::EngineUsageFindFakeFastAddress);
      } else {
        const std::uint32_t pointer_size =
            std::max<std::uint32_t>(1, state.address_byte_size);
        const std::uint64_t alignment = pointer_size * 2;
        const std::uint64_t fast_max = pointer_size == 4 ? 0x50 : 0x90;
        const std::uint64_t search_start =
            *target_address > 0x100 ? *target_address - 0x100 : 0;
        std::ostringstream candidates;
        for (std::uint64_t header =
                 (search_start + alignment - 1) & ~(alignment - 1);
             header + pointer_size * 2 <= *target_address;
             header += alignment) {
          const auto bytes = read_memory_bytes(process, header + pointer_size,
                                               pointer_size, failure);
          if (!bytes) {
            continue;
          }
          const std::uint64_t size_and_flags = decode_pointer(
              bytes->data(), pointer_size, target.GetByteOrder());
          const std::uint64_t size = size_and_flags & ~0x7ULL;
          if (size >= alignment && size <= fast_max &&
              header + size >= *target_address) {
            candidates << "0x" << std::hex << header
                       << l10n::text(l10n::Key::EngineSizeAddress) << size
                       << '\n';
          }
        }
        response = candidates.str();
        if (response.empty()) {
          response =
              l10n::text(l10n::Key::EngineNoPlausibleFastbinSizedFakeChunk);
        }
      }
    } else if (command == "try_free") {
      std::string failure;
      const auto user_address = resolve_address(arguments, process, failure);
      if (!user_address) {
        response = l10n::text(l10n::Key::EngineUsageTryFreeUserPointer);
      } else {
        const std::uint64_t header_size = state.address_byte_size * 2;
        const auto chunk = std::find_if(
            state.heap_chunks.begin(), state.heap_chunks.end(),
            [user_address, header_size](const HeapChunkInfo &candidate) {
              return candidate.address + header_size == *user_address;
            });
        if (chunk == state.heap_chunks.end()) {
          response = l10n::text(
              l10n::Key::EngineUnsafePointerIsNotADiscoveredChunkPayload);
        } else if (!chunk->in_use) {
          response = l10n::text(l10n::Key::EngineUnsafeChunkAppearsAlreadyFree);
        } else if ((chunk->size % (state.address_byte_size * 2)) != 0) {
          response = l10n::text(l10n::Key::EngineUnsafeChunkSizeIsMisaligned);
        } else {
          std::ostringstream result;
          result << l10n::format(l10n::Key::EnginePlausibleFree, *user_address,
                                 chunk->address, chunk->size);
          response = result.str();
        }
      }
    } else if (command == "patch") {
      const std::vector<std::string> values = split_arguments(arguments);
      if (values.size() < 2) {
        response = l10n::text(l10n::Key::EngineUsagePatchAddressHexBytes);
      } else {
        std::string failure;
        const auto address = resolve_address(values[0], process, failure);
        std::string byte_text;
        for (std::size_t index = 1; index < values.size(); ++index) {
          if (!byte_text.empty()) {
            byte_text.push_back(' ');
          }
          byte_text += values[index];
        }
        const auto replacement = parse_hex_bytes(byte_text);
        response =
            address && replacement
                ? apply_patch(*address, *replacement)
                : error_response(l10n::text(
                      l10n::Key::EngineErrorInvalidAddressOrHexadecimalBytes));
      }
    } else if (command == "assemble" || command == "asm") {
      const std::size_t instruction_separator = arguments.find_first_of(" \t");
      const std::string_view address_text =
          instruction_separator == std::string_view::npos
              ? arguments
              : arguments.substr(0, instruction_separator);
      const std::string_view instruction =
          instruction_separator == std::string_view::npos
              ? std::string_view{}
              : trim(arguments.substr(instruction_separator + 1));
      if (address_text.empty() || instruction.empty()) {
        response = l10n::text(
            l10n::Key::EngineUsageAssembleAddressIntelSyntaxInstruction);
      } else {
        std::string failure;
        const auto address = resolve_address(address_text, process, failure);
        const auto replacement =
            address
                ? assemble_intel_instruction(instruction, *address,
                                             state.architecture,
                                             state.address_byte_size, failure)
                : std::nullopt;
        response = address && replacement ? apply_patch(*address, *replacement)
                                          : error_detail(failure);
      }
    } else if (command == "patch_list") {
      std::ostringstream patches;
      for (const PatchInfo &patch : state.patches) {
        patches << patch.id << " 0x" << std::hex << patch.address
                << l10n::text(l10n::Key::EngineOriginal);
        for (std::uint8_t byte : patch.original) {
          patches << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(byte);
        }
        patches << l10n::text(l10n::Key::EngineReplacement);
        for (std::uint8_t byte : patch.replacement) {
          patches << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned int>(byte);
        }
        patches << '\n';
      }
      response = patches.str();
      if (response.empty()) {
        response = l10n::text(l10n::Key::EngineNoActivePatches);
      }
    } else if (command == "patch_revert") {
      const auto requested = parse_integer(arguments);
      if (!requested) {
        response = l10n::text(l10n::Key::EngineUsagePatchRevertIdAddress);
      } else {
        auto patch = std::find_if(state.patches.begin(), state.patches.end(),
                                  [requested](const PatchInfo &candidate) {
                                    return candidate.id == *requested ||
                                           candidate.address == *requested;
                                  });
        if (patch == state.patches.end()) {
          response =
              error_response(l10n::text(l10n::Key::EngineErrorPatchNotFound));
        } else {
          lldb::SBError write_error;
          const std::size_t written =
              process.WriteMemory(patch->address, patch->original.data(),
                                  patch->original.size(), write_error);
          state.disassembly_graph.reset();
          if (write_error.Fail() || written != patch->original.size()) {
            response = error_detail(error_text(write_error));
          } else {
            const std::uint32_t patch_id = patch->id;
            state.patches.erase(patch);
            if (!state.memory.empty()) {
              capture_memory(process, state.memory_base, state);
            }
            if (!state.instructions.empty()) {
              capture_instructions(target, state.instructions.front().address,
                                   state);
            }
            response = l10n::format(l10n::Key::EnginePatchReverted, patch_id);
          }
        }
      }
    } else if (command == "vmmap" || command == "mmap" || command == "memmap" ||
               command == "!address") {
      std::string address_failure;
      const auto requested_address =
          arguments.empty()
              ? std::nullopt
              : resolve_address(arguments, process, address_failure);
      std::ostringstream mappings;
      for (const MemoryRegionInfo &region : state.memory_regions) {
        if (requested_address && (*requested_address < region.start ||
                                  *requested_address >= region.end)) {
          continue;
        }
        if (!arguments.empty() && !requested_address &&
            region.name.find(arguments) == std::string::npos) {
          continue;
        }
        mappings << "0x" << std::hex << region.start << "-0x" << region.end
                 << ' ' << permission_text(region) << ' ' << region.name
                 << '\n';
      }
      response = mappings.str();
      if (response.empty()) {
        response = l10n::text(l10n::Key::EngineNoMatchingMemoryMappings);
      }
    } else if (command == "xinfo" || command == "examine") {
      std::string address_failure;
      const auto address = resolve_address(arguments, process, address_failure);
      if (!address) {
        response =
            l10n::text(l10n::Key::EngineUsageXinfoAddressRegisterExpression);
      } else {
        std::ostringstream information;
        information << l10n::text(l10n::Key::EngineAddressAddress) << std::hex
                    << *address << '\n';
        if (const MemoryRegionInfo *region =
                region_containing(state, *address)) {
          information << l10n::text(l10n::Key::EngineMappingAddress)
                      << region->start << "-0x" << region->end << ' '
                      << permission_text(*region) << ' ' << region->name
                      << l10n::text(l10n::Key::EngineOffsetAddress)
                      << (*address - region->start) << '\n';
        }
        lldb::SBAddress resolved = target.ResolveLoadAddress(*address);
        if (resolved.IsValid()) {
          information << l10n::text(l10n::Key::EngineModule)
                      << module_path(resolved.GetModule())
                      << l10n::text(l10n::Key::EngineSection)
                      << safe_string(resolved.GetSection().GetName())
                      << l10n::text(l10n::Key::EngineFileAddressAddress)
                      << resolved.GetFileAddress() << '\n';
        }
        const std::string symbol = symbol_for_address(target, *address);
        if (!symbol.empty()) {
          information << l10n::text(l10n::Key::EngineSymbol) << symbol << '\n';
        }
        response = information.str();
      }
    } else if (command == "piebase") {
      std::ostringstream bases;
      for (std::size_t index = 0; index < target.GetNumModules(); ++index) {
        lldb::SBModule module =
            target.GetModuleAtIndex(static_cast<std::uint32_t>(index));
        const std::string path = module_path(module);
        if (!arguments.empty() && path.find(arguments) == std::string::npos) {
          continue;
        }
        lldb::SBAddress header = module.GetObjectFileHeaderAddress();
        const lldb::addr_t load = header.GetLoadAddress(target);
        if (load != LLDB_INVALID_ADDRESS) {
          bases << "0x" << std::hex << load << ' ' << path << '\n';
        }
        if (arguments.empty()) {
          break;
        }
      }
      response = bases.str();
      if (response.empty()) {
        response = l10n::text(l10n::Key::EngineModuleNotFoundOrNotLoaded);
      }
    } else if (command == "got" || command == "gotplt" || command == "plt") {
      const std::vector<std::string_view> wanted =
          command == "got" ? std::vector<std::string_view>{".got", ".got.plt"}
          : command == "gotplt"
              ? std::vector<std::string_view>{".got.plt"}
              : std::vector<std::string_view>{".plt", ".plt.sec"};
      std::ostringstream listing;
      for (std::size_t module_index = 0; module_index < target.GetNumModules();
           ++module_index) {
        lldb::SBModule module =
            target.GetModuleAtIndex(static_cast<std::uint32_t>(module_index));
        const std::string path = module_path(module);
        if (!arguments.empty() && path.find(arguments) == std::string::npos) {
          continue;
        }
        for (std::string_view section_name : wanted) {
          std::vector<lldb::SBSection> matches;
          for (std::size_t section_index = 0;
               section_index < module.GetNumSections(); ++section_index) {
            collect_matching_sections(module.GetSectionAtIndex(section_index),
                                      section_name, matches);
          }
          for (lldb::SBSection section : matches) {
            const lldb::addr_t load = section.GetLoadAddress(target);
            listing << path << ' ' << section_name << " 0x" << std::hex << load
                    << "-0x" << (load + section.GetByteSize()) << '\n';
            if (command == "plt") {
              lldb::SBInstructionList instructions =
                  target.ReadInstructions(target.ResolveLoadAddress(load), 32);
              for (std::size_t instruction_index = 0;
                   instruction_index < instructions.GetSize();
                   ++instruction_index) {
                lldb::SBInstruction instruction =
                    instructions.GetInstructionAtIndex(
                        static_cast<std::uint32_t>(instruction_index));
                listing << "  0x"
                        << instruction.GetAddress().GetLoadAddress(target)
                        << ' ' << safe_string(instruction.GetMnemonic(target))
                        << ' ' << safe_string(instruction.GetOperands(target))
                        << '\n';
              }
              continue;
            }
            const std::uint32_t pointer_size =
                std::max<std::uint32_t>(1, state.address_byte_size);
            const std::size_t slots = std::min<std::size_t>(
                section.GetByteSize() / pointer_size, 256);
            for (std::size_t slot = 0; slot < slots; ++slot) {
              std::string failure;
              const auto bytes = read_memory_bytes(
                  process, load + slot * pointer_size, pointer_size, failure);
              if (!bytes) {
                listing << "  <" << failure << ">\n";
                break;
              }
              const std::uint64_t value = decode_pointer(
                  bytes->data(), pointer_size, target.GetByteOrder());
              listing << "  0x" << (load + slot * pointer_size) << " -> 0x"
                      << value;
              const std::string symbol = symbol_for_address(target, value);
              if (!symbol.empty()) {
                listing << ' ' << symbol;
              }
              listing << '\n';
            }
          }
        }
      }
      response = listing.str();
      if (response.empty()) {
        response = l10n::text(l10n::Key::EngineMatchingSectionNotFound);
      }
    } else if (command == "checksec") {
      if (!state.security.available) {
        response = l10n::text(l10n::Key::EngineELFSecurityMetadataUnavailable);
      } else {
        std::ostringstream security;
        security << l10n::text(l10n::Key::EnginePIE)
                 << (state.security.pie ? l10n::text(l10n::Key::EngineEnabled)
                                        : l10n::text(l10n::Key::EngineDisabled))
                 << l10n::text(l10n::Key::EngineNX)
                 << (state.security.nx ? l10n::text(l10n::Key::EngineEnabled)
                                       : l10n::text(l10n::Key::EngineDisabled))
                 << l10n::text(l10n::Key::EngineRELRO)
                 << (state.security.full_relro
                         ? l10n::text(l10n::Key::EngineFull)
                     : state.security.relro
                         ? l10n::text(l10n::Key::EnginePartial)
                         : l10n::text(l10n::Key::EngineNone))
                 << l10n::text(l10n::Key::EngineCanary)
                 << (state.security.stack_canary
                         ? l10n::text(l10n::Key::EngineFound)
                         : l10n::text(l10n::Key::EngineNotFound))
                 << l10n::text(l10n::Key::EngineSymbols)
                 << (state.security.stripped
                         ? l10n::text(l10n::Key::EngineStripped)
                         : l10n::text(l10n::Key::EnginePresent));
        response = security.str();
      }
    } else if (command == "auxv") {
      if (state.mode != SessionMode::Local || state.process_is_remote) {
        response = error_response(l10n::text(
            l10n::Key::
                EngineErrorAuxvHostLookupIsUnavailableForRemoteSessions));
      } else if (state.process_id == 0) {
        response = error_response(l10n::text(l10n::Key::EngineErrorNoProcess));
      } else {
        const std::filesystem::path auxv_path =
            std::filesystem::path{"/proc"} / std::to_string(state.process_id) /
            "auxv";
        std::ifstream auxv_file{auxv_path, std::ios::binary};
        const std::vector<std::uint8_t> bytes{
            std::istreambuf_iterator<char>{auxv_file},
            std::istreambuf_iterator<char>{}};
        const std::uint32_t width = state.address_byte_size;
        std::ostringstream entries;
        if (width == 0 || bytes.size() % (width * 2) != 0) {
          response = error_response(
              l10n::text(l10n::Key::EngineErrorInvalidProcAuxiliaryVector));
        } else {
          const auto name_for_type = [](std::uint64_t type) {
            switch (type) {
            case 3:
              return "AT_PHDR";
            case 4:
              return "AT_PHENT";
            case 5:
              return "AT_PHNUM";
            case 6:
              return "AT_PAGESZ";
            case 7:
              return "AT_BASE";
            case 9:
              return "AT_ENTRY";
            case 11:
              return "AT_UID";
            case 12:
              return "AT_EUID";
            case 13:
              return "AT_GID";
            case 14:
              return "AT_EGID";
            case 15:
              return "AT_PLATFORM";
            case 16:
              return "AT_HWCAP";
            case 17:
              return "AT_CLKTCK";
            case 23:
              return "AT_SECURE";
            case 25:
              return "AT_RANDOM";
            case 26:
              return "AT_HWCAP2";
            case 31:
              return "AT_EXECFN";
            case 33:
              return "AT_SYSINFO_EHDR";
            default:
              return "AT_UNKNOWN";
            }
          };
          for (std::size_t offset = 0; offset + width * 2 <= bytes.size();
               offset += width * 2) {
            const std::uint64_t type = decode_pointer(
                bytes.data() + offset, width, target.GetByteOrder());
            const std::uint64_t value = decode_pointer(
                bytes.data() + offset + width, width, target.GetByteOrder());
            if (type == 0) {
              break;
            }
            entries << name_for_type(type) << '(' << std::dec << type
                    << ") = 0x" << std::hex << value << '\n';
          }
          response = entries.str();
        }
      }
    } else if (command == "elfsections") {
      response = execute_lldb_command(
          arguments.empty()
              ? "image dump sections"
              : std::string{"image dump sections "} + std::string{arguments});
    } else if (command == "kbase" || command == "kchecksec") {
      response = l10n::text(l10n::Key::EngineKernelSessionsUnsupported);
    } else if (command == "tls") {
      lldb::SBFrame frame = selected_frame(process);
      const std::array<const char *, 4> register_names{"fs_base", "tpidr_el0",
                                                       "tp", "gs_base"};
      std::ostringstream tls;
      for (const char *name : register_names) {
        lldb::SBValue value = frame.FindRegister(name);
        if (value.IsValid()) {
          tls << name << "=0x" << std::hex << value.GetValueAsUnsigned()
              << '\n';
        }
      }
      response = tls.str();
      if (response.empty()) {
        response = l10n::text(
            l10n::Key::EngineTLSBaseRegisterIsUnavailableForThisTarget);
      }
    } else if (command == "retaddr") {
      lldb::SBThread thread = process.GetSelectedThread();
      std::ostringstream addresses;
      for (std::uint32_t index = 1; index < thread.GetNumFrames(); ++index) {
        lldb::SBFrame frame = thread.GetFrameAtIndex(index);
        addresses << '#' << index << " 0x" << std::hex << frame.GetPC() << ' '
                  << safe_string(frame.GetFunctionName()) << '\n';
      }
      response = addresses.str();
      if (response.empty()) {
        response = l10n::text(l10n::Key::EngineNoSavedReturnAddress);
      }
    } else if (command == "canary") {
      lldb::SBFrame frame = selected_frame(process);
      std::optional<std::uint64_t> canary_address;
      lldb::SBValue fs_base = frame.FindRegister("fs_base");
      if (fs_base.IsValid()) {
        canary_address = fs_base.GetValueAsUnsigned() + 0x28;
      } else {
        lldb::SBValue guard = frame.EvaluateExpression("&__stack_chk_guard");
        if (guard.IsValid() && guard.GetError().Success()) {
          canary_address = guard.GetValueAsUnsigned();
        }
      }
      if (!canary_address) {
        response = l10n::text(l10n::Key::EngineStackCanaryLocationUnavailable);
      } else {
        std::string failure;
        const auto bytes = read_memory_bytes(process, *canary_address,
                                             state.address_byte_size, failure);
        if (!bytes) {
          response = error_detail(failure);
        } else {
          std::ostringstream canary;
          canary << "0x" << std::hex << *canary_address << ": 0x"
                 << decode_pointer(bytes->data(), state.address_byte_size,
                                   target.GetByteOrder());
          response = canary.str();
        }
      }
    } else if (command == "distance") {
      const std::vector<std::string> values = split_arguments(arguments);
      if (values.size() != 2) {
        response = l10n::text(l10n::Key::EngineUsageDistanceAddressAddress);
      } else {
        std::string first_failure;
        std::string second_failure;
        const auto first = resolve_address(values[0], process, first_failure);
        const auto second = resolve_address(values[1], process, second_failure);
        if (!first || !second) {
          response = error_response(
              l10n::text(l10n::Key::EngineErrorCouldNotResolveBothAddresses));
        } else {
          const std::int64_t delta =
              static_cast<std::int64_t>(*second - *first);
          std::ostringstream difference;
          difference << l10n::format(
              l10n::Key::EngineAddressDistance, delta,
              state.address_byte_size == 0
                  ? std::int64_t{0}
                  : delta / static_cast<std::int64_t>(state.address_byte_size),
              static_cast<std::uint64_t>(delta));
          response = difference.str();
        }
      }
    } else if (command == "procinfo") {
      if (state.mode != SessionMode::Local || state.process_is_remote) {
        response = error_response(l10n::text(
            l10n::Key::
                EngineErrorProcinfoHostLookupIsUnavailableForRemoteSessions));
      } else if (state.process_id == 0) {
        response = error_response(l10n::text(l10n::Key::EngineErrorNoProcess));
      } else {
        const std::filesystem::path process_root =
            std::filesystem::path{"/proc"} / std::to_string(state.process_id);
        std::ifstream status_file{process_root / "status"};
        std::ostringstream information;
        std::string line;
        while (std::getline(status_file, line)) {
          if (line.starts_with("Name:") || line.starts_with("State:") ||
              line.starts_with("Pid:") || line.starts_with("PPid:") ||
              line.starts_with("Uid:") || line.starts_with("Gid:") ||
              line.starts_with("Threads:") || line.starts_with("Seccomp:")) {
            information << line << '\n';
          }
        }
        std::ifstream command_file{process_root / "cmdline", std::ios::binary};
        std::string process_command_line{
            std::istreambuf_iterator<char>{command_file},
            std::istreambuf_iterator<char>{}};
        std::replace(process_command_line.begin(), process_command_line.end(),
                     '\0', ' ');
        information << l10n::text(l10n::Key::EngineCmdline)
                    << process_command_line << '\n';
        response = information.str();
      }
    } else if (command == "errno") {
      lldb::SBFrame frame = selected_frame(process);
      lldb::SBValue value = frame.EvaluateExpression("(int)errno");
      if (!value.IsValid() || value.GetError().Fail()) {
        response = error_response(
            l10n::text(l10n::Key::EngineErrorUnableToReadDebuggeeErrno));
      } else {
        const int error_number = static_cast<int>(value.GetValueAsSigned());
        response = std::to_string(error_number) + " (" +
                   std::strerror(error_number) + ')';
      }
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
        response = error_response(l10n::text(
            l10n::Key::EngineErrorSelectTheProcessExecutableBeforeAttach));
      } else {
        lldb::SBError attach_error;
        process = target.AttachToProcessWithID(
            listener, static_cast<lldb::pid_t>(*process_id), attach_error);
        if (attach_error.Fail() || !process.IsValid()) {
          state.error = error_text(attach_error);
          response = error_detail(state.error);
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
          response = error_response(
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
        response = error_response(l10n::text(
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
          response = error_detail(state.error);
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
        response = error_response(
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
    } else if (command == "g" || command == "go" || command == "c" ||
               command == "continue") {
      response = continue_impl();
    } else if (command == "pause" || command == "breakin") {
      response = stop_impl();
    } else if (command == "dump" || command == "x") {
      std::string failure;
      const auto address = resolve_address(arguments, process, failure);
      response = address ? dump_memory_impl(*address) : error_detail(failure);
    } else if (command == "t" || command == "step" || command == "p" ||
               command == "next" || command == "ti" || command == "si" ||
               command == "stepi" || command == "pi" || command == "ni" ||
               command == "nexti") {
      if (state.state != SessionState::Stopped || !process.IsValid()) {
        response = error_response(
            l10n::text(l10n::Key::EngineErrorSteppingRequiresAStoppedProcess));
      } else {
        lldb::SBThread thread = process.GetSelectedThread();
        if (!thread.IsValid()) {
          response = error_response(
              l10n::text(l10n::Key::EngineErrorNoSelectedThread));
        } else {
          lldb::SBError step_error;
          if (command == "t" || command == "step") {
            thread.StepInto();
          } else if (command == "p" || command == "next") {
            thread.StepOver();
          } else {
            const bool step_over =
                command == "pi" || command == "ni" || command == "nexti";
            thread.StepInstruction(step_over, step_error);
          }
          if (step_error.Fail()) {
            response = error_detail(error_text(step_error));
          } else {
            state.state = SessionState::Running;
            state.crash = {};
            state.error.clear();
            response = l10n::text(l10n::Key::EngineStepping);
          }
        }
      }
    } else if (command == "r" || command == "reg" || command == "regs" ||
               command == "registers") {
      if (state.state != SessionState::Stopped || !process.IsValid()) {
        response = error_response(
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
          response = error_response(
              l10n::text(l10n::Key::EngineErrorRegisterNotFound));
        } else if (new_value.empty()) {
          response = name + " = " + safe_string(value.GetValue());
        } else {
          lldb::SBError write_error;
          const std::string value_text{new_value};
          if (!value.SetValueFromCString(value_text.c_str(), write_error)) {
            response = error_detail(error_text(write_error));
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
        response = error_response(l10n::text(
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
               (arguments == "connect" ||
                arguments.starts_with("connect "))) {
      std::string endpoint{arguments.substr(std::string_view{"connect"}.size())};
      while (!endpoint.empty() &&
             std::isspace(static_cast<unsigned char>(endpoint.front())) != 0) {
        endpoint.erase(endpoint.begin());
      }
      if (endpoint.empty()) {
        response = error_response(
            l10n::text(l10n::Key::EngineErrorProcessConnectRequiresAnEndpoint));
      } else if (!target.IsValid()) {
        response = error_response(
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
          response = error_detail(state.error);
        } else if (connect_error.Fail() || !process.IsValid()) {
          state.state = SessionState::Error;
          state.error = error_text(connect_error);
          response = error_detail(state.error);
        } else {
          synchronize_after_lldb_command(true);
          state.error.clear();
          response = l10n::text(l10n::Key::EngineConnected);
        }
      }
    } else if (command == "?") {
      lldb::SBFrame frame = selected_frame(process);
      if (!frame.IsValid()) {
        response = error_response(l10n::text(
            l10n::Key::EngineErrorExpressionEvaluationRequiresAFrame));
      } else {
        const std::string expression{arguments};
        lldb::SBValue value = frame.EvaluateExpression(expression.c_str());
        const lldb::SBError expression_error = value.GetError();
        response = expression_error.Fail()
                       ? error_detail(error_text(expression_error))
                       : safe_string(value.GetValue());
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
            listener, static_cast<lldb::pid_t>(command.value), attach_error),
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
        if (options.endpoint.empty()) {
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
        state.security =
            state.local_symbol_path.empty()
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
        if (endpoint.find("://") == std::string::npos) {
          endpoint.insert(0, "connect://");
        }
        state.state = SessionState::Connecting;
        publish();
        lldb::SBError connect_error;
        connect_remote_process(endpoint, connect_error);
        if (shutdown_requested_.load()) {
          state.error = l10n::text(l10n::Key::EngineRemoteConnectionCancelled);
          break;
        }
        if (connect_error.Fail() || !process.IsValid()) {
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
        continue_impl();
        publish();
        break;
      case CommandKind::Stop:
        stop_impl();
        publish();
        break;
      case CommandKind::StepInstruction:
        step_instruction_impl(command.enabled);
        publish();
        break;
      case CommandKind::RunToAddress:
        run_to_address_impl(command.value);
        publish();
        break;
      case CommandKind::Terminate:
        terminate_impl();
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
          command_message = error_response(l10n::text(
              l10n::Key::
                  EngineErrorMemoryWriteSizeMustBeBetween1And16777216Bytes));
        } else {
          command_message = apply_patch(command.value, command.bytes);
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
          lldb::SBValue value =
              frame.EvaluateExpression(command.argument.c_str());
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
      }
      publish();
    }

    if (append_process_output(process, state)) {
      publish();
    }

    std::unique_lock lock{mutex_};
    wake_.wait_for(lock, 10ms, [this] { return !commands_.empty(); });
  }

  save_session();
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
