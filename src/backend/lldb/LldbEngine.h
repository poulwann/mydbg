#pragma once

#include "backend/session/SessionStore.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace debugger {

enum class SessionState {
  Initializing,
  NoTarget,
  TargetLoaded,
  Launching,
  Connecting,
  Running,
  Stopped,
  Exited,
  Error,
  ShuttingDown,
};

enum class SessionMode {
  Local,
  Remote,
  QemuUser,
  QemuSystem,
};

struct PointerChainEntry {
  std::uint64_t address{};
  std::uint64_t value{};
  bool readable{};
  std::string mapping;
  std::string symbol;
  std::string error;
};

struct RegisterValue {
  std::string name;
  std::string value;
  std::uint64_t byte_size{};
  std::string previous_value;
  std::uint64_t numeric_value{};
  bool has_numeric_value{};
  bool changed{};
  std::vector<PointerChainEntry> pointer_chain;
};

enum class InstructionFlowKind {
  Other,
  Call,
  Return,
  Jump,
  ConditionalJump,
  Syscall,
};

struct ResolvedOperandInfo {
  std::string role;
  std::string expression;
  std::uint64_t value{};
  bool has_value{};
  bool memory{};
  std::vector<PointerChainEntry> pointer_chain;
  std::string error;
};

struct BranchPrediction {
  bool conditional{};
  bool available{};
  bool taken{};
  std::uint64_t taken_target{};
  std::uint64_t fallthrough_target{};
  std::string explanation;
};

struct AbiArgumentInfo {
  std::string name;
  std::uint64_t value{};
  bool available{};
  std::vector<PointerChainEntry> pointer_chain;
  std::string error;
};

struct DebugSourceLocation {
  std::string path;
  std::uint32_t line{};
  std::uint32_t column{};

  bool operator==(const DebugSourceLocation &) const = default;
};

// Declarations only: no ABI slot or variable location is inferred from DWARF.
struct DebugDeclaration {
  std::string name;
  std::string type;
  bool parameter{};

  bool operator==(const DebugDeclaration &) const = default;
};

struct DebugFunctionInfo {
  std::optional<std::uint64_t> address;
  std::string name;
  std::string type;
  std::vector<DebugDeclaration> parameters;

  bool operator==(const DebugFunctionInfo &) const = default;
};

struct DebugScopeInfo {
  std::shared_ptr<const DebugFunctionInfo> function;
  std::shared_ptr<const DebugScopeInfo> parent;
  std::vector<DebugDeclaration> declarations;
  std::string inline_name;
  DebugSourceLocation inline_call_site;
};

struct InstructionReference {
  std::uint64_t address{};
  std::string symbol;
  std::string preview;
  bool runtime{};
  DebugDeclaration declaration;
  std::shared_ptr<const DebugFunctionInfo> function;
};

struct InstructionRow {
  std::uint64_t address{};
  std::uint64_t file_address{};
  bool has_file_address{};
  std::vector<std::uint8_t> bytes;
  std::string mnemonic;
  std::string operands;
  std::string comment;
  std::string user_comment;
  std::vector<InstructionReference> references;
  InstructionFlowKind flow_kind{InstructionFlowKind::Other};
  // Decoded load address; indirect targets require a resolved operand.
  std::optional<std::uint64_t> flow_target;
  std::vector<ResolvedOperandInfo> resolved_operands;
  BranchPrediction branch;
  std::vector<AbiArgumentInfo> arguments;
  std::shared_ptr<const DebugSourceLocation> source;
  std::shared_ptr<const DebugScopeInfo> debug_scope;
  bool begins_source{};
  bool begins_function{};
  bool begins_debug_scope{};
};

struct DisassemblyGraphEdge {
  enum class Kind { Jump, Taken, Fallthrough };
  Kind kind{Kind::Jump};
  std::optional<std::uint64_t> target;
};

struct DisassemblyGraphBlock {
  std::uint64_t address{};
  std::vector<InstructionRow> instructions;
  std::vector<DisassemblyGraphEdge> edges;
};

struct DisassemblyGraph {
  std::uint64_t address{};
  std::string name;
  std::string status;
  std::vector<DisassemblyGraphBlock> blocks;
};

struct BreakpointInfo {
  std::uint32_t id{};
  bool enabled{};
  std::uint32_t hit_count{};
  std::string description;
  std::string condition;
  std::string script_condition;
  std::string script_error;
  std::vector<std::uint64_t> addresses;
};

struct StackFrameInfo {
  std::uint64_t thread_id{};
  std::uint32_t index{};
  bool selected{};
  std::uint64_t pc{};
  std::uint64_t sp{};
  std::string function;
  std::string module;
  std::string source_path;
  std::uint32_t source_line{};
};

struct ThreadInfo {
  std::uint64_t id{};
  std::uint32_t index{};
  bool selected{};
  std::string name;
  std::string stop_reason;
  std::vector<StackFrameInfo> frames;
};

struct MemoryRegionInfo {
  std::uint64_t start{};
  std::uint64_t end{};
  bool readable{};
  bool writable{};
  bool executable{};
  std::string name;
};

struct ModuleInfo {
  std::uint64_t base{};
  std::uint64_t end{};
  std::uint64_t load_bias{};
  bool has_load_bias{};
  std::string path;
  std::string uuid;
  // LLDB's resolved local symbol file, distinct from the module identity.
  std::string debug_info_path;
};

struct StackEntry {
  std::uint64_t address{};
  std::uint64_t value{};
  std::string symbol;
  std::vector<PointerChainEntry> pointer_chain;
};

struct HeapChunkInfo {
  std::uint64_t address{};
  std::uint64_t previous_size{};
  std::uint64_t size{};
  std::uint64_t flags{};
  bool in_use{};
  std::uint64_t forward{};
  std::uint64_t backward{};
};

struct ElfSecurityInfo {
  bool available{};
  bool pie{};
  bool nx{};
  bool relro{};
  bool full_relro{};
  bool stack_canary{};
  bool stripped{};
};

struct PatchInfo {
  std::uint32_t id{};
  std::uint64_t address{};
  std::vector<std::uint8_t> original;
  std::vector<std::uint8_t> replacement;
};

struct WatchInfo {
  std::string expression;
  std::string value;
  std::string error;
};

enum class ValueScanType {
  Byte,
  Word,
  Dword,
  Qword,
  Float,
  Double,
};

enum class ValueScanComparison {
  Exact,
  Changed,
  Unchanged,
  Increased,
  Decreased,
};

struct BinaryStringInfo {
  std::uint64_t file_offset{};
  std::uint64_t file_address{};
  std::uint64_t load_address{};
  bool has_file_address{};
  bool has_load_address{};
  std::string encoding;
  std::string value;
};

struct ValueScanResult {
  std::uint64_t address{};
  std::string previous_value;
  std::string current_value;
  std::string region;
};

enum class LaunchStopPolicy {
  Main,
  Entry,
  None,
};

struct LaunchOptions {
  std::string executable{};
  std::vector<std::string> arguments{};
  std::vector<std::string> environment{};
  std::string working_directory{};
  LaunchStopPolicy stop_policy{LaunchStopPolicy::Main};
};

struct RemoteOptions {
  std::string executable{};
  std::string endpoint{};
  SessionMode mode{SessionMode::Remote};
};

enum class OutputStream {
  Stdout,
  Stderr,
};

struct OutputChunk {
  std::uint64_t sequence{};
  OutputStream stream{OutputStream::Stdout};
  std::string data;
};

struct CyclicMatch {
  std::string source;
  std::uint64_t address{};
  bool has_address{};
  std::size_t offset{};
  std::string bytes;
};

struct CrashInfo {
  bool crashed{};
  std::uint32_t signal_number{};
  std::string signal_name;
  std::uint64_t fault_address{};
  bool has_fault_address{};
  bool stack_executable{};
  bool control_flow_suspect{};
  std::string summary;
  std::vector<CyclicMatch> cyclic_matches;
};

struct StopHistoryEntry {
  std::uint64_t generation{};
  std::uint64_t stop_revision{};
  std::uint64_t thread_id{};
  std::uint64_t pc{};
  std::uint64_t sp{};
  std::string stop_reason;
  std::vector<RegisterValue> registers;
};

struct SessionSnapshot {
  SessionState state{SessionState::Initializing};
  SessionMode mode{SessionMode::Local};
  std::uint64_t revision{};
  std::uint64_t generation{};
  std::uint64_t stop_revision{};
  std::string target_path;
  std::string local_symbol_path;
  SessionIdentity session;
  std::string session_error;
  std::uint64_t session_analysis_revision{};
  bool process_is_remote{};
  std::string target_triple;
  std::string architecture;
  std::string byte_order;
  std::uint32_t address_byte_size{};
  bool supports_intel_syntax{};
  bool intel_syntax{true};
  std::uint64_t process_id{};
  std::uint64_t thread_id{};
  std::uint64_t pc{};
  std::uint64_t pc_file_address{};
  std::uint64_t pc_module_load_bias{};
  bool has_pc_file_address{};
  std::string pc_module_path;
  std::uint64_t sp{};
  std::uint64_t memory_base{};
  std::vector<std::uint8_t> memory;
  std::vector<RegisterValue> registers;
  std::vector<InstructionRow> instructions;
  std::shared_ptr<const DisassemblyGraph> disassembly_graph;
  std::vector<BreakpointInfo> breakpoints;
  std::vector<ThreadInfo> threads;
  std::vector<MemoryRegionInfo> memory_regions;
  std::vector<ModuleInfo> modules;
  std::vector<StackEntry> stack;
  std::vector<HeapChunkInfo> heap_chunks;
  std::string heap_error;
  std::vector<PatchInfo> patches;
  std::vector<WatchInfo> watches;
  CrashInfo crash;
  std::deque<StopHistoryEntry> stop_history;
  ElfSecurityInfo security;
  std::vector<BinaryStringInfo> binary_strings;
  std::size_t binary_string_count{};
  bool binary_strings_truncated{};
  std::string binary_strings_error;
  std::vector<ValueScanResult> value_scan_results;
  std::size_t value_scan_match_count{};
  std::uint64_t value_scan_revision{};
  bool value_scan_active{};
  bool value_scan_truncated{};
  ValueScanType value_scan_type{ValueScanType::Dword};
  bool value_scan_signed{};
  bool value_scan_writable_only{true};
  std::string value_scan_error;
  bool theme_dark{true};
  std::string stop_reason;
  std::string process_output;
  std::deque<OutputChunk> output_chunks;
  std::size_t output_chunk_bytes{};
  std::uint64_t output_sequence{};
  std::string console_output;
  std::string error;
  int exit_status{};
};

using CommandId = std::uint64_t;

struct CommandResult {
  CommandId id{};
  bool success{};
  std::string message;
  std::uint64_t snapshot_revision{};
  std::uint64_t generation{};
  std::uint64_t stop_revision{};
  std::vector<std::uint8_t> bytes{};
  std::string value{};
  std::string type{};
  std::string summary{};
  std::uint64_t numeric_value{};
  bool has_numeric_value{};
};

class CommandTicket final {
public:
  CommandTicket() = default;

  [[nodiscard]] CommandId id() const noexcept { return id_; }
  [[nodiscard]] bool valid() const noexcept { return result_.valid(); }
  [[nodiscard]] bool wait_for(std::chrono::milliseconds timeout) const;
  [[nodiscard]] CommandResult get() const;

private:
  friend class LldbEngine;
  CommandTicket(CommandId id, std::shared_future<CommandResult> result)
      : id_(id), result_(std::move(result)) {}

  CommandId id_{};
  std::shared_future<CommandResult> result_;
};

class LldbEngine final {
public:
  explicit LldbEngine(std::shared_ptr<SessionStore> sessions = {});
  ~LldbEngine();

  LldbEngine(const LldbEngine &) = delete;
  LldbEngine &operator=(const LldbEngine &) = delete;

  CommandTicket load(std::string executable);
  CommandTicket launch(std::string executable);
  CommandTicket launch(LaunchOptions options);
  CommandTicket attach(std::uint64_t process_id);
  CommandTicket connect_remote(RemoteOptions options);
  CommandTicket detach();
  CommandTicket continue_execution();
  CommandTicket stop();
  CommandTicket step_instruction(bool step_over);
  CommandTicket read_instructions(std::uint64_t address);
  CommandTicket run_to_address(std::uint64_t address);
  CommandTicket terminate();
  CommandTicket set_breakpoint(std::string specification);
  CommandTicket set_conditional_breakpoint(std::string specification,
                                           std::string condition);
  CommandTicket remove_breakpoint(std::uint32_t id);
  CommandTicket set_breakpoint_enabled(std::uint32_t id, bool enabled);
  CommandTicket set_breakpoint_script(std::uint32_t id, std::string condition);
  CommandTicket clear_saved_session(std::string expected_sha256);
  CommandTicket set_comment(std::uint64_t load_address, std::string text,
                            std::uint64_t expected_generation);
  CommandTicket read_memory(std::uint64_t address);
  CommandTicket read_memory(std::uint64_t address, std::size_t size);
  CommandTicket write_memory(std::uint64_t address,
                             std::vector<std::uint8_t> bytes);
  CommandTicket evaluate(std::string expression);
  CommandTicket read_register(std::string name);
  CommandTicket write_register(std::string name, std::uint64_t value);
  CommandTicket write_register(std::string name, std::string value);
  CommandTicket send_stdin(std::string bytes);
  CommandTicket select_thread(std::uint64_t thread_id);
  CommandTicket select_frame(std::uint64_t thread_id,
                             std::uint32_t frame_index);
  CommandTicket execute_command(std::string command);
  CommandTicket set_intel_syntax(bool enabled);
  CommandTicket set_disassembly_graph_enabled(bool enabled);
  CommandTicket scan_binary_strings(std::uint32_t minimum_length,
                                    bool include_utf16);
  CommandTicket start_value_scan(ValueScanType type, std::string value,
                                 bool unknown, bool signed_values,
                                 bool writable_only);
  CommandTicket next_value_scan(ValueScanComparison comparison,
                                std::string value);
  CommandTicket reset_value_scan();

  [[nodiscard]] SessionSnapshot snapshot() const;
  [[nodiscard]] std::optional<SessionSnapshot>
  wait_for_update(std::uint64_t after_revision,
                  std::chrono::milliseconds timeout) const;

private:
  enum class CommandKind {
    Load,
    Launch,
    Attach,
    ConnectRemote,
    Detach,
    Continue,
    Stop,
    StepInstruction,
    RunToAddress,
    Terminate,
    SetBreakpoint,
    SetConditionalBreakpoint,
    RemoveBreakpoint,
    EnableBreakpoint,
    SetBreakpointScript,
    ClearSavedSession,
    SetComment,
    ReadMemory,
    ReadMemoryBytes,
    WriteMemoryBytes,
    EvaluateExpression,
    ReadRegister,
    WriteRegister,
    SendStdin,
    SelectThread,
    SelectFrame,
    ReadInstructions,
    ExecuteConsole,
    SetDisassemblyStyle,
    SetDisassemblyGraphEnabled,
    ScanBinaryStrings,
    StartValueScan,
    NextValueScan,
    ResetValueScan,
    Shutdown,
  };

  struct Command {
    CommandKind kind;
    CommandId id{};
    std::shared_ptr<std::promise<CommandResult>> completion{};
    std::string argument{};
    LaunchOptions launch_options{};
    std::string argument2{};
    RemoteOptions remote_options{};
    std::uint64_t value{};
    std::uint64_t value2{};
    SessionIdentity expected_session{};
    bool enabled{};
    std::vector<std::uint8_t> bytes{};
    std::string result_value{};
    std::string result_type{};
    std::string result_summary{};
    std::uint64_t result_numeric_value{};
    bool has_result_numeric_value{};
  };

  CommandTicket enqueue(Command command);
  void request_shutdown();
  void run();

  struct WorkerControl;

  mutable std::mutex mutex_;
  std::condition_variable wake_;
  mutable std::condition_variable updated_;
  std::deque<Command> commands_;
  CommandId next_command_id_{1};
  std::atomic_bool shutdown_requested_{false};
  SessionSnapshot snapshot_;
  std::shared_ptr<SessionStore> sessions_;
  std::unique_ptr<WorkerControl> worker_control_;
  std::thread worker_;
};

[[nodiscard]] const char *to_string(SessionState state) noexcept;
[[nodiscard]] const char *to_string(SessionMode mode) noexcept;
[[nodiscard]] std::string_view operand_role_display(std::string_view role);
[[nodiscard]] std::string cyclic_source_display(std::string_view source);

} // namespace debugger
