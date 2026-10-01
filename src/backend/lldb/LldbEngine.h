#pragma once

#include "backend/DebuggerTypes.h"

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
#include <sys/types.h>
#include <thread>
#include <vector>

namespace debugger {

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
  // Stable facade storage; QemuProcess exclusively owns its lifecycle on the
  // worker. Keep these slots in place for native clients allocating the facade.
  pid_t qemu_pid_{-1};
  int qemu_stdin_fd_{-1};
  int qemu_stdout_fd_{-1};
  // Main-image ELF symbols (name, value) for engine-side breakpoint
  // resolution on remote sessions (lazy cache keyed by the symbol file path).
  std::vector<std::pair<std::string, std::uint64_t>> main_symbols_;
  std::string main_symbols_path_;
  SessionSnapshot snapshot_;
  std::shared_ptr<SessionStore> sessions_;
  std::unique_ptr<WorkerControl> worker_control_;
  std::thread worker_;
};

} // namespace debugger
