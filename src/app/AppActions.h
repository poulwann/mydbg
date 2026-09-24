#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace debugger {
class DecompilerEngine;
class LldbEngine;
struct BreakpointInfo;
struct InstructionRow;
struct ModuleInfo;
struct SessionSnapshot;
namespace plugins {
class PluginLoader;
}
} // namespace debugger

namespace mydbg::app {

struct UiState;
enum class DebugAction : std::size_t;

std::string bytes_as_hex(const std::vector<std::uint8_t> &bytes);
std::optional<std::vector<std::uint8_t>>
parse_hex_byte_text(std::string_view text);
std::optional<std::uint64_t> parse_value(std::string_view text);
void load_plugins(debugger::plugins::PluginLoader &loader);
std::optional<std::uint64_t>
pointer_at(const debugger::SessionSnapshot &snapshot, std::size_t offset);
void follow_memory(debugger::LldbEngine &engine, UiState &ui,
                   std::uint64_t address);
void follow_disassembly(debugger::LldbEngine &engine, UiState &ui,
                        std::uint64_t address);
void reset_navigation_history(UiState &ui);
void show_in_memory_map(UiState &ui, std::uint64_t address);
std::string address_specification(std::uint64_t address);
const debugger::BreakpointInfo *
breakpoint_info_at(const debugger::SessionSnapshot &snapshot,
                   std::uint64_t address);
void request_new_condition_editor(UiState &ui, std::uint64_t address);
void request_existing_condition_editor(
    UiState &ui, const debugger::BreakpointInfo &breakpoint);
void close_condition_editor(UiState &ui);
void request_instruction_patch_editor(
    const debugger::SessionSnapshot &snapshot, UiState &ui,
    const debugger::InstructionRow &instruction, bool assemble);
std::optional<std::uint64_t>
selected_file_address(const debugger::SessionSnapshot &snapshot,
                      const UiState &ui);
const debugger::ModuleInfo *
module_for_address(const debugger::SessionSnapshot &snapshot,
                   std::uint64_t address);
std::optional<std::uint64_t>
load_address_for_file(const debugger::SessionSnapshot &snapshot,
                      std::string_view module_path, std::uint64_t file_address);
void request_decompilation(debugger::DecompilerEngine &decompiler,
                           const debugger::SessionSnapshot &snapshot,
                           std::string executable_path,
                           std::uint64_t file_address,
                           std::uint64_t load_address);
bool can_start_or_continue(const debugger::SessionSnapshot &snapshot,
                           const UiState &ui);
bool can_terminate(const debugger::SessionSnapshot &snapshot);
void start_or_continue(const debugger::SessionSnapshot &snapshot,
                       debugger::LldbEngine &engine, const UiState &ui);
void toggle_cursor_breakpoint(const debugger::SessionSnapshot &snapshot,
                              debugger::LldbEngine &engine, const UiState &ui);
bool debug_action_enabled(DebugAction action,
                          const debugger::SessionSnapshot &snapshot,
                          const UiState &ui);
void execute_debug_action(DebugAction action,
                          const debugger::SessionSnapshot &snapshot,
                          debugger::LldbEngine &engine, const UiState &ui);

enum class AppNavigationTarget {
  None,
  Disassembly,
  Memory,
};

struct AppNavigationResult {
  AppNavigationTarget target{AppNavigationTarget::None};
  std::uint64_t address{};
};

AppNavigationTarget
app_follow_address(const debugger::SessionSnapshot &snapshot,
                   debugger::LldbEngine &engine, UiState &ui,
                   std::uint64_t address);
void app_traverse_navigation_history(const debugger::SessionSnapshot &snapshot,
                                     debugger::LldbEngine &engine, UiState &ui,
                                     bool forward);
void app_request_navigation_dialog(const debugger::SessionSnapshot &snapshot,
                                   UiState &ui, bool decompiler_view);
void app_toggle_navigation_graph(UiState &ui);
bool app_navigation_session_valid(const debugger::SessionSnapshot &snapshot,
                                  const UiState &ui);
AppNavigationResult
app_submit_navigation_address(const debugger::SessionSnapshot &snapshot,
                              debugger::LldbEngine &engine, UiState &ui);
bool app_navigation_address_is_code(const debugger::SessionSnapshot &snapshot,
                                    std::uint64_t address);
bool app_instruction_patch_session_valid(
    const debugger::SessionSnapshot &snapshot, const UiState &ui);
void app_close_instruction_patch_editor(UiState &ui);
bool app_apply_instruction_patch(debugger::LldbEngine &engine, UiState &ui);
void app_select_theme(debugger::LldbEngine &engine, UiState &ui, bool dark);

} // namespace mydbg::app
