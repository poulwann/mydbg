#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
struct StopHistoryEntry;
struct RegisterValue;
struct InstructionRow;
struct MemoryRegionInfo;
} // namespace debugger

namespace mydbg::app {

struct UiState;

struct DebuggerSessionInput {
  std::string file_dialog_error;
  bool file_dialog_open{};
};

struct DebuggerMemoryPointer {
  std::size_t pointer_width{};
  bool full_pointer{};
  bool known_byte_order{};
  std::optional<std::uint64_t> pointer;
};

std::string_view trim_view(std::string_view text);

void debugger_request_comment_editor(const debugger::SessionSnapshot &snapshot,
                                     UiState &ui, std::uint64_t address,
                                     std::string_view text);

DebuggerSessionInput debugger_sync_session_input(UiState &ui);

const debugger::StopHistoryEntry *
debugger_selected_history(const debugger::SessionSnapshot &snapshot,
                          const UiState &ui);

bool debugger_validate_comment(const debugger::SessionSnapshot &snapshot,
                               UiState &ui, bool control_lease);

bool debugger_complete_comment(UiState &ui);

void debugger_sync_disassembly_mode(const debugger::SessionSnapshot &snapshot,
                                    debugger::LldbEngine &engine, UiState &ui);

std::vector<debugger::InstructionRow>::const_iterator
debugger_disassembly_cursor(const debugger::SessionSnapshot &snapshot,
                            const UiState &ui);

std::vector<debugger::InstructionRow>::const_iterator
debugger_move_disassembly_cursor(
    const debugger::SessionSnapshot &snapshot, UiState &ui,
    std::vector<debugger::InstructionRow>::const_iterator cursor, bool up,
    bool down);

void debugger_follow_memory_region(debugger::LldbEngine &engine, UiState &ui,
                                   const debugger::MemoryRegionInfo &region);

std::optional<std::uint64_t>
debugger_memory_visible_hint_end(const debugger::SessionSnapshot &snapshot,
                                 const UiState &ui);

void debugger_complete_register_write(const debugger::SessionSnapshot &snapshot,
                                      UiState &ui);

void debugger_begin_register_edit(const debugger::SessionSnapshot &snapshot,
                                  UiState &ui,
                                  const debugger::RegisterValue &value);

void debugger_write_register(debugger::LldbEngine &engine, UiState &ui,
                             const debugger::RegisterValue &value,
                             std::string text);

void debugger_clear_register(debugger::LldbEngine &engine, UiState &ui,
                             const debugger::RegisterValue &value);

bool debugger_register_is_integer(const debugger::RegisterValue &value);

std::uint64_t debugger_register_mask(const debugger::RegisterValue &value,
                                     bool integer);

bool debugger_apply_condition(debugger::LldbEngine &engine, UiState &ui,
                              bool creating, std::uint32_t breakpoint_id);

bool debugger_sync_memory_selection(const debugger::SessionSnapshot &snapshot,
                                    UiState &ui);

void debugger_sync_memory_editor(const debugger::SessionSnapshot &snapshot,
                                 UiState &ui, bool dump_changed,
                                 std::size_t editable_count);

void debugger_patch_memory_byte(const debugger::SessionSnapshot &snapshot,
                                debugger::LldbEngine &engine, UiState &ui,
                                std::size_t byte_offset,
                                std::uint64_t byte_address);

bool debugger_memory_address_is_code(const debugger::SessionSnapshot &snapshot,
                                     std::uint64_t address);

std::size_t debugger_memory_selection_start(const UiState &ui);

std::size_t debugger_memory_selection_end(const UiState &ui);

bool debugger_memory_has_selection(const debugger::SessionSnapshot &snapshot,
                                   const UiState &ui);

std::span<const std::uint8_t>
debugger_memory_selected_bytes(const debugger::SessionSnapshot &snapshot,
                               const UiState &ui);

void debugger_select_memory_byte(const debugger::SessionSnapshot &snapshot,
                                 UiState &ui, std::size_t offset, bool extend,
                                 bool editing);

void debugger_select_memory_context(const debugger::SessionSnapshot &snapshot,
                                    UiState &ui, std::size_t offset);

bool debugger_memory_byte_is_patched(const debugger::SessionSnapshot &snapshot,
                                     std::uint64_t byte_address);

DebuggerMemoryPointer
debugger_memory_pointer(const debugger::SessionSnapshot &snapshot,
                        std::size_t first);

} // namespace mydbg::app
