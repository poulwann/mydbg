#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
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
struct CommentState;
struct SessionInputState;
struct FileDialogState;
struct HistoryState;
struct RegisterState;
struct BreakpointState;

struct DebuggerSessionInput {
  std::string file_dialog_error;
  bool file_dialog_open{};
};

std::string_view trim_view(std::string_view text);

void debugger_request_comment_editor(const debugger::SessionSnapshot &snapshot,
                                     CommentState &state, std::uint64_t address,
                                     std::string_view text);

DebuggerSessionInput debugger_sync_session_input(SessionInputState &state,
                                                 FileDialogState &files);

const debugger::StopHistoryEntry *
debugger_selected_history(const debugger::SessionSnapshot &snapshot,
                          const HistoryState &state);

bool debugger_validate_comment(const debugger::SessionSnapshot &snapshot,
                               CommentState &state,
                               const SessionInputState &session,
                               bool control_lease);

bool debugger_complete_comment(CommentState &state);

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

void debugger_complete_register_write(const debugger::SessionSnapshot &snapshot,
                                      RegisterState &state);

void debugger_begin_register_edit(const debugger::SessionSnapshot &snapshot,
                                  RegisterState &state,
                                  const debugger::RegisterValue &value);

void debugger_write_register(debugger::LldbEngine &engine, RegisterState &state,
                             const debugger::RegisterValue &value,
                             std::string text);

void debugger_clear_register(debugger::LldbEngine &engine, RegisterState &state,
                             const debugger::RegisterValue &value);

bool debugger_register_is_integer(const debugger::RegisterValue &value);

std::uint64_t debugger_register_mask(const debugger::RegisterValue &value,
                                     bool integer);

bool debugger_apply_condition(debugger::LldbEngine &engine,
                              BreakpointState &state, bool creating,
                              std::uint32_t breakpoint_id);

} // namespace mydbg::app
