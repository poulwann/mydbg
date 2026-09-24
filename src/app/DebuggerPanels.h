#pragma once

#include <string>
#include <vector>

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
struct PointerChainEntry;
struct InstructionRow;
} // namespace debugger

namespace mydbg::app {

struct UiState;

void draw_error_text(const std::string &error);

const char *byte_order_text(const std::string &order);

void draw_session_panel(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine, UiState &ui,
                        bool control_lease);

std::string
pointer_chain_text(const std::vector<debugger::PointerChainEntry> &chain);

std::string branch_details_text(const debugger::InstructionRow &instruction);

const char *branch_summary_text(const debugger::InstructionRow &instruction);

void draw_comment_editor(const debugger::SessionSnapshot &snapshot,
                         debugger::LldbEngine &engine, UiState &ui,
                         bool control_lease);

void draw_instruction_context_actions(
    const debugger::SessionSnapshot &snapshot, debugger::LldbEngine &engine,
    UiState &ui, const debugger::InstructionRow &instruction,
    bool control_lease);

void draw_disassembly_panel(const debugger::SessionSnapshot &snapshot,
                            debugger::LldbEngine &engine, UiState &ui,
                            bool control_lease);

void draw_threads_panel(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine, UiState &ui);

void draw_backtrace_panel(const debugger::SessionSnapshot &snapshot,
                          debugger::LldbEngine &engine, UiState &ui);

void draw_stack_panel(const debugger::SessionSnapshot &snapshot,
                      debugger::LldbEngine &engine, UiState &ui);

void draw_heap_panel(const debugger::SessionSnapshot &snapshot,
                     debugger::LldbEngine &engine, UiState &ui);

void draw_memory_map_panel(const debugger::SessionSnapshot &snapshot,
                           debugger::LldbEngine &engine, UiState &ui);

void draw_modules_panel(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine, UiState &ui);

void draw_security_panel(const debugger::SessionSnapshot &snapshot,
                         UiState &ui);

void draw_register_panel(const debugger::SessionSnapshot &snapshot,
                         debugger::LldbEngine &engine, UiState &ui);

void draw_breakpoints_panel(const debugger::SessionSnapshot &snapshot,
                            debugger::LldbEngine &engine, UiState &ui);

void draw_scans_panel(const debugger::SessionSnapshot &snapshot,
                      debugger::LldbEngine &engine, UiState &ui);

} // namespace mydbg::app
