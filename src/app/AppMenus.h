#pragma once

#include <cstdint>

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
namespace help {
class HelpSystem;
}
} // namespace debugger

namespace mydbg::app {

struct UiState;

void draw_navigation_dialog(const debugger::SessionSnapshot &snapshot,
                            debugger::LldbEngine &engine, UiState &ui);
void draw_breakpoint_context_actions(const debugger::SessionSnapshot &snapshot,
                                     debugger::LldbEngine &engine, UiState &ui,
                                     std::uint64_t address);
void draw_pointer_context_actions(const debugger::SessionSnapshot &snapshot,
                                  debugger::LldbEngine &engine, UiState &ui,
                                  std::uint64_t address);
void draw_instruction_patch_editor(const debugger::SessionSnapshot &snapshot,
                                   debugger::LldbEngine &engine, UiState &ui);
void draw_keybindings_settings(UiState &ui);
void draw_debugger_menu(const debugger::SessionSnapshot &snapshot,
                        debugger::LldbEngine &engine, UiState &ui,
                        debugger::help::HelpSystem &help, bool control_lease);

} // namespace mydbg::app
