#pragma once

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
} // namespace debugger

namespace mydbg::app {

struct UiState;

void draw_memory_panel(const debugger::SessionSnapshot &snapshot,
                       debugger::LldbEngine &engine, UiState &ui);

} // namespace mydbg::app
