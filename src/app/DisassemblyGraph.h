#pragma once

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
} // namespace debugger

namespace mydbg::app {

struct UiState;

void draw_disassembly_graph(const debugger::SessionSnapshot &snapshot,
                            debugger::LldbEngine &engine, UiState &ui,
                            bool control_lease);

} // namespace mydbg::app
