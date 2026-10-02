#pragma once

#include <cstdint>

namespace debugger {
class LldbEngine;
struct SessionSnapshot;
namespace scripting {
class PythonRuntime;
}
} // namespace debugger

namespace mydbg::app {

struct UiState;

void open_rop_at(UiState &ui, std::uint64_t address);
void draw_rop_panel(const debugger::SessionSnapshot &snapshot,
                    debugger::LldbEngine &engine,
                    debugger::scripting::PythonRuntime &runtime, UiState &ui,
                    bool control_lease);

} // namespace mydbg::app
