#pragma once

#include <memory>

namespace debugger {
class DecompilerEngine;
class LldbEngine;
struct DecompilerSnapshot;
struct SessionSnapshot;
} // namespace debugger

namespace mydbg::app {

struct UiState;

void draw_decompiler_panel(
    const debugger::SessionSnapshot &snapshot,
    const std::shared_ptr<const debugger::DecompilerSnapshot> &decompiled,
    debugger::DecompilerEngine &decompiler, debugger::LldbEngine &engine,
    UiState &ui, bool control_lease);

} // namespace mydbg::app
