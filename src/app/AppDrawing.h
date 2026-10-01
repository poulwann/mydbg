#pragma once

#include "backend/DebuggerTypes.h"
#include "backend/decompiler/DecompilerEngine.h"
#include "scripting/PythonRuntime.h"

namespace debugger::help {
class HelpSystem;
}

namespace debugger {
class LldbEngine;
}

namespace mydbg::app {

struct UiState;

void dispatch_contextual_shortcuts(
    const debugger::SessionSnapshot &snapshot, debugger::LldbEngine &engine,
    debugger::scripting::PythonRuntime &runtime, UiState &ui,
    const debugger::scripting::ScriptSnapshot &script);
void draw_application_workspace(
    const debugger::SessionSnapshot &snapshot,
    const debugger::scripting::ScriptSnapshot &script,
    const std::shared_ptr<const debugger::DecompilerSnapshot> &decompiled,
    debugger::LldbEngine &engine, debugger::DecompilerEngine &decompiler,
    debugger::scripting::PythonRuntime &python, UiState &ui,
    debugger::help::HelpSystem &help, bool &focus_disassembly_on_first_frame,
    std::uint32_t visibility_before);

} // namespace mydbg::app
