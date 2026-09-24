#pragma once

#include "backend/decompiler/DecompilerEngine.h"
#include "backend/lldb/LldbEngine.h"
#include "scripting/PythonRuntime.h"

namespace debugger::help {
class HelpSystem;
}

namespace mydbg::app {

struct UiState;

void draw_application_workspace(
    const debugger::SessionSnapshot &snapshot,
    const debugger::scripting::ScriptSnapshot &script,
    const std::shared_ptr<const debugger::DecompilerSnapshot> &decompiled,
    debugger::LldbEngine &engine, debugger::DecompilerEngine &decompiler,
    debugger::scripting::PythonRuntime &python, UiState &ui,
    debugger::help::HelpSystem &help, bool &focus_disassembly_on_first_frame,
    std::uint32_t visibility_before);

} // namespace mydbg::app
