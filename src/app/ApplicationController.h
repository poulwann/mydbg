#pragma once

#include "backend/decompiler/DecompilerEngine.h"
#include "backend/lldb/LldbEngine.h"
#include "scripting/PythonRuntime.h"

namespace mydbg::app {

struct UiState;

void initialize_application(const char *initial_executable,
                            const char *initial_script,
                            debugger::LldbEngine &engine,
                            debugger::scripting::PythonRuntime &python,
                            UiState &ui);
void update_application_session(debugger::SessionSnapshot &snapshot,
                                debugger::SessionStore &sessions, UiState &ui);
bool synchronize_application_theme(const debugger::SessionSnapshot &snapshot,
                                   UiState &ui);
void update_application_selection(const debugger::SessionSnapshot &snapshot,
                                  UiState &ui);
std::shared_ptr<const debugger::DecompilerSnapshot>
update_application_decompiler(const debugger::SessionSnapshot &snapshot,
                              debugger::DecompilerEngine &decompiler,
                              UiState &ui);

} // namespace mydbg::app
