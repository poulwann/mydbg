#include "app/ScriptRunner.h"
#include "backend/lldb/LldbEngine.h"
#include "backend/session/SessionStore.h"
#include "localization/Localization.h"
#include "scripting/PythonRuntime.h"

#include <chrono>
#include <cstdio>
#include <memory>

namespace mydbg::app {

int run_headless_script(const char *script_file) {
  const auto sessions = std::make_shared<debugger::SessionStore>(
      debugger::SessionStore::default_directory());
  debugger::LldbEngine engine{sessions};
  debugger::scripting::PythonRuntime runtime{engine};
  if (!runtime.run_file(script_file)) {
    std::fprintf(stderr, l10n::text(l10n::Key::GuiPythonQueueScriptFailed),
                 script_file);
    return 90;
  }
  if (!runtime.wait_for_completion(std::chrono::hours{1})) {
    runtime.stop();
    std::fputs(l10n::text(l10n::Key::GuiPythonHeadlessTimeLimit), stderr);
    return 91;
  }
  const debugger::scripting::ScriptSnapshot result = runtime.snapshot();
  if (!result.output.empty()) {
    std::fwrite(result.output.data(), 1, result.output.size(), stdout);
  }
  if (!result.traceback.empty()) {
    std::fprintf(stderr, "%s\n", result.traceback.c_str());
  }
  return result.status == debugger::scripting::ScriptStatus::Succeeded ? 0 : 92;
}

} // namespace mydbg::app
