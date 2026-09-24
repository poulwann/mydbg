#include "app/App.h"
#include "app/GuiApplication.h"
#include "app/Headless.h"
#include "app/ScriptRunner.h"
#include "localization/Localization.h"
#include "scripting/PythonHost.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>

namespace mydbg::app {

int run(int argc, char **argv) {
  if (std::getenv("MYDBG_CTF_CHALLENGE") == nullptr) {
    static_cast<void>(::setenv("MYDBG_CTF_CHALLENGE", MYDBG_CTF_CHALLENGE, 0));
  }
  try {
    debugger::scripting::PythonHost python_host;
    if (argc == 2 && std::strcmp(argv[1], "--headless-keybindings") == 0) {
      return run_keybinding_headless();
    }
    if ((argc == 3 || argc == 4) && std::strcmp(argv[1], "--headless") == 0) {
      return run_headless(argv[2], argc == 4 ? argv[3] : nullptr);
    }
    if (argc == 3 && std::strcmp(argv[1], "--headless-condition") == 0) {
      return run_condition_headless(argv[2]);
    }
    if (argc == 3 && std::strcmp(argv[1], "--headless-heap") == 0) {
      return run_heap_headless(argv[2]);
    }
    if (argc == 3 && std::strcmp(argv[1], "--headless-scans") == 0) {
      return run_scans_headless(argv[2]);
    }
    if (argc == 3 && std::strcmp(argv[1], "--headless-intelligence") == 0) {
      return run_stop_intelligence_headless(argv[2]);
    }
    if (argc == 3 && std::strcmp(argv[1], "--headless-script") == 0) {
      return run_headless_script(argv[2]);
    }
    if (argc == 3 && std::strcmp(argv[1], "--script") == 0) {
      return run_gui(nullptr, argv[2]);
    }
    if (argc > 2) {
      std::fprintf(stderr, l10n::text(l10n::Key::AppUsage), argv[0]);
      return 1;
    }
    return run_gui(argc == 2 ? argv[1] : nullptr, nullptr);
  } catch (const std::exception &error) {
    std::fprintf(stderr, l10n::text(l10n::Key::AppStartupFailure),
                 error.what());
    return 2;
  }
}

} // namespace mydbg::app
