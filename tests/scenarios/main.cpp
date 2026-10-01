#include "Scenarios.h"
#include "scripting/PythonHost.h"

#include <cstdio>
#include <cstring>
#include <exception>

int main(int argc, char **argv) {
  using namespace mydbg::app;
  try {
    debugger::scripting::PythonHost python;
    if (argc == 2 && std::strcmp(argv[1], "--headless-keybindings") == 0) {
      return run_keybinding_headless();
    }
    if ((argc == 3 || argc == 4) && std::strcmp(argv[1], "--headless") == 0) {
      return run_headless(argv[2], argc == 4 ? argv[3] : nullptr);
    }
    if (argc == 3) {
      if (std::strcmp(argv[1], "--headless-condition") == 0) {
        return run_condition_headless(argv[2]);
      }
      if (std::strcmp(argv[1], "--headless-heap") == 0) {
        return run_heap_headless(argv[2]);
      }
      if (std::strcmp(argv[1], "--headless-scans") == 0) {
        return run_scans_headless(argv[2]);
      }
      if (std::strcmp(argv[1], "--headless-intelligence") == 0) {
        return run_stop_intelligence_headless(argv[2]);
      }
    }
    std::fprintf(stderr,
                 "usage: %s --headless-keybindings | --headless ELF [ATTACH] | "
                 "--headless-condition ELF | --headless-heap ELF | "
                 "--headless-scans ELF | --headless-intelligence ELF\n",
                 argv[0]);
    return 1;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "scenario failure: %s\n", error.what());
    return 2;
  }
}
