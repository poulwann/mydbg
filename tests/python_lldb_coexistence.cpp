#include "backend/lldb/LldbEngine.h"

#include <pybind11/embed.h>

#include <chrono>
#include <cstdio>
#include <stdexcept>
#include <thread>

namespace py = pybind11;
using namespace std::chrono_literals;

namespace {

void wait_until_ready(debugger::LldbEngine &engine) {
  const auto deadline = std::chrono::steady_clock::now() + 5s;
  while (std::chrono::steady_clock::now() < deadline) {
    const debugger::SessionSnapshot snapshot = engine.snapshot();
    if (snapshot.state == debugger::SessionState::NoTarget) {
      return;
    }
    if (snapshot.state == debugger::SessionState::Error) {
      throw std::runtime_error(snapshot.error);
    }
    std::this_thread::sleep_for(1ms);
  }
  throw std::runtime_error("LLDB engine did not become ready");
}

void exercise_once() {
  py::scoped_interpreter interpreter{};
  {
    py::gil_scoped_release release;
    debugger::LldbEngine engine;
    wait_until_ready(engine);

    std::thread script([] {
      py::gil_scoped_acquire acquire;
      py::dict globals;
      globals["__builtins__"] = py::module_::import("builtins");
      py::exec("def run(value):\n    return value + 1\n", globals);
      if (globals["run"](41).cast<int>() != 42) {
        throw std::runtime_error("embedded Python returned the wrong result");
      }
    });
    script.join();
  }
}

} // namespace

int main() {
  try {
    for (int iteration = 0; iteration < 3; ++iteration) {
      exercise_once();
    }
  } catch (const std::exception &error) {
    std::fprintf(stderr, "coexistence failure: %s\n", error.what());
    return 1;
  }
  return 0;
}
