#pragma once

#include <pybind11/pybind11.h>

#include <atomic>
#include <memory>

namespace debugger {
class LldbEngine;
}

namespace debugger::scripting {

void install_python_bindings();

[[nodiscard]] pybind11::object
make_python_debugger(LldbEngine &engine,
                     std::shared_ptr<std::atomic_bool> cancellation);

} // namespace debugger::scripting
