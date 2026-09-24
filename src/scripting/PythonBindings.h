#pragma once

#include "backend/lldb/LldbEngine.h"

#include <pybind11/pybind11.h>

#include <atomic>
#include <memory>

namespace debugger::scripting {

[[nodiscard]] pybind11::object
make_python_debugger(LldbEngine &engine,
                     std::shared_ptr<std::atomic_bool> cancellation);

} // namespace debugger::scripting
