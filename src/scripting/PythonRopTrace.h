#pragma once

#include "scripting/RopTrace.h"

#include <atomic>
#include <memory>

namespace debugger {
class LldbEngine;
}

namespace debugger::scripting {

// Called only by PythonRuntime's exclusive worker. Acquires the GIL and
// converts all Python values and exceptions before releasing it.
[[nodiscard]] std::shared_ptr<const RopTrace>
run_rop_trace(LldbEngine &engine, const RopTraceRequest &request,
              const std::shared_ptr<std::atomic_bool> &cancellation);

} // namespace debugger::scripting
