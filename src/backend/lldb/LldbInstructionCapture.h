#pragma once

#include "backend/DebuggerTypes.h"
#include <lldb/API/LLDB.h>

namespace debugger::lldb_detail {

// Instruction bytes, debug metadata, operand analysis and CFG construction
// share one capture boundary. Rizin and its capture-local caches remain private
// here.
void capture_instructions(lldb::SBTarget &target, lldb::addr_t start_address,
                          SessionSnapshot &state);
void capture_disassembly_graph(lldb::SBTarget &target,
                               lldb::addr_t requested_address,
                               SessionSnapshot &state);

} // namespace debugger::lldb_detail
