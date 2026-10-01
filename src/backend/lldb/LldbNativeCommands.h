#pragma once

#include "backend/DebuggerTypes.h"
#include <lldb/API/LLDB.h>

namespace debugger::lldb_detail {

// A disengaged result means the command is not owned by that handler, not that
// it failed. Failure remains separate from the (possibly empty) response text.
std::optional<std::string>
execute_inspection_command(std::string_view command, std::string_view arguments,
                           lldb::SBTarget &target, lldb::SBProcess &process,
                           const SessionSnapshot &state, bool &failed);
std::optional<std::string>
execute_heap_command(std::string_view command, std::string_view arguments,
                     lldb::SBTarget &target, lldb::SBProcess &process,
                     const SessionSnapshot &state, bool &failed);
std::optional<std::string>
execute_flow_command(std::string_view command, std::string_view arguments,
                     lldb::SBTarget &target, lldb::SBProcess &process,
                     SessionSnapshot &state, bool &failed);
std::string continue_process(lldb::SBTarget &target, lldb::SBProcess &process,
                             SessionSnapshot &state, bool &failed);
std::string pause_process(lldb::SBProcess &process, SessionSnapshot &state,
                          bool &failed);
std::string run_to_address(lldb::addr_t address, lldb::SBProcess &process,
                           SessionSnapshot &state, bool &failed);
std::string terminate_process(lldb::SBProcess &process, SessionSnapshot &state,
                              bool &failed);
std::string
render_console_context(const SessionSnapshot &state,
                       const std::vector<std::string> &context_sections,
                       std::string_view requested_section);

// The worker owns one patch editor across generations; active patches live in
// the session snapshot, while ID allocation and transactional edits live here.
class PatchCommands final {
public:
  std::optional<std::string> execute(std::string_view command,
                                     std::string_view arguments,
                                     lldb::SBTarget &target,
                                     lldb::SBProcess &process,
                                     SessionSnapshot &state, bool &failed);

  std::string apply_patch(lldb::addr_t address,
                          const std::vector<std::uint8_t> &replacement,
                          lldb::SBTarget &target, lldb::SBProcess &process,
                          SessionSnapshot &state, bool &failed);

private:
  std::uint32_t next_patch_id_{1};
};

class NativeCommandStatus final {
public:
  explicit NativeCommandStatus(bool &failed) : failed_(failed) {}
  const char *error_response(const char *message);
  std::string error_detail(const std::string &message);

private:
  bool &failed_;
};

} // namespace debugger::lldb_detail
