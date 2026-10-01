#pragma once

#include "backend/DebuggerTypes.h"
#include <lldb/API/LLDB.h>

namespace debugger::lldb_detail {

std::optional<std::vector<std::uint8_t>>
parse_remote_packet_bytes(std::string_view response);
bool is_frameless_qemu_mips_stop(lldb::SBProcess &process,
                                 const SessionSnapshot &state);
std::optional<std::uint64_t> read_frameless_qemu_mips_register(
    lldb::SBTarget &target, const SessionSnapshot &state,
    std::string_view register_name, std::string &failure);
bool write_frameless_qemu_mips_register(lldb::SBTarget &target,
                                        const SessionSnapshot &state,
                                        std::string_view register_name,
                                        std::uint64_t value,
                                        std::string &failure);
bool step_frameless_qemu_mips(lldb::SBTarget &target, std::string &failure);
bool step_frameless_qemu_mips_at_breakpoint(lldb::SBTarget &target,
                                            const SessionSnapshot &state,
                                            std::string &failure);
bool capture_frameless_qemu_mips_registers(lldb::SBTarget &target,
                                           SessionSnapshot &state);
void append_powerpc_fallback_frames(lldb::SBTarget &target,
                                    lldb::SBProcess &process,
                                    SessionSnapshot &state);
void append_frameless_qemu_mips_frame(lldb::SBTarget &target,
                                      SessionSnapshot &state);

} // namespace debugger::lldb_detail
