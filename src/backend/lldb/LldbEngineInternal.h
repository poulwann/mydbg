#pragma once

#include "backend/lldb/LldbEngine.h"
#include "backend/conditions/BreakpointCondition.h"
#include "plugins/PluginApi.h"

#include <elf.h>
#include <lldb/API/LLDB.h>
#include <rz_analysis.h>
#include <rz_asm.h>

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <unordered_set>
#include <utility>


namespace debugger::lldb_detail {

struct ElfLoadSegment {
  std::uint64_t file_offset{};
  std::uint64_t file_size{};
  std::uint64_t virtual_address{};
};

struct BinaryImage {
  std::vector<std::uint8_t> bytes;
  std::vector<ElfLoadSegment> load_segments;
  bool big_endian{};
};

using ScanValueBytes = std::array<std::uint8_t, sizeof(std::uint64_t)>;

struct ValueScanCandidate {
  std::uint64_t address{};
  ScanValueBytes previous{};
  ScanValueBytes current{};
};

std::string safe_string(const char *value);
std::string error_text(const lldb::SBError &error);
std::string byte_order_name(lldb::ByteOrder byte_order);
bool is_x86_architecture(std::string_view architecture);
bool is_inspectable_stop(lldb::StateType state);
bool should_destroy(lldb::StateType state);
std::string_view trim(std::string_view text);
std::string lowercase(std::string_view text);
std::optional<std::uint64_t> parse_integer(std::string_view text);
std::vector<std::string> split_arguments(std::string_view text);
std::string cyclic_pattern(std::size_t length);
std::optional<std::vector<std::uint8_t>>
parse_hex_bytes(std::string_view text);
std::optional<std::vector<std::uint8_t>>
assemble_intel_instruction(std::string_view instruction, std::uint64_t address,
                           std::string_view architecture,
                           std::uint32_t address_byte_size,
                           std::string &failure);
std::optional<std::vector<std::uint8_t>>
read_memory_bytes(lldb::SBProcess &process, lldb::addr_t address,
                  std::size_t size, std::string &failure);
std::string format_hexdump(lldb::addr_t address,
                           const std::vector<std::uint8_t> &bytes);
ElfSecurityInfo inspect_elf_security(const std::filesystem::path &path);

std::optional<BinaryImage> read_binary_image(const std::filesystem::path &path,
                                             std::string &error);
std::optional<std::uint64_t>
file_address_for_offset(const BinaryImage &image, std::uint64_t file_offset);
bool is_binary_string_character(std::uint8_t value);
std::vector<BinaryStringInfo> extract_binary_strings(
    const BinaryImage &image, std::size_t minimum_length, bool include_utf16,
    std::size_t &total, bool &truncated);
std::size_t value_scan_width(ValueScanType type);
std::uint64_t decode_scan_unsigned(const ScanValueBytes &bytes,
                                   std::size_t width, bool big_endian);
std::int64_t decode_scan_signed(const ScanValueBytes &bytes, std::size_t width,
                                bool big_endian);
void encode_scan_unsigned(std::uint64_t value, std::size_t width,
                          bool big_endian, ScanValueBytes &bytes);
std::optional<ScanValueBytes>
parse_scan_value(std::string_view text, ValueScanType type, bool signed_values,
                 bool big_endian, std::string &error);
double decode_scan_float(const ScanValueBytes &bytes, ValueScanType type,
                         bool big_endian);
int compare_scan_values(const ScanValueBytes &left, const ScanValueBytes &right,
                        ValueScanType type, bool signed_values,
                        bool big_endian);
std::string format_scan_value(const ScanValueBytes &bytes, ValueScanType type,
                              bool signed_values, bool big_endian);
const MemoryRegionInfo *region_containing(const SessionSnapshot &state,
                                          std::uint64_t address);
std::string permission_text(const MemoryRegionInfo &region);
std::string register_value_text(lldb::SBValue value);
std::optional<std::uint64_t>
register_value_as_unsigned(lldb::SBValue value);
std::optional<std::vector<std::uint8_t>>
parse_remote_packet_bytes(std::string_view response);
bool is_frameless_qemu_mips_stop(lldb::SBProcess &process,
                                  const SessionSnapshot &state);
std::optional<std::uint64_t> read_frameless_qemu_mips_register(
    lldb::SBTarget &target, const SessionSnapshot &state,
    std::string_view register_name, std::string &failure);
bool write_frameless_qemu_mips_register(
    lldb::SBTarget &target, const SessionSnapshot &state,
    std::string_view register_name, std::uint64_t value,
    std::string &failure);

struct ElfSymbol {
  std::string name;
  std::uint64_t value{};
};

void append_output_chunk(SessionSnapshot &state, std::string_view data,
                         OutputStream stream = OutputStream::Stdout);

std::vector<ElfSymbol> read_elf_symbols(const std::filesystem::path &path);

void collect_matching_sections(lldb::SBSection section, std::string_view wanted,
                               std::vector<lldb::SBSection> &matches);
void append_console(SessionSnapshot &state, std::string_view command,
                    std::string_view response);
void refresh_breakpoints(lldb::SBTarget &target, SessionSnapshot &state);
void capture_memory(lldb::SBProcess &process, lldb::addr_t address,
                    SessionSnapshot &state);
lldb::SBFrame selected_frame(lldb::SBProcess &process);
std::optional<lldb::addr_t> resolve_address(std::string_view expression,
                                            lldb::SBProcess &process,
                                            std::string &failure);
bool append_process_output(lldb::SBProcess &process, SessionSnapshot &state);
std::string module_path(const lldb::SBModule &module);
std::string symbol_for_address(lldb::SBTarget &target,
                               lldb::addr_t load_address);
lldb::addr_t section_end(lldb::SBSection section, lldb::SBTarget &target);
void capture_threads(lldb::SBProcess &process, SessionSnapshot &state);
void capture_memory_regions(lldb::SBTarget &target, lldb::SBProcess &process,
                            SessionSnapshot &state);
void capture_heap(lldb::SBTarget &target, lldb::SBProcess &process,
                  SessionSnapshot &state);
void capture_modules(lldb::SBTarget &target, SessionSnapshot &state);
std::uint64_t decode_pointer(const std::uint8_t *bytes, std::uint32_t size,
                             lldb::ByteOrder byte_order);
std::optional<std::uint64_t> register_numeric(const SessionSnapshot &state,
                                              std::string_view name);
std::vector<PointerChainEntry>
resolve_pointer_chain(lldb::SBTarget &target, lldb::SBProcess &process,
                      const SessionSnapshot &state, std::uint64_t start,
                      std::size_t maximum_depth);
void capture_stack(lldb::SBTarget &target, lldb::SBProcess &process,
                   SessionSnapshot &state);
void capture_instructions(lldb::SBTarget &target, lldb::addr_t start_address,
                          SessionSnapshot &state);
void capture_disassembly_graph(lldb::SBTarget &target,
                               lldb::addr_t requested_address,
                               SessionSnapshot &state);
std::optional<std::uint64_t> fault_address_from_stop(std::string_view text);
void find_cyclic_matches(lldb::SBTarget &target, lldb::SBProcess &process,
                         const SessionSnapshot &state, CrashInfo &crash);
void capture_crash(lldb::SBTarget &target, lldb::SBProcess &process,
                   lldb::SBThread &thread, SessionSnapshot &state);
bool step_frameless_qemu_mips(lldb::SBTarget &target, std::string &failure);
void record_stop_history(SessionSnapshot &state);
void capture_stop(lldb::SBTarget &target, lldb::SBProcess &process,
                  std::optional<lldb::addr_t> memory_view_address,
                  std::optional<lldb::addr_t> instruction_view_address,
                  SessionSnapshot &state);

} // namespace debugger::lldb_detail
