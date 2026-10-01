#pragma once

#include "backend/DebuggerTypes.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace mydbg::app {

struct SessionInputState {
  std::array<char, 4096> executable_path{};
  std::uint64_t attach_process_id{};
  std::array<char, 256> remote_endpoint{};
  int remote_profile{};
  debugger::SessionIdentity observed;
  debugger::SessionStatus status;
  debugger::CommandTicket clear;
  std::string action_message;
  bool remote_endpoint_initialized{};
};

struct CommentState {
  std::optional<std::uint64_t> address;
  std::uint64_t generation{};
  debugger::SessionIdentity session;
  std::array<char, 65537> text{};
  bool editor_requested{};
  debugger::CommandTicket write;
  std::string error;
};

struct BreakpointState {
  std::array<char, 256> specification{};
  std::array<char, 4096> condition{};
  std::optional<std::uint32_t> editing;
  std::optional<std::uint64_t> creating;
  bool condition_editor_requested{};
  std::string condition_error;
};

struct InstructionPatchState {
  std::array<char, 1024> text{};
  std::optional<std::uint64_t> address;
  std::vector<std::uint8_t> original;
  std::uint64_t generation{};
  bool assemble{};
  bool editor_requested{};
  std::string error;
};

struct RegisterState {
  std::string edit_name;
  std::array<char, 4096> edit_text{};
  std::uint64_t edit_revision{};
  bool edit_focus{};
  debugger::CommandTicket write;
  std::string write_name;
  std::string edit_error;
};

struct ScanState {
  std::array<char, 256> binary_string_filter{};
  std::array<char, 128> value_scan_value{};
  int binary_string_minimum_length{4};
  bool binary_string_include_utf16{true};
  debugger::ValueScanType value_scan_type{debugger::ValueScanType::Dword};
  debugger::ValueScanComparison value_scan_comparison{
      debugger::ValueScanComparison::Exact};
  bool value_scan_unknown{};
  bool value_scan_signed{};
  bool value_scan_writable_only{true};
};

struct HistoryState {
  std::optional<std::uint64_t> generation;
  std::optional<std::uint64_t> stop;
};

} // namespace mydbg::app
