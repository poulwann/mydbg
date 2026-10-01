#include "backend/lldb/LldbRemoteArchitecture.h"
#include "backend/lldb/LldbEngineInternal.h"
#include "localization/Localization.h"

namespace debugger::lldb_detail {

namespace {

constexpr std::array<std::string_view, 32> mips_general_register_names{
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3", "t0", "t1", "t2",
    "t3",   "t4", "t5", "t6", "t7", "s0", "s1", "s2", "s3", "s4", "s5",
    "s6",   "s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"};

std::optional<std::uint8_t> hex_nibble(char digit) {
  if (digit >= '0' && digit <= '9') {
    return static_cast<std::uint8_t>(digit - '0');
  }
  if (digit >= 'a' && digit <= 'f') {
    return static_cast<std::uint8_t>(digit - 'a' + 10);
  }
  if (digit >= 'A' && digit <= 'F') {
    return static_cast<std::uint8_t>(digit - 'A' + 10);
  }
  return std::nullopt;
}

std::optional<std::string_view>
remote_packet_payload(std::string_view response) {
  constexpr std::string_view marker = "response:";
  const std::size_t marker_position = response.find(marker);
  if (marker_position == std::string_view::npos) {
    return std::nullopt;
  }
  const std::string_view payload =
      trim(response.substr(marker_position + marker.size()));
  return payload.empty() ? std::nullopt
                         : std::optional<std::string_view>{payload};
}

bool is_remote_error_reply(std::string_view payload) {
  return payload.size() == 3 && payload.front() == 'E' &&
         hex_nibble(payload[1]).has_value() &&
         hex_nibble(payload[2]).has_value();
}

std::optional<std::vector<std::uint8_t>>
parse_remote_hex_payload(std::string_view payload) {
  if (payload.empty() || is_remote_error_reply(payload) ||
      payload.size() % 2 != 0) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> bytes;
  bytes.reserve(payload.size() / 2);
  for (std::size_t position = 0; position < payload.size(); position += 2) {
    const auto high = hex_nibble(payload[position]);
    const auto low = hex_nibble(payload[position + 1]);
    if (!high || !low) {
      return std::nullopt;
    }
    bytes.push_back(static_cast<std::uint8_t>((*high << 4U) | *low));
  }
  return bytes;
}

std::optional<std::string> send_remote_packet(lldb::SBTarget &target,
                                              std::string_view packet,
                                              std::string &failure) {
  lldb::SBCommandReturnObject result;
  std::string command = "process plugin packet send ";
  command.append(packet);
  target.GetDebugger().GetCommandInterpreter().HandleCommand(command.c_str(),
                                                             result, false);
  if (!result.Succeeded()) {
    failure = safe_string(result.GetError());
    if (failure.empty()) {
      failure = l10n::text(l10n::Key::SnapshotRemotePacketRejected);
    }
    return std::nullopt;
  }

  const std::string output = safe_string(result.GetOutput());
  const auto payload = remote_packet_payload(output);
  if (!payload) {
    failure = l10n::text(l10n::Key::SnapshotRemotePacketResponseMissing);
    return std::nullopt;
  }
  return std::string{*payload};
}

std::optional<std::vector<std::uint8_t>>
read_remote_packet(lldb::SBTarget &target, std::string_view packet,
                   std::string &failure) {
  const auto payload = send_remote_packet(target, packet, failure);
  if (!payload) {
    return std::nullopt;
  }
  if (is_remote_error_reply(*payload)) {
    failure = l10n::format(l10n::Key::SnapshotRemotePacketRejectedWithResponse,
                           payload->c_str());
    return std::nullopt;
  }
  auto bytes = parse_remote_hex_payload(*payload);
  if (!bytes) {
    failure = l10n::text(l10n::Key::SnapshotRemoteHexDataMalformed);
  }
  return bytes;
}

std::optional<std::uint32_t>
mips_register_number(std::string_view register_name) {
  register_name = trim(register_name);
  if (!register_name.empty() && register_name.front() == '$') {
    register_name.remove_prefix(1);
  }
  const std::string name = lowercase(register_name);
  const auto named = std::find(mips_general_register_names.begin(),
                               mips_general_register_names.end(), name);
  if (named != mips_general_register_names.end()) {
    return static_cast<std::uint32_t>(
        std::distance(mips_general_register_names.begin(), named));
  }
  if (name == "s8") {
    return 30;
  }
  constexpr std::array<std::string_view, 6> special_registers{
      "status", "lo", "hi", "badvaddr", "cause", "pc"};
  if (name == "sr") {
    return 32;
  }
  const auto special =
      std::find(special_registers.begin(), special_registers.end(), name);
  if (special != special_registers.end()) {
    return 32 + static_cast<std::uint32_t>(special - special_registers.begin());
  }

  std::string_view numbered{name};
  if (numbered.starts_with('r')) {
    numbered.remove_prefix(1);
  }
  std::uint32_t number = 0;
  const auto [end, error] = std::from_chars(
      numbered.data(), numbered.data() + numbered.size(), number, 10);
  if (!numbered.empty() && error == std::errc{} &&
      end == numbered.data() + numbered.size() && number < 32) {
    return number;
  }
  return std::nullopt;
}

std::optional<lldb::ByteOrder>
snapshot_byte_order(const SessionSnapshot &state) {
  if (state.byte_order == "little") {
    return lldb::eByteOrderLittle;
  }
  if (state.byte_order == "big") {
    return lldb::eByteOrderBig;
  }
  return std::nullopt;
}

std::string format_register_value(std::uint64_t value) {
  std::ostringstream formatted;
  formatted << "0x" << std::hex << value;
  return formatted.str();
}

std::string remote_register_packet(std::uint32_t number) {
  std::array<char, 8> digits{};
  const auto [end, error] =
      std::to_chars(digits.data(), digits.data() + digits.size(), number, 16);
  if (error != std::errc{}) {
    return {};
  }
  return "p" + std::string{digits.data(), end};
}

} // namespace

bool capture_frameless_qemu_mips_registers(lldb::SBTarget &target,
                                           SessionSnapshot &state) {
  std::string failure;
  const auto pc =
      read_frameless_qemu_mips_register(target, state, "pc", failure);
  if (!pc) {
    return false;
  }

  const auto append_register = [&state](std::string_view name,
                                        std::uint64_t value) {
    state.registers.push_back(RegisterValue{
        .name = std::string{name},
        .value = format_register_value(value),
        .byte_size = state.address_byte_size,
        .previous_value = {},
        .numeric_value = value,
        .has_numeric_value = true,
        .changed = false,
        .pointer_chain = {},
    });
    if (name == "sp") {
      state.sp = value;
    }
  };

  const std::uint32_t register_width = state.address_byte_size;
  const auto byte_order = snapshot_byte_order(state);
  const auto register_block = read_remote_packet(target, "g", failure);
  if (register_width != 0 && register_width <= sizeof(std::uint64_t) &&
      byte_order && register_block &&
      register_block->size() >= mips_general_register_names.size() *
                                    static_cast<std::size_t>(register_width)) {
    for (std::size_t index = 0; index < mips_general_register_names.size();
         ++index) {
      const std::uint64_t value =
          decode_pointer(register_block->data() + index * register_width,
                         register_width, *byte_order);
      append_register(mips_general_register_names[index], value);
    }
  } else {
    for (const std::string_view name : mips_general_register_names) {
      const auto value =
          read_frameless_qemu_mips_register(target, state, name, failure);
      if (!value) {
        continue;
      }
      append_register(name, *value);
    }
  }
  if (!register_numeric(state, "sp")) {
    state.registers.clear();
    state.sp = 0;
    return false;
  }
  state.pc = *pc;
  append_register("pc", state.pc);
  return true;
}

bool step_frameless_qemu_mips(lldb::SBTarget &target, std::string &failure) {
  const auto response = send_remote_packet(target, "s", failure);
  if (!response) {
    return false;
  }
  if (response->empty() ||
      (response->front() != 'S' && response->front() != 'T')) {
    failure = l10n::text(l10n::Key::SnapshotRemoteStepResponseInvalid);
    return false;
  }
  return true;
}

std::optional<std::vector<std::uint8_t>>
parse_remote_packet_bytes(std::string_view response) {
  const auto payload = remote_packet_payload(response);
  return payload ? parse_remote_hex_payload(*payload) : std::nullopt;
}

bool is_frameless_qemu_mips_stop(lldb::SBProcess &process,
                                 const SessionSnapshot &state) {
  return state.state == SessionState::Stopped && process.IsValid() &&
         (state.mode == SessionMode::QemuUser ||
          state.mode == SessionMode::QemuSystem) &&
         state.architecture.starts_with("mips") &&
         !selected_frame(process).IsValid();
}

std::optional<std::uint64_t> read_frameless_qemu_mips_register(
    lldb::SBTarget &target, const SessionSnapshot &state,
    std::string_view register_name, std::string &failure) {
  const auto number = mips_register_number(register_name);
  if (!number) {
    failure = l10n::text(l10n::Key::SnapshotMipsRegisterUnknown);
    return std::nullopt;
  }
  if (state.address_byte_size == 0 ||
      state.address_byte_size > sizeof(std::uint64_t)) {
    failure = l10n::text(l10n::Key::SnapshotMipsRegisterWidthUnavailable);
    return std::nullopt;
  }
  const auto byte_order = snapshot_byte_order(state);
  if (!byte_order) {
    failure = l10n::text(l10n::Key::SnapshotMipsRegisterByteOrderUnavailable);
    return std::nullopt;
  }

  const auto bytes =
      read_remote_packet(target, remote_register_packet(*number), failure);
  if (!bytes) {
    return std::nullopt;
  }
  if (bytes->size() != state.address_byte_size) {
    failure = l10n::text(l10n::Key::SnapshotMipsRegisterWidthUnexpected);
    return std::nullopt;
  }
  return decode_pointer(bytes->data(), state.address_byte_size, *byte_order);
}

bool write_frameless_qemu_mips_register(lldb::SBTarget &target,
                                        const SessionSnapshot &state,
                                        std::string_view register_name,
                                        std::uint64_t value,
                                        std::string &failure) {
  const auto number = mips_register_number(register_name);
  if (!number) {
    failure = l10n::text(l10n::Key::SnapshotMipsRegisterUnknown);
    return false;
  }
  const std::uint32_t width = state.address_byte_size;
  if (width == 0 || width > sizeof(std::uint64_t)) {
    failure = l10n::text(l10n::Key::SnapshotMipsRegisterWidthUnavailable);
    return false;
  }
  const auto byte_order = snapshot_byte_order(state);
  if (!byte_order) {
    failure = l10n::text(l10n::Key::SnapshotMipsRegisterByteOrderUnavailable);
    return false;
  }
  if (width < sizeof(std::uint64_t) &&
      value >= (std::uint64_t{1} << (width * 8U))) {
    failure = l10n::text(l10n::Key::SnapshotMipsRegisterValueOutOfRange);
    return false;
  }

  std::array<char, 8> number_digits{};
  const auto [number_end, number_error] =
      std::to_chars(number_digits.data(),
                    number_digits.data() + number_digits.size(), *number, 16);
  if (number_error != std::errc{}) {
    failure = l10n::text(l10n::Key::SnapshotMipsRegisterNumberEncodingFailed);
    return false;
  }
  std::string packet{"P"};
  packet.append(number_digits.data(), number_end);
  packet.push_back('=');
  constexpr std::string_view hex_digits = "0123456789abcdef";
  for (std::uint32_t index = 0; index < width; ++index) {
    const std::uint32_t byte_index =
        *byte_order == lldb::eByteOrderBig ? width - index - 1 : index;
    const std::uint8_t byte =
        static_cast<std::uint8_t>(value >> (byte_index * 8U));
    packet.push_back(hex_digits[byte >> 4U]);
    packet.push_back(hex_digits[byte & 0x0fU]);
  }

  const auto response = send_remote_packet(target, packet, failure);
  if (!response) {
    return false;
  }
  if (*response == "OK") {
    return true;
  }
  failure =
      is_remote_error_reply(*response)
          ? l10n::format(
                l10n::Key::SnapshotRemoteRegisterWriteRejectedWithResponse,
                response->c_str())
          : l10n::text(l10n::Key::SnapshotRemoteRegisterWriteResponseInvalid);
  return false;
}

void append_powerpc_fallback_frames(lldb::SBTarget &target,
                                    lldb::SBProcess &process,
                                    SessionSnapshot &state) {
  if (!state.architecture.starts_with("powerpc") ||
      state.address_byte_size != 4) {
    return;
  }
  const auto link_register = register_numeric(state, "lr");
  if (!link_register) {
    return;
  }
  const auto byte_order =
      state.byte_order == "big" ? lldb::eByteOrderBig : lldb::eByteOrderLittle;
  const auto read_word =
      [&process,
       byte_order](std::uint64_t address) -> std::optional<std::uint64_t> {
    std::array<std::uint8_t, 4> bytes{};
    lldb::SBError error;
    const std::size_t count =
        process.ReadMemory(address, bytes.data(), bytes.size(), error);
    if (error.Fail() || count != bytes.size()) {
      return std::nullopt;
    }
    return decode_pointer(bytes.data(), 4, byte_order);
  };

  for (ThreadInfo &thread : state.threads) {
    if (!thread.selected || thread.frames.size() != 1) {
      continue;
    }
    std::uint64_t frame_pointer = state.sp;
    for (std::uint32_t depth = 1; depth < 64; ++depth) {
      const auto caller_stack = read_word(frame_pointer);
      if (!caller_stack || *caller_stack <= frame_pointer ||
          (*caller_stack & 3U) != 0) {
        break;
      }
      const auto return_address =
          depth == 1 ? link_register : read_word(*caller_stack + 4);
      if (!return_address || *return_address == 0) {
        break;
      }

      StackFrameInfo frame{
          .thread_id = thread.id,
          .index = depth,
          .selected = false,
          .pc = *return_address,
          .sp = *caller_stack,
          .function = symbol_for_address(target, *return_address),
          .module = module_path(
              target.ResolveLoadAddress(*return_address).GetModule()),
          .source_path = {},
          .source_line = 0,
      };
      lldb::SBLineEntry line =
          target.ResolveLoadAddress(*return_address).GetLineEntry();
      if (line.IsValid()) {
        std::array<char, 4096> path{};
        line.GetFileSpec().GetPath(path.data(), path.size());
        frame.source_path = safe_string(path.data());
        frame.source_line = line.GetLine();
      }
      thread.frames.push_back(std::move(frame));
      frame_pointer = *caller_stack;
    }
  }
}

void append_frameless_qemu_mips_frame(lldb::SBTarget &target,
                                      SessionSnapshot &state) {
  for (ThreadInfo &captured_thread : state.threads) {
    captured_thread.selected = captured_thread.id == state.thread_id;
    if (!captured_thread.selected || !captured_thread.frames.empty()) {
      continue;
    }
    captured_thread.frames.push_back(StackFrameInfo{
        .thread_id = state.thread_id,
        .index = 0,
        .selected = true,
        .pc = state.pc,
        .sp = state.sp,
        .function = symbol_for_address(target, state.pc),
        .module = state.pc_module_path,
        .source_path = {},
        .source_line = 0,
    });
  }
}

bool step_frameless_qemu_mips_at_breakpoint(lldb::SBTarget &target,
                                            const SessionSnapshot &state,
                                            std::string &failure) {
  std::vector<lldb::SBBreakpoint> disabled;
  for (const BreakpointInfo &breakpoint : state.breakpoints) {
    if (!breakpoint.enabled ||
        std::ranges::find(breakpoint.addresses, state.pc) ==
            breakpoint.addresses.end()) {
      continue;
    }
    lldb::SBBreakpoint native = target.FindBreakpointByID(breakpoint.id);
    if (native.IsValid()) {
      native.SetEnabled(false);
      disabled.push_back(native);
    }
  }

  const bool stepped = step_frameless_qemu_mips(target, failure);
  for (lldb::SBBreakpoint &breakpoint : disabled) {
    breakpoint.SetEnabled(true);
  }
  return stepped;
}

} // namespace debugger::lldb_detail
