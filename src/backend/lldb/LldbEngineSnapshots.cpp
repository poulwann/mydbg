#include "backend/lldb/LldbEngineInternal.h"
#include "localization/Localization.h"

#include <cinttypes>
#include <span>

namespace debugger::lldb_detail {

using namespace std::chrono_literals;

void collect_matching_sections(lldb::SBSection section, std::string_view wanted,
                               std::vector<lldb::SBSection> &matches) {
  if (safe_string(section.GetName()) == wanted) {
    matches.push_back(section);
  }
  const std::size_t child_count = section.GetNumSubSections();
  for (std::size_t index = 0; index < child_count; ++index) {
    collect_matching_sections(section.GetSubSectionAtIndex(index), wanted,
                              matches);
  }
}

void append_console(SessionSnapshot &state, std::string_view command,
                    std::string_view response) {
  constexpr std::size_t maximum_console_bytes = 1024 * 1024;
  state.console_output.append("> ");
  state.console_output.append(command);
  state.console_output.push_back('\n');
  state.console_output.append(response);
  if (response.empty() || response.back() != '\n') {
    state.console_output.push_back('\n');
  }
  if (state.console_output.size() > maximum_console_bytes) {
    state.console_output.erase(0, state.console_output.size() -
                                      maximum_console_bytes);
  }
}

void refresh_breakpoints(lldb::SBTarget &target, SessionSnapshot &state) {
  state.breakpoints.clear();
  if (!target.IsValid()) {
    return;
  }

  const std::uint32_t count = target.GetNumBreakpoints();
  state.breakpoints.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    lldb::SBBreakpoint breakpoint = target.GetBreakpointAtIndex(index);
    BreakpointInfo info;
    info.id = static_cast<std::uint32_t>(breakpoint.GetID());
    info.enabled = breakpoint.IsEnabled();
    info.hit_count = breakpoint.GetHitCount();
    info.condition = safe_string(breakpoint.GetCondition());

    lldb::SBStream description;
    if (breakpoint.GetDescription(description)) {
      info.description = safe_string(description.GetData());
    }
    constexpr std::string_view description_prefix = "SBBreakpoint: ";
    if (info.description.starts_with(description_prefix)) {
      info.description.erase(0, description_prefix.size());
    }
    if (info.description.starts_with("id = ")) {
      const std::size_t first_field_end = info.description.find(", ");
      if (first_field_end != std::string::npos) {
        info.description.erase(0, first_field_end + 2);
      }
    }

    const std::size_t location_count = breakpoint.GetNumLocations();
    info.addresses.reserve(location_count);
    for (std::size_t location_index = 0; location_index < location_count;
         ++location_index) {
      lldb::SBBreakpointLocation location = breakpoint.GetLocationAtIndex(
          static_cast<std::uint32_t>(location_index));
      const lldb::addr_t address = location.GetLoadAddress();
      if (address != LLDB_INVALID_ADDRESS) {
        info.addresses.push_back(address);
      }
    }
    state.breakpoints.push_back(std::move(info));
  }
}

void capture_memory(lldb::SBProcess &process, lldb::addr_t address,
                    SessionSnapshot &state) {
  constexpr std::size_t memory_page_size = 256;
  state.memory_base = address;
  state.memory.assign(memory_page_size, 0);
  lldb::SBError memory_error;
  const std::size_t bytes_read = process.ReadMemory(
      address, state.memory.data(), state.memory.size(), memory_error);
  if (memory_error.Fail() && bytes_read == 0) {
    state.memory.clear();
    state.error = error_text(memory_error);
  } else {
    state.memory.resize(bytes_read);
    state.error.clear();
  }
}

lldb::SBFrame selected_frame(lldb::SBProcess &process) {
  lldb::SBThread thread = process.GetSelectedThread();
  if (!thread.IsValid() && process.GetNumThreads() != 0) {
    thread = process.GetThreadAtIndex(0);
  }
  if (!thread.IsValid()) {
    return {};
  }
  lldb::SBFrame frame = thread.GetSelectedFrame();
  if (!frame.IsValid() && thread.GetNumFrames() != 0) {
    frame = thread.GetFrameAtIndex(0);
  }
  return frame;
}

std::optional<lldb::addr_t> resolve_address(std::string_view expression,
                                            lldb::SBProcess &process,
                                            std::string &failure) {
  expression = trim(expression);
  if (const auto numeric = parse_integer(expression)) {
    return *numeric;
  }

  lldb::SBFrame frame = selected_frame(process);
  if (!frame.IsValid()) {
    failure = l10n::text(l10n::Key::SnapshotAddressRequiresStoppedFrame);
    return std::nullopt;
  }

  std::string register_name{expression};
  if (!register_name.empty() && register_name.front() == '$') {
    register_name.erase(0, 1);
  }
  lldb::SBValue register_value = frame.FindRegister(register_name.c_str());
  if (register_value.IsValid()) {
    lldb::SBError register_error;
    const std::uint64_t value =
        register_value.GetValueAsUnsigned(register_error);
    if (register_error.Success()) {
      return value;
    }
  }

  const std::string expression_string{expression};
  lldb::SBValue value = frame.EvaluateExpression(expression_string.c_str());
  lldb::SBError value_error = value.GetError();
  if (value.IsValid() && value_error.Success()) {
    lldb::SBError conversion_error;
    const std::uint64_t address = value.GetValueAsUnsigned(conversion_error);
    if (conversion_error.Success()) {
      return address;
    }
  }

  failure = value_error.Fail()
                ? error_text(value_error)
                : l10n::text(l10n::Key::SnapshotAddressResolutionFailed);
  return std::nullopt;
}

bool append_process_output(lldb::SBProcess &process, SessionSnapshot &state) {
  if (!process.IsValid()) {
    return false;
  }

  const auto append = [&state](OutputStream stream, const char *data,
                               std::size_t size) {
    constexpr std::size_t maximum_output_bytes = 1024U * 1024U;
    if (state.process_output.size() + size > maximum_output_bytes) {
      const std::size_t discard =
          state.process_output.size() + size - maximum_output_bytes;
      state.process_output.erase(0, discard);
    }
    state.process_output.append(data, size);

    state.output_chunks.push_back(OutputChunk{
        .sequence = ++state.output_sequence,
        .stream = stream,
        .data = std::string{data, size},
    });
    state.output_chunk_bytes += size;
    while (state.output_chunk_bytes > maximum_output_bytes &&
           !state.output_chunks.empty()) {
      state.output_chunk_bytes -= state.output_chunks.front().data.size();
      state.output_chunks.pop_front();
    }
  };

  bool appended = false;
  std::array<char, 4096> buffer{};
  const auto drain = [&](OutputStream stream, auto read) {
    for (;;) {
      const std::size_t count = (process.*read)(buffer.data(), buffer.size());
      if (count == 0) {
        break;
      }
      append(stream, buffer.data(), count);
      appended = true;
    }
  };
  drain(OutputStream::Stdout, &lldb::SBProcess::GetSTDOUT);
  drain(OutputStream::Stderr, &lldb::SBProcess::GetSTDERR);
  return appended;
}

namespace {

std::string debug_file_path(lldb::SBFileSpec file) {
  std::array<char, 4096> path{};
  const auto length = file.GetPath(path.data(), path.size());
  return length != 0 && length < path.size() ? std::string{path.data()}
                                             : std::string{};
}

std::string module_debug_info_path(lldb::SBModule module) {
  // Resolve the symbol vendor before asking for its file. A stripped image can
  // report its own filename even though it has no usable debug information.
  if (module.GetNumCompileUnits() == 0) {
    return {};
  }
  auto path = debug_file_path(module.GetSymbolFileSpec());
  std::error_code error;
  return !path.empty() && std::filesystem::is_regular_file(path, error)
             ? path
             : std::string{};
}

} // namespace

std::string module_path(const lldb::SBModule &module) {
  if (!module.IsValid()) {
    return {};
  }
  std::array<char, 4096> path{};
  module.GetFileSpec().GetPath(path.data(), path.size());
  return safe_string(path.data());
}

std::string register_value_text(lldb::SBValue value) {
  if (const char *text = value.GetValue(); text != nullptr && text[0] != '\0') {
    return text;
  }
  lldb::SBData data = value.GetData();
  const auto size = data.GetByteSize();
  if (size == 0) {
    return {};
  }
  constexpr char digits[] = "0123456789abcdef";
  std::string result = "{";
  result.reserve(size * 5 + 3);
  for (std::size_t index = 0; index < size; ++index) {
    lldb::SBError error;
    const auto byte = data.GetUnsignedInt8(error, index);
    if (error.Fail()) {
      return {};
    }
    result += " 0x";
    result += digits[byte >> 4];
    result += digits[byte & 0xf];
  }
  result += " }";
  return result;
}

std::optional<std::uint64_t>
register_value_as_unsigned(lldb::SBValue value) {
  if (!value.IsValid()) {
    return std::nullopt;
  }

  lldb::SBError conversion_error;
  const std::uint64_t converted =
      value.GetValueAsUnsigned(conversion_error);
  if (conversion_error.Success()) {
    return converted;
  }

  const std::string rendered = safe_string(value.GetValue());
  std::string_view numeric = trim(rendered);
  int base = 10;
  if (numeric.starts_with("0x") || numeric.starts_with("0X")) {
    numeric.remove_prefix(2);
    base = 16;
  }
  if (numeric.empty()) {
    return std::nullopt;
  }

  std::uint64_t parsed = 0;
  const auto [end, error] =
      std::from_chars(numeric.data(), numeric.data() + numeric.size(), parsed,
                      base);
  if (error != std::errc{} || end == numeric.data()) {
    return std::nullopt;
  }
  return parsed;
}

static std::string symbol_for_address(lldb::SBTarget &target,
                                      lldb::addr_t load_address,
                                      lldb::SBSymbolContext symbols) {

  const char *name = nullptr;
  lldb::addr_t symbol_start = LLDB_INVALID_ADDRESS;
  lldb::addr_t symbol_end = LLDB_INVALID_ADDRESS;
  lldb::SBFunction function = symbols.GetFunction();
  if (function.IsValid()) {
    name = function.GetDisplayName();
    symbol_start = function.GetStartAddress().GetLoadAddress(target);
    symbol_end = function.GetEndAddress().GetLoadAddress(target);
  } else {
    lldb::SBSymbol symbol = symbols.GetSymbol();
    if (symbol.IsValid()) {
      name = symbol.GetDisplayName();
      symbol_start = symbol.GetStartAddress().GetLoadAddress(target);
      symbol_end = symbol.GetEndAddress().GetLoadAddress(target);
    }
  }
  if (name == nullptr || symbol_start == LLDB_INVALID_ADDRESS ||
      load_address < symbol_start ||
      (load_address != symbol_start &&
       (symbol_end == LLDB_INVALID_ADDRESS || load_address >= symbol_end))) {
    return {};
  }

  std::ostringstream result;
  result << name;
  if (symbol_start != LLDB_INVALID_ADDRESS && load_address > symbol_start) {
    result << "+0x" << std::hex << (load_address - symbol_start);
  }
  return result.str();
}

std::string symbol_for_address(lldb::SBTarget &target,
                               lldb::addr_t load_address) {
  return symbol_for_address(target, load_address,
                            target.ResolveLoadAddress(load_address)
                                .GetSymbolContext(lldb::eSymbolContextFunction |
                                                  lldb::eSymbolContextSymbol));
}

lldb::addr_t section_end(lldb::SBSection section, lldb::SBTarget &target,
                         std::optional<std::uint64_t> &load_bias,
                         bool &uniform_bias) {
  lldb::addr_t end = 0;
  const lldb::addr_t start = section.GetLoadAddress(target);
  if (start != LLDB_INVALID_ADDRESS) {
    end = start + section.GetByteSize();
    const lldb::addr_t file_address = section.GetFileAddress();
    if (file_address != LLDB_INVALID_ADDRESS && section.GetFileByteSize() != 0 &&
        section.GetByteSize() != 0) {
      // Only a real file-backed loaded section establishes the slide. A
      // header/base address alone cannot distinguish ET_EXEC from PIE.
      if (start < file_address) {
        uniform_bias = false;
      } else {
        const auto bias = start - file_address;
        if (load_bias && *load_bias != bias) {
          uniform_bias = false;
        } else {
          load_bias = bias;
        }
      }
    }
  }
  const std::size_t child_count = section.GetNumSubSections();
  for (std::size_t index = 0; index < child_count; ++index) {
    end = std::max(end, section_end(section.GetSubSectionAtIndex(index), target,
                                    load_bias, uniform_bias));
  }
  return end;
}

void capture_threads(lldb::SBProcess &process, SessionSnapshot &state) {
  state.threads.clear();
  const lldb::tid_t selected_thread_id =
      process.GetSelectedThread().GetThreadID();
  const std::uint32_t thread_count = process.GetNumThreads();
  state.threads.reserve(thread_count);
  for (std::uint32_t thread_index = 0; thread_index < thread_count;
       ++thread_index) {
    lldb::SBThread thread = process.GetThreadAtIndex(thread_index);
    if (!thread.IsValid()) {
      continue;
    }

    ThreadInfo thread_info;
    thread_info.id = thread.GetThreadID();
    thread_info.index = thread.GetIndexID();
    thread_info.selected = thread_info.id == selected_thread_id;
    thread_info.name = safe_string(thread.GetName());
    if (thread_info.name.empty()) {
      thread_info.name = safe_string(thread.GetQueueName());
    }
    std::array<char, 512> reason{};
    const std::size_t reason_length =
        thread.GetStopDescription(reason.data(), reason.size());
    if (reason_length != 0) {
      thread_info.stop_reason.assign(
          reason.data(), std::min(reason_length, reason.size() - 1));
    }

    constexpr std::uint32_t maximum_frames = 64;
    const std::uint32_t frame_count =
        std::min(thread.GetNumFrames(), maximum_frames);
    lldb::SBFrame selected_frame = thread.GetSelectedFrame();
    const std::uint32_t selected_frame_id =
        selected_frame.IsValid() ? selected_frame.GetFrameID()
                                 : std::numeric_limits<std::uint32_t>::max();
    thread_info.frames.reserve(frame_count);
    for (std::uint32_t frame_index = 0; frame_index < frame_count;
         ++frame_index) {
      lldb::SBFrame frame = thread.GetFrameAtIndex(frame_index);
      if (!frame.IsValid()) {
        continue;
      }
      StackFrameInfo frame_info;
      frame_info.thread_id = thread_info.id;
      frame_info.index = frame_index;
      frame_info.selected =
          thread_info.selected && frame.GetFrameID() == selected_frame_id;
      frame_info.pc = frame.GetPC();
      frame_info.sp = frame.GetSP();
      frame_info.function = safe_string(frame.GetFunctionName());
      frame_info.module = module_path(frame.GetModule());
      lldb::SBLineEntry line = frame.GetLineEntry();
      if (line.IsValid()) {
        std::array<char, 4096> path{};
        line.GetFileSpec().GetPath(path.data(), path.size());
        frame_info.source_path = safe_string(path.data());
        frame_info.source_line = line.GetLine();
      }
      thread_info.frames.push_back(std::move(frame_info));
    }
    state.threads.push_back(std::move(thread_info));
  }
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
      state.byte_order == "big" ? lldb::eByteOrderBig
                                : lldb::eByteOrderLittle;
  const auto read_word = [&process, byte_order](
                             std::uint64_t address)
      -> std::optional<std::uint64_t> {
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

void capture_memory_regions(lldb::SBTarget &target, lldb::SBProcess &process,
                            SessionSnapshot &state) {
  state.memory_regions.clear();
  lldb::SBMemoryRegionInfoList regions = process.GetMemoryRegions();
  const std::uint32_t region_count = regions.GetSize();
  state.memory_regions.reserve(region_count);
  for (std::uint32_t index = 0; index < region_count; ++index) {
    lldb::SBMemoryRegionInfo region;
    if (!regions.GetMemoryRegionAtIndex(index, region) || !region.IsMapped()) {
      continue;
    }
    state.memory_regions.push_back(MemoryRegionInfo{
        .start = region.GetRegionBase(),
        .end = region.GetRegionEnd(),
        .readable = region.IsReadable(),
        .writable = region.IsWritable(),
        .executable = region.IsExecutable(),
        .name = safe_string(region.GetName()),
    });
  }
  if (!state.memory_regions.empty() ||
      (state.mode != SessionMode::QemuUser &&
       state.mode != SessionMode::QemuSystem)) {
    return;
  }

  // Some QEMU stubs do not implement qMemoryRegionInfo. LLDB still retains
  // each loaded ELF module's PT_LOAD containers, their p_memsz ranges and
  // p_flags, and the target's section load addresses. Publish only those
  // file-backed ranges: anonymous remote mappings cannot be inferred here.
  const std::uint32_t module_count = target.GetNumModules();
  for (std::uint32_t module_index = 0; module_index < module_count;
       ++module_index) {
    lldb::SBModule module = target.GetModuleAtIndex(module_index);
    const std::string path = module_path(module);
    if (!module.IsValid() || path.empty()) {
      continue;
    }
    const std::size_t section_count = module.GetNumSections();
    for (std::size_t section_index = 0; section_index < section_count;
         ++section_index) {
      lldb::SBSection section = module.GetSectionAtIndex(section_index);
      const std::string section_name = safe_string(section.GetName());
      if (!section.IsValid() ||
          section.GetSectionType() != lldb::eSectionTypeContainer ||
          !section_name.starts_with("PT_LOAD[") ||
          !section_name.ends_with(']')) {
        continue;
      }
      const lldb::addr_t start = section.GetLoadAddress(target);
      const lldb::addr_t size = section.GetByteSize();
      if (start == LLDB_INVALID_ADDRESS || size == 0 ||
          size > std::numeric_limits<lldb::addr_t>::max() - start) {
        continue;
      }
      const std::uint32_t permissions = section.GetPermissions();
      state.memory_regions.push_back(MemoryRegionInfo{
          .start = start,
          .end = start + size,
          .readable =
              (permissions & lldb::ePermissionsReadable) != 0,
          .writable =
              (permissions & lldb::ePermissionsWritable) != 0,
          .executable =
              (permissions & lldb::ePermissionsExecutable) != 0,
          .name = path,
      });
    }
  }
  std::ranges::sort(
      state.memory_regions, {},
      [](const MemoryRegionInfo &region) { return region.start; });
}


void capture_heap(lldb::SBTarget &target, lldb::SBProcess &process,
                  SessionSnapshot &state) {
  state.heap_chunks.clear();
  state.heap_error.clear();
  const auto heap_region = std::find_if(
      state.memory_regions.begin(), state.memory_regions.end(),
      [](const MemoryRegionInfo &region) { return region.name == "[heap]"; });
  if (heap_region == state.memory_regions.end()) {
    state.heap_error = l10n::text(l10n::Key::SnapshotHeapMappingMissing);
    return;
  }

  const std::uint32_t pointer_size =
      std::max<std::uint32_t>(1, state.address_byte_size);
  if (pointer_size != 4 && pointer_size != 8) {
    state.heap_error =
        l10n::text(l10n::Key::SnapshotAllocatorPointerSizeUnsupported);
    return;
  }
  const std::uint64_t alignment = static_cast<std::uint64_t>(pointer_size) * 2;
  auto read_word = [&](std::uint64_t address, std::uint64_t &value) {
    std::array<std::uint8_t, 8> bytes{};
    lldb::SBError error;
    const std::size_t read =
        process.ReadMemory(address, bytes.data(), pointer_size, error);
    if (read != pointer_size || error.Fail()) {
      return false;
    }
    value = decode_pointer(bytes.data(), pointer_size, target.GetByteOrder());
    return true;
  };

  std::uint64_t cursor = heap_region->start;
  bool found_first = false;
  constexpr std::size_t chunk_limit = 256;
  while (cursor + pointer_size * 2 <= heap_region->end &&
         state.heap_chunks.size() < chunk_limit) {
    std::uint64_t previous_size = 0;
    std::uint64_t size_and_flags = 0;
    if (!read_word(cursor, previous_size) ||
        !read_word(cursor + pointer_size, size_and_flags)) {
      state.heap_error = l10n::text(l10n::Key::SnapshotHeapHeaderReadFailed);
      break;
    }
    const std::uint64_t chunk_size = size_and_flags & ~0x7ULL;
    const bool plausible = chunk_size >= alignment &&
                           chunk_size % alignment == 0 &&
                           chunk_size <= heap_region->end - cursor;
    if (!plausible) {
      if (found_first || cursor - heap_region->start >= 4096) {
        state.heap_error = l10n::text(l10n::Key::SnapshotHeapHeaderInvalid);
        break;
      }
      cursor += alignment;
      continue;
    }
    found_first = true;
    std::uint64_t forward = 0;
    std::uint64_t backward = 0;
    read_word(cursor + pointer_size * 2, forward);
    read_word(cursor + pointer_size * 3, backward);

    bool in_use = false;
    if (cursor + chunk_size + pointer_size < heap_region->end) {
      std::uint64_t next_flags = 0;
      if (read_word(cursor + chunk_size + pointer_size, next_flags)) {
        in_use = (next_flags & 1U) != 0;
      }
    }
    state.heap_chunks.push_back(HeapChunkInfo{
        .address = cursor,
        .previous_size = previous_size,
        .size = chunk_size,
        .flags = size_and_flags & 0x7U,
        .in_use = in_use,
        .forward = forward,
        .backward = backward,
    });
    cursor += chunk_size;
  }
  for (HeapChunkInfo &chunk : state.heap_chunks) {
    if (!chunk.in_use || chunk.forward == 0) {
      continue;
    }
    const std::uint64_t user_address = chunk.address + pointer_size * 2;
    const std::uint64_t decoded_forward = chunk.forward ^ (user_address >> 12);
    const bool points_to_chunk = std::any_of(
        state.heap_chunks.begin(), state.heap_chunks.end(),
        [decoded_forward, pointer_size](const HeapChunkInfo &candidate) {
          return decoded_forward == candidate.address + pointer_size * 2;
        });
    if (decoded_forward == 0 || points_to_chunk) {
      chunk.in_use = false;
    }
  }
  if (!found_first && state.heap_error.empty()) {
    state.heap_error = l10n::text(l10n::Key::SnapshotHeapChunksNotFound);
  }
  if (state.heap_chunks.size() == chunk_limit) {
    state.heap_error = l10n::text(l10n::Key::SnapshotHeapWalkTruncated);
  }
}

void capture_modules(lldb::SBTarget &target, SessionSnapshot &state) {
  state.modules.clear();
  const std::uint32_t module_count = target.GetNumModules();
  state.modules.reserve(module_count);
  for (std::uint32_t index = 0; index < module_count; ++index) {
    lldb::SBModule module = target.GetModuleAtIndex(index);
    if (!module.IsValid()) {
      continue;
    }
    const lldb::addr_t base =
        module.GetObjectFileHeaderAddress().GetLoadAddress(target);
    lldb::addr_t end = 0;
    std::optional<std::uint64_t> load_bias;
    bool uniform_bias = true;
    const std::size_t section_count = module.GetNumSections();
    for (std::size_t section_index = 0; section_index < section_count;
         ++section_index) {
      end = std::max(end, section_end(module.GetSectionAtIndex(section_index),
                                      target, load_bias, uniform_bias));
    }
    state.modules.push_back(ModuleInfo{
        .base = base == LLDB_INVALID_ADDRESS ? 0 : base,
        .end = end,
        .load_bias = load_bias.value_or(0),
        .has_load_bias = load_bias.has_value() && uniform_bias,
        .path = module_path(module),
        .uuid = safe_string(module.GetUUIDString()),
        .debug_info_path = module_debug_info_path(module),
    });
  }
}

std::uint64_t decode_pointer(const std::uint8_t *bytes, std::uint32_t size,
                             lldb::ByteOrder byte_order) {
  std::uint64_t value = 0;
  if (byte_order == lldb::eByteOrderBig) {
    for (std::uint32_t index = 0; index < size; ++index) {
      value = (value << 8U) | bytes[index];
    }
  } else {
    for (std::uint32_t index = 0; index < size; ++index) {
      value |= static_cast<std::uint64_t>(bytes[index]) << (index * 8U);
    }
  }
  return value;
}
std::optional<std::uint64_t> register_numeric(const SessionSnapshot &state,
                                              std::string_view name) {
  if (!name.empty() && name.front() == '$') {
    name.remove_prefix(1);
  }
  const auto found =
      std::find_if(state.registers.begin(), state.registers.end(),
                   [name](const RegisterValue &value) {
                     return value.name == name && value.has_numeric_value;
                   });
  if (found == state.registers.end()) {
    return std::nullopt;
  }
  return found->numeric_value;
}

std::vector<PointerChainEntry>
resolve_pointer_chain(lldb::SBTarget &target, lldb::SBProcess &process,
                      const SessionSnapshot &state, std::uint64_t start,
                      std::size_t maximum_depth = 3) {
  std::vector<PointerChainEntry> chain;
  const std::uint32_t width = state.address_byte_size;
  if (width == 0 || width > sizeof(std::uint64_t)) {
    return chain;
  }

  std::unordered_set<std::uint64_t> visited;
  std::uint64_t current = start;
  for (std::size_t depth = 0; depth < maximum_depth; ++depth) {
    PointerChainEntry entry{};
    entry.address = current;
    const MemoryRegionInfo *region = region_containing(state, current);
    if (region == nullptr || !region->readable) {
      entry.error =
          region == nullptr
              ? l10n::text(l10n::Key::SnapshotPointerUnmapped)
              : l10n::text(l10n::Key::SnapshotPointerMappingUnreadable);
      chain.push_back(std::move(entry));
      break;
    }
    if (!visited.insert(current).second) {
      entry.error = l10n::text(l10n::Key::SnapshotPointerCycle);
      chain.push_back(std::move(entry));
      break;
    }

    std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
    lldb::SBError error;
    const std::size_t read =
        process.ReadMemory(current, bytes.data(), width, error);
    if (read != width || error.Fail()) {
      entry.error = error.Fail()
                        ? error_text(error)
                        : l10n::text(l10n::Key::SnapshotShortPointerRead);
      chain.push_back(std::move(entry));
      break;
    }
    entry.readable = true;
    entry.value = decode_pointer(bytes.data(), width, target.GetByteOrder());
    entry.symbol = symbol_for_address(target, entry.value);
    if (const MemoryRegionInfo *destination =
            region_containing(state, entry.value)) {
      entry.mapping = destination->name;
    }
    current = entry.value;
    chain.push_back(std::move(entry));
    if (current == 0) {
      break;
    }
  }
  return chain;
}

InstructionFlowKind convert_flow_kind(lldb::InstructionControlFlowKind kind) {
  switch (kind) {
  case lldb::eInstructionControlFlowKindCall:
  case lldb::eInstructionControlFlowKindFarCall:
    return InstructionFlowKind::Call;
  case lldb::eInstructionControlFlowKindReturn:
  case lldb::eInstructionControlFlowKindFarReturn:
    return InstructionFlowKind::Return;
  case lldb::eInstructionControlFlowKindJump:
  case lldb::eInstructionControlFlowKindFarJump:
    return InstructionFlowKind::Jump;
  case lldb::eInstructionControlFlowKindCondJump:
    return InstructionFlowKind::ConditionalJump;
  case lldb::eInstructionControlFlowKindUnknown:
  case lldb::eInstructionControlFlowKindOther:
    return InstructionFlowKind::Other;
  }
  return InstructionFlowKind::Other;
}

std::optional<std::pair<bool, std::string>>
predict_x86_branch(const InstructionRow &row, const SessionSnapshot &state) {
  auto flags = register_numeric(state, "rflags");
  if (!flags) {
    flags = register_numeric(state, "eflags");
  }
  if (!flags || row.bytes.empty()) {
    return std::nullopt;
  }

  std::size_t opcode_index = 0;
  while (opcode_index < row.bytes.size()) {
    const std::uint8_t byte = row.bytes[opcode_index];
    if (byte == 0x66 || byte == 0x67 || byte == 0xf2 || byte == 0xf3 ||
        byte == 0x2e || byte == 0x36 || byte == 0x3e || byte == 0x26 ||
        byte == 0x64 || byte == 0x65 ||
        (state.address_byte_size == 8 && byte >= 0x40 && byte <= 0x4f)) {
      ++opcode_index;
      continue;
    }
    break;
  }
  if (opcode_index >= row.bytes.size()) {
    return std::nullopt;
  }

  std::optional<std::uint8_t> condition;
  const std::uint8_t opcode = row.bytes[opcode_index];
  if (opcode >= 0x70 && opcode <= 0x7f) {
    condition = static_cast<std::uint8_t>(opcode & 0x0fU);
  } else if (opcode == 0x0f && opcode_index + 1 < row.bytes.size() &&
             row.bytes[opcode_index + 1] >= 0x80 &&
             row.bytes[opcode_index + 1] <= 0x8f) {
    condition = static_cast<std::uint8_t>(row.bytes[opcode_index + 1] & 0x0fU);
  }
  if (!condition) {
    return std::nullopt;
  }

  const bool carry = (*flags & (1ULL << 0U)) != 0;
  const bool parity = (*flags & (1ULL << 2U)) != 0;
  const bool zero = (*flags & (1ULL << 6U)) != 0;
  const bool sign = (*flags & (1ULL << 7U)) != 0;
  const bool overflow = (*flags & (1ULL << 11U)) != 0;
  const auto prediction = [](bool taken, l10n::Key explanation) {
    return std::pair{taken, std::string{l10n::text(explanation)}};
  };
  switch (*condition) {
  case 0x0:
    return prediction(overflow, l10n::Key::SnapshotBranchOverflowSet);
  case 0x1:
    return prediction(!overflow, l10n::Key::SnapshotBranchOverflowClear);
  case 0x2:
    return prediction(carry, l10n::Key::SnapshotBranchCarrySet);
  case 0x3:
    return prediction(!carry, l10n::Key::SnapshotBranchCarryClear);
  case 0x4:
    return prediction(zero, l10n::Key::SnapshotBranchZeroSet);
  case 0x5:
    return prediction(!zero, l10n::Key::SnapshotBranchZeroClear);
  case 0x6:
    return prediction(carry || zero, l10n::Key::SnapshotBranchCarryOrZeroSet);
  case 0x7:
    return prediction(!carry && !zero,
                      l10n::Key::SnapshotBranchCarryAndZeroClear);
  case 0x8:
    return prediction(sign, l10n::Key::SnapshotBranchSignSet);
  case 0x9:
    return prediction(!sign, l10n::Key::SnapshotBranchSignClear);
  case 0xa:
    return prediction(parity, l10n::Key::SnapshotBranchParitySet);
  case 0xb:
    return prediction(!parity, l10n::Key::SnapshotBranchParityClear);
  case 0xc:
    return prediction(sign != overflow,
                      l10n::Key::SnapshotBranchSignDiffersFromOverflow);
  case 0xd:
    return prediction(sign == overflow,
                      l10n::Key::SnapshotBranchSignEqualsOverflow);
  case 0xe:
    return prediction(zero || sign != overflow,
                      l10n::Key::SnapshotBranchZeroOrSignDiffersFromOverflow);
  case 0xf:
    return prediction(!zero && sign == overflow,
                      l10n::Key::SnapshotBranchNonzeroAndSignEqualsOverflow);
  }
  return std::pair{false, std::string{}};
}

struct StaticInstructionFlow {
  bool terminates{};
  bool conditional{};
  bool returns{};
  bool unsupported{};
  unsigned delay_slots{};
  std::optional<std::uint64_t> target;
  std::optional<std::uint64_t> fallthrough;
};

namespace {

DebugSourceLocation debug_source(lldb::SBFileSpec file, std::uint32_t line,
                                 std::uint32_t column) {
  return {debug_file_path(file), line, column};
}

std::vector<DebugDeclaration> debug_declarations(lldb::SBBlock block,
                                                 lldb::SBTarget &target,
                                                 bool arguments, bool locals) {
  std::vector<DebugDeclaration> declarations;
  // The target overload exposes declarations without evaluating a location in
  // the stopped frame (which may belong to an entirely different function).
  auto values = block.GetVariables(target, arguments, locals, locals);
  declarations.reserve(values.GetSize());
  for (std::uint32_t index = 0; index < values.GetSize(); ++index) {
    auto value = values.GetValueAtIndex(index);
    if (!value.IsValid()) {
      continue;
    }
    auto type = value.GetType();
    DebugDeclaration declaration{
        safe_string(value.GetName()), safe_string(type.GetDisplayTypeName()),
        value.GetValueType() == lldb::eValueTypeVariableArgument};
    if (!declaration.name.empty() || !declaration.type.empty()) {
      declarations.push_back(std::move(declaration));
    }
  }
  return declarations;
}

// All caches live for one capture. LLDB owns parsing and address relocation;
// declarations and types are queried once per function/block, not per operand.
class InstructionDebugMetadata final {
public:
  explicit InstructionDebugMetadata(lldb::SBTarget &target) : target_(target) {}

  lldb::SBSymbolContext &context(std::uint64_t address) {
    const auto [found, inserted] = contexts_.try_emplace(address);
    if (inserted) {
      found->second = target_.ResolveLoadAddress(address).GetSymbolContext(
          lldb::eSymbolContextModule | lldb::eSymbolContextFunction |
          lldb::eSymbolContextBlock | lldb::eSymbolContextLineEntry |
          lldb::eSymbolContextSymbol);
    }
    return found->second;
  }

  std::shared_ptr<const DebugFunctionInfo> function(lldb::SBFunction function) {
    if (!function.IsValid()) {
      return {};
    }
    const auto start = function.GetStartAddress().GetLoadAddress(target_);
    if (start == LLDB_INVALID_ADDRESS) {
      return {};
    }
    const auto [found, inserted] = functions_.try_emplace(start);
    if (inserted) {
      auto info = std::make_shared<DebugFunctionInfo>();
      info->address = start;
      info->name = safe_string(function.GetName());
      auto type = function.GetType();
      info->type = safe_string(type.GetDisplayTypeName());
      info->parameters =
          debug_declarations(function.GetBlock(), target_, true, false);
      // Some producers expose a function type but omit formal-parameter DIEs.
      // Keep unnamed types unnamed; never zip ABI slots with source parameters.
      if (info->parameters.empty()) {
        auto arguments = type.GetFunctionArgumentTypes();
        for (std::uint32_t index = 0; index < arguments.GetSize(); ++index) {
          auto argument = arguments.GetTypeAtIndex(index);
          info->parameters.push_back(
              {{}, safe_string(argument.GetDisplayTypeName()), true});
        }
      }
      found->second = std::move(info);
    }
    return found->second;
  }

  void capture(InstructionRow &row) {
    auto &symbols = context(row.address);
    auto line = symbols.GetLineEntry();
    if (line.IsValid() && line.GetLine() != 0) {
      auto start = line.GetStartAddress().GetLoadAddress(target_);
      if (start == LLDB_INVALID_ADDRESS) {
        start = row.address;
      }
      const auto [found, inserted] = sources_.try_emplace(start);
      if (inserted) {
        found->second = std::make_shared<DebugSourceLocation>(
            debug_source(line.GetFileSpec(), line.GetLine(), line.GetColumn()));
      }
      row.source = found->second;
    }
    auto info = function(symbols.GetFunction());
    if (info) {
      auto block = symbols.GetBlock();
      if (!block.IsValid()) {
        block = symbols.GetFunction().GetBlock();
      }
      row.debug_scope = scope(block, info, 0);
    }
  }

  DebugDeclaration global(lldb::SBSymbolContext &symbols,
                          std::uint64_t address) {
    auto symbol = symbols.GetSymbol();
    auto module = symbols.GetModule();
    if (!symbol.IsValid() || !module.IsValid() ||
        symbols.GetFunction().IsValid()) {
      return {};
    }
    const auto start = symbol.GetStartAddress().GetLoadAddress(target_);
    if (start == LLDB_INVALID_ADDRESS || address < start) {
      return {};
    }
    auto found = globals_.find(start);
    if (found == globals_.end()) {
      found = globals_.try_emplace(start).first;
      const auto name = safe_string(symbol.GetName());
      if (!name.empty()) {
        auto values = module.FindGlobalVariables(target_, name.c_str(), 64);
        for (std::uint32_t index = 0; index < values.GetSize(); ++index) {
          auto value = values.GetValueAtIndex(index);
          // Same-name file statics can coexist. Only an address-verified
          // declaration may annotate this reference, including interior refs.
          if (value.GetAddress().GetLoadAddress(target_) != start) {
            continue;
          }
          auto type = value.GetType();
          found->second.declaration = {safe_string(value.GetName()),
                                       safe_string(type.GetDisplayTypeName()),
                                       false};
          found->second.size = type.GetByteSize();
          break;
        }
      }
    }
    return address == start || address - start < found->second.size
               ? found->second.declaration
               : DebugDeclaration{};
  }

private:
  std::shared_ptr<const DebugScopeInfo>
  scope(lldb::SBBlock block,
        const std::shared_ptr<const DebugFunctionInfo> &info, unsigned depth) {
    if (!block.IsValid() || depth == 64) {
      return {};
    }
    // SBBlock has no public identity/equality accessor. Its description carries
    // the block's opaque ID; do not parse its text for declarations or ranges.
    lldb::SBStream identity;
    block.GetDescription(identity);
    auto &blocks = scopes_[*info->address];
    const auto [found, inserted] =
        blocks.try_emplace(safe_string(identity.GetData()));
    auto &entry = found->second;
    if (inserted) {
      auto result = std::make_shared<DebugScopeInfo>();
      result->function = info;
      result->parent = scope(block.GetParent(), info, depth + 1);
      result->declarations =
          debug_declarations(block, target_, block.IsInlined(), true);
      if (block.IsInlined()) {
        result->inline_name = safe_string(block.GetInlinedName());
        result->inline_call_site = debug_source(
            block.GetInlinedCallSiteFile(), block.GetInlinedCallSiteLine(),
            block.GetInlinedCallSiteColumn());
      }
      entry = std::move(result);
    }
    return entry;
  }

  struct Global {
    DebugDeclaration declaration;
    std::uint64_t size{};
  };
  lldb::SBTarget &target_;
  std::unordered_map<std::uint64_t, lldb::SBSymbolContext> contexts_;
  std::unordered_map<std::uint64_t, std::shared_ptr<const DebugFunctionInfo>>
      functions_;
  std::unordered_map<
      std::uint64_t,
      std::unordered_map<std::string, std::shared_ptr<const DebugScopeInfo>>>
      scopes_;
  std::unordered_map<std::uint64_t, std::shared_ptr<const DebugSourceLocation>>
      sources_;
  std::unordered_map<std::uint64_t, Global> globals_;
};

void group_debug_metadata(InstructionRow &row, const InstructionRow *previous) {
  row.begins_source = row.source && (previous == nullptr || !previous->source ||
                                     *row.source != *previous->source);
  row.begins_function =
      row.debug_scope &&
      (previous == nullptr || !previous->debug_scope ||
       row.debug_scope->function != previous->debug_scope->function);
  row.begins_debug_scope =
      row.debug_scope &&
      (previous == nullptr || row.debug_scope != previous->debug_scope);
}

} // namespace

// A capture-local cache: disassembly painting never reads target memory, and
// repeated operands do not cause repeated symbol queries or pointer walks.
class InstructionReferences final {
public:
  InstructionReferences(lldb::SBTarget &target, const SessionSnapshot &state,
                        InstructionDebugMetadata &debug)
      : target_(target), process_(target.GetProcess()), state_(state),
        debug_(debug) {}

  void append(InstructionRow &row, std::uint64_t address, bool runtime,
              bool indirect = true) {
    std::array<std::uint64_t, 4> visited{};
    for (std::size_t depth = 0; depth < visited.size(); ++depth) {
      if (address == LLDB_INVALID_ADDRESS ||
          std::find(visited.begin(), visited.begin() + depth, address) !=
              visited.begin() + depth) {
        break;
      }
      visited[depth] = address;
      const CachedReference *reference = lookup(address);
      if (reference == nullptr) {
        break;
      }
      if (reference->navigable || !reference->symbol.empty() ||
          !reference->preview.empty()) {
        const auto existing = std::find_if(
            row.references.begin(), row.references.end(),
            [address](const InstructionReference &entry) {
              return entry.address == address;
            });
        if (existing != row.references.end()) {
          // A static derivation is stronger than a register-dependent hint.
          existing->runtime = existing->runtime && runtime;
        } else if (row.references.size() < 12) {
          row.references.push_back(
              {address, reference->symbol, reference->preview, runtime,
               reference->declaration, reference->function});
        }
      }
      if (!indirect || !reference->preview.empty() || !reference->pointer) {
        break;
      }
      address = *reference->pointer;
    }
  }

  std::optional<std::uint64_t> pointer_at(std::uint64_t address) {
    const auto *reference = lookup(address, true);
    return reference != nullptr ? reference->pointer : std::nullopt;
  }

private:
  struct CachedReference {
    std::string symbol;
    std::string preview;
    DebugDeclaration declaration;
    std::shared_ptr<const DebugFunctionInfo> function;
    std::optional<std::uint64_t> pointer;
    bool navigable{};
    bool read_attempted{};
  };

  static std::string string_preview(const std::uint8_t *bytes,
                                    std::size_t size) {
    constexpr std::size_t maximum_characters = 96;
    std::size_t length = 0;
    std::size_t printable = 0;
    while (length < size && bytes[length] != 0) {
      const auto byte = bytes[length];
      if (byte >= 0x20 && byte <= 0x7e) {
        ++printable;
      } else if (byte != '\n' && byte != '\r' && byte != '\t' &&
                 byte != '\a' && byte != '\b' && byte != '\f' && byte != '\v') {
        return {};
      }
      ++length;
    }
    // Short unterminated reads and binary/control-heavy data are not strings.
    const bool truncated = length > maximum_characters;
    if (printable < 3 || printable * 2 < length ||
        (length == size && !truncated)) {
      return {};
    }
    std::string result;
    result.reserve(std::min(length, maximum_characters) + 8);
    result += '"';
    for (std::size_t index = 0;
         index < std::min(length, maximum_characters); ++index) {
      switch (bytes[index]) {
      case '\\': result += "\\\\"; break;
      case '"': result += "\\\""; break;
      case '\n': result += "\\n"; break;
      case '\r': result += "\\r"; break;
      case '\t': result += "\\t"; break;
      case '\a': result += "\\a"; break;
      case '\b': result += "\\b"; break;
      case '\f': result += "\\f"; break;
      case '\v': result += "\\v"; break;
      default: result += static_cast<char>(bytes[index]); break;
      }
    }
    result += '"';
    if (truncated) {
      result += "...";
    }
    return result;
  }

  const CachedReference *lookup(std::uint64_t address,
                                bool require_pointer = false) {
    auto found = cache_.find(address);
    if (found != cache_.end() &&
        (!require_pointer || found->second.read_attempted)) {
      return &found->second;
    }
    if (found == cache_.end()) {
      if (cache_.size() >= 8192) {
        return nullptr;
      }
      found = cache_.try_emplace(address).first;
      auto &symbols = debug_.context(address);
      found->second.symbol = symbol_for_address(target_, address, symbols);
      found->second.function = debug_.function(symbols.GetFunction());
      found->second.declaration = debug_.global(symbols, address);
      const auto *region = region_containing(state_, address);
      found->second.navigable =
          region != nullptr && (region->readable || region->executable);
    }
    CachedReference &reference = found->second;
    const MemoryRegionInfo *region = region_containing(state_, address);
    if (reference.read_attempted || region == nullptr || !region->readable ||
        (region->executable && !require_pointer) || remaining_reads_ == 0) {
      return &reference;
    }
    std::array<std::uint8_t, 97> bytes{};
    const auto count = static_cast<std::size_t>(
        std::min<std::uint64_t>(bytes.size(), region->end - address));
    if (count == 0) {
      return &reference;
    }
    --remaining_reads_;
    reference.read_attempted = true;
    lldb::SBError error;
    const auto read =
        process_.IsValid()
            ? process_.ReadMemory(address, bytes.data(), count, error)
            : target_.ReadMemory(target_.ResolveLoadAddress(address),
                                 bytes.data(), count, error);
    if (read == 0) {
      return &reference;
    }
    if (!region->executable) {
      reference.preview = string_preview(bytes.data(), read);
    }
    const auto width = state_.address_byte_size;
    const auto order = target_.GetByteOrder();
    if ((width == 4 || width == 8) && read >= width &&
        (order == lldb::eByteOrderLittle || order == lldb::eByteOrderBig)) {
      const auto pointer = decode_pointer(bytes.data(), width, order);
      if (const auto *destination = region_containing(state_, pointer);
          destination != nullptr &&
          (destination->readable || destination->executable)) {
        reference.pointer = pointer;
      }
    }
    return &reference;
  }

  lldb::SBTarget &target_;
  lldb::SBProcess process_;
  const SessionSnapshot &state_;
  InstructionDebugMetadata &debug_;
  std::unordered_map<std::uint64_t, CachedReference> cache_;
  std::size_t remaining_reads_{1024};
};

class InstructionAnalyzer final {
public:
  InstructionAnalyzer() : analysis_(rz_analysis_new(), &rz_analysis_free) {}

  void analyze(InstructionRow &row, lldb::SBTarget &target,
               lldb::SBProcess &process, const SessionSnapshot &state) {

    std::string failure;
    if (!configure(state, failure)) {
      ResolvedOperandInfo unavailable{};
      unavailable.role = "analysis";
      unavailable.error = std::move(failure);
      row.resolved_operands.push_back(std::move(unavailable));
      return;
    }

    RzAnalysisOp operation;
    rz_analysis_op_init(&operation);
    const int decoded = rz_analysis_op(
        analysis_.get(), &operation, static_cast<ut64>(row.address),
        row.bytes.data(), static_cast<ut64>(row.bytes.size()),
        static_cast<RzAnalysisOpMask>(RZ_ANALYSIS_OP_MASK_VAL));
    if (decoded <= 0) {
      rz_analysis_op_fini(&operation);
      ResolvedOperandInfo unavailable{};
      unavailable.role = "analysis";
      unavailable.error =
          l10n::text(l10n::Key::SnapshotInstructionDecodeFailed);
      row.resolved_operands.push_back(std::move(unavailable));
      return;
    }

    const std::uint32_t operation_type = operation.type & 0xffffU;
    if (operation_type == RZ_ANALYSIS_OP_TYPE_SWI) {
      row.flow_kind = InstructionFlowKind::Syscall;
    } else if (operation_type == RZ_ANALYSIS_OP_TYPE_CALL ||
               operation_type == RZ_ANALYSIS_OP_TYPE_UCALL) {
      row.flow_kind = InstructionFlowKind::Call;
    } else if (operation_type == RZ_ANALYSIS_OP_TYPE_RET) {
      row.flow_kind = InstructionFlowKind::Return;
    } else if (operation_type == RZ_ANALYSIS_OP_TYPE_JMP ||
               operation_type == RZ_ANALYSIS_OP_TYPE_UJMP) {
      row.flow_kind = (operation.type & RZ_ANALYSIS_OP_TYPE_COND) != 0
                          ? InstructionFlowKind::ConditionalJump
                          : InstructionFlowKind::Jump;
    }

    append_operand(row, "destination", operation.dst, target, process, state);
    for (const RzAnalysisValue *source : operation.src) {
      if (source != nullptr) {
        append_operand(row, "source", source, target, process, state);
      }
    }

    if (row.flow_kind == InstructionFlowKind::ConditionalJump) {
      row.branch.conditional = true;
      row.branch.taken_target =
          operation.jump == UT64_MAX
              ? 0
              : static_cast<std::uint64_t>(operation.jump);
      row.branch.fallthrough_target =
          operation.fail == UT64_MAX
              ? row.address + row.bytes.size()
              : static_cast<std::uint64_t>(operation.fail);
      if (is_x86_architecture(state.architecture)) {
        if (auto prediction = predict_x86_branch(row, state)) {
          row.branch.available = true;
          row.branch.taken = prediction->first;
          row.branch.explanation = std::move(prediction->second);
        } else {
          row.branch.explanation =
              l10n::text(l10n::Key::SnapshotBranchConditionUnavailable);
        }
      } else {
        row.branch.explanation =
            l10n::text(l10n::Key::SnapshotBranchArchitectureUnsupported);
      }
    }

    if (row.flow_kind == InstructionFlowKind::Call ||
        row.flow_kind == InstructionFlowKind::Syscall) {
      capture_arguments(row, target, process, state);
    }
    rz_analysis_op_fini(&operation);
  }

  bool configure_graph(const SessionSnapshot &state, std::string &failure) {
    // LLDB's public instruction API does not expose per-address ARM/Thumb
    // mode. Do not decode Thumb bytes as ARM based on the current PC's CPSR.
    if (state.address_byte_size == 4 &&
        state.architecture.starts_with("arm")) {
      failure = l10n::text(l10n::Key::SnapshotStaticArmModeUnavailable);
      return false;
    }
    return configure(state, failure);
  }

  StaticInstructionFlow analyze_flow(InstructionRow &row,
                                     InstructionReferences *references,
                                     const SessionSnapshot &state) {
    StaticInstructionFlow flow;
    const auto lldb_target = row.flow_target;
    row.flow_target.reset();
    RzAnalysisOp operation;
    rz_analysis_op_init(&operation);
    const int decoded = rz_analysis_op(
        analysis_.get(), &operation, static_cast<ut64>(row.address),
        row.bytes.data(), static_cast<ut64>(row.bytes.size()),
        references != nullptr
            ? static_cast<RzAnalysisOpMask>(RZ_ANALYSIS_OP_MASK_BASIC |
                                            RZ_ANALYSIS_OP_MASK_VAL)
            : RZ_ANALYSIS_OP_MASK_BASIC);
    const auto operation_type = operation.type & 0xffffU;
    if (decoded <= 0 || operation.size <= 0 ||
        static_cast<std::size_t>(operation.size) != row.bytes.size() ||
        operation_type == RZ_ANALYSIS_OP_TYPE_NULL ||
        operation_type == RZ_ANALYSIS_OP_TYPE_UNK) {
      flow.terminates = true;
      flow.unsupported = true;
    } else {
      if (references != nullptr) {
        capture_references(row, operation, *references, state);
      }
      flow.conditional = (operation.type & RZ_ANALYSIS_OP_TYPE_COND) != 0;
      if (operation_type == RZ_ANALYSIS_OP_TYPE_JMP ||
          operation_type == RZ_ANALYSIS_OP_TYPE_UJMP) {
        flow.terminates = true;
        row.flow_kind = flow.conditional ? InstructionFlowKind::ConditionalJump
                                        : InstructionFlowKind::Jump;
        constexpr auto indirect =
            RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_REG |
            RZ_ANALYSIS_OP_TYPE_MEM;
        if (operation_type == RZ_ANALYSIS_OP_TYPE_JMP &&
            (operation.type & indirect) == 0 && operation.jump != UT64_MAX) {
          flow.target = operation.jump;
          row.flow_target = operation.jump;
        }
      } else if (operation_type == RZ_ANALYSIS_OP_TYPE_RET) {
        flow.terminates = true;
        flow.returns = true;
        row.flow_kind = InstructionFlowKind::Return;
      } else if (operation_type == RZ_ANALYSIS_OP_TYPE_CALL ||
                 operation_type == RZ_ANALYSIS_OP_TYPE_UCALL) {
        row.flow_kind = InstructionFlowKind::Call;
        constexpr auto indirect =
            RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_REG |
            RZ_ANALYSIS_OP_TYPE_MEM;
        if (operation_type == RZ_ANALYSIS_OP_TYPE_CALL &&
            (operation.type & indirect) == 0 && operation.jump != UT64_MAX) {
          row.flow_target = operation.jump;
        }
      } else if (operation_type == RZ_ANALYSIS_OP_TYPE_SWI) {
        row.flow_kind = InstructionFlowKind::Syscall;
      } else if (operation.eob ||
                 operation_type == RZ_ANALYSIS_OP_TYPE_ILL ||
                 operation_type == RZ_ANALYSIS_OP_TYPE_TRAP ||
                 operation_type == RZ_ANALYSIS_OP_TYPE_SWITCH ||
                 row.flow_kind == InstructionFlowKind::Jump ||
                 row.flow_kind == InstructionFlowKind::ConditionalJump ||
                 row.flow_kind == InstructionFlowKind::Return) {
        flow.terminates = true;
        flow.unsupported = true;
      }
      if (flow.terminates) {
        if (operation.delay < 0 || operation.delay > 8) {
          flow.unsupported = true;
        } else {
          flow.delay_slots = static_cast<unsigned>(operation.delay);
        }
        if (flow.conditional && operation.fail != UT64_MAX) {
          flow.fallthrough = operation.fail;
        }
      }
    }
    rz_analysis_op_fini(&operation);
    if (!row.flow_target) {
      row.flow_target = lldb_target;
      if (references != nullptr && row.flow_kind == InstructionFlowKind::Call &&
          lldb_target) {
        references->append(row, *lldb_target, false, false);
      }
    }
    return flow;
  }

private:
  bool configure(const SessionSnapshot &state, std::string &failure) {
    std::string plugin;
    if (is_x86_architecture(state.architecture)) {
      plugin = "x86";
    } else if (state.architecture.find("aarch64") != std::string::npos ||
               state.architecture.find("arm64") != std::string::npos ||
               state.architecture.starts_with("arm")) {
      plugin = "arm";
    } else if (state.architecture.find("riscv") != std::string::npos) {
      plugin = "riscv";
    } else if (state.architecture.find("mips") != std::string::npos) {
      plugin = "mips";
    } else {
      failure =
          l10n::format(l10n::Key::SnapshotAnalysisUnavailableForArchitecture,
                       state.architecture.c_str());
      return false;
    }
    const std::string configuration =
        plugin + ':' + std::to_string(state.address_byte_size * 8U) + ':' +
        state.byte_order;
    if (configuration == configuration_) {
      return true;
    }
    if (!analysis_ || !rz_analysis_use(analysis_.get(), plugin.c_str()) ||
        !rz_analysis_set_bits(analysis_.get(),
                              static_cast<int>(state.address_byte_size * 8U))) {
      failure = l10n::text(l10n::Key::SnapshotAnalysisArchitectureUnsupported);
      return false;
    }
    rz_analysis_set_big_endian(analysis_.get(),
                               state.byte_order == "big" ? 1 : 0);
    rz_analysis_set_os(analysis_.get(), "linux");
    configuration_ = configuration;
    return true;
  }

  static std::string expression_for(const RzAnalysisValue &operand) {
    if (operand.type == RZ_ANALYSIS_VAL_IMM) {
      std::ostringstream expression;
      expression << "0x" << std::hex << static_cast<std::uint64_t>(operand.imm);
      return expression.str();
    }
    std::ostringstream expression;
    if (operand.type == RZ_ANALYSIS_VAL_MEM || operand.memref != 0) {
      expression << '[';
    }
    bool has_component = false;
    if (operand.base != 0) {
      expression << "0x" << std::hex << operand.base;
      has_component = true;
    }
    if (operand.reg != nullptr && operand.reg->name != nullptr) {
      if (has_component) {
        expression << '+';
      }
      expression << operand.reg->name;
      has_component = true;
    }
    if (operand.regdelta != nullptr && operand.regdelta->name != nullptr) {
      if (has_component) {
        expression << '+';
      }
      expression << operand.regdelta->name;
      if (operand.mul > 1) {
        expression << '*' << std::dec << operand.mul;
      }
      has_component = true;
    }
    if (operand.delta != 0 || !has_component) {
      if (has_component && operand.delta >= 0) {
        expression << '+';
      }
      expression << std::showbase << std::hex << operand.delta;
    }
    if (operand.type == RZ_ANALYSIS_VAL_MEM || operand.memref != 0) {
      expression << ']';
    }
    return expression.str();
  }

  static std::optional<std::uint64_t>
  evaluate_operand(const RzAnalysisValue &operand, const InstructionRow &row,
                   const SessionSnapshot &state, bool &runtime,
                   std::string *failure = nullptr) {
    if (operand.type == RZ_ANALYSIS_VAL_IMM) {
      return static_cast<std::uint64_t>(operand.imm);
    }
    const bool x86 = is_x86_architecture(state.architecture);
    const bool memory =
        operand.type == RZ_ANALYSIS_VAL_MEM || operand.memref != 0;
    const auto unavailable = [failure](std::string_view reason) {
      if (failure != nullptr) {
        *failure = reason;
      }
    };
    const auto register_value = [&](const RzRegItem *reg)
        -> std::optional<std::uint64_t> {
      if (reg == nullptr) {
        return 0;
      }
      if (reg->name == nullptr) {
        return std::nullopt;
      }
      const std::string_view name{reg->name};
      if (x86 && memory && (name == "rip" || name == "eip")) {
        // Rizin src/dst displacements exclude the instruction length.
        const auto next = row.address + row.bytes.size();
        return name == "eip" ? static_cast<std::uint32_t>(next) : next;
      }
      if (row.address != state.pc || state.state != SessionState::Stopped) {
        return std::nullopt;
      }
      runtime = true;
      if (auto value = register_numeric(state, name)) {
        return value;
      }
      if (x86 && reg->size == 32) {
        constexpr std::array<std::pair<std::string_view, std::string_view>, 16>
            aliases{{{"eax", "rax"}, {"ebx", "rbx"}, {"ecx", "rcx"},
                     {"edx", "rdx"}, {"esi", "rsi"}, {"edi", "rdi"},
                     {"esp", "rsp"}, {"ebp", "rbp"}, {"r8d", "r8"},
                     {"r9d", "r9"}, {"r10d", "r10"}, {"r11d", "r11"},
                     {"r12d", "r12"}, {"r13d", "r13"}, {"r14d", "r14"},
                     {"r15d", "r15"}}};
        for (const auto &[alias, full] : aliases) {
          if (name == alias) {
            if (auto value = register_numeric(state, full)) {
              return static_cast<std::uint32_t>(*value);
            }
            break;
          }
        }
      }
      return std::nullopt;
    };
    // Some non-x86 plugins omit index extension/shift metadata. Do not
    // manufacture an effective address from an incomplete expression.
    if (!x86 && memory && operand.regdelta != nullptr) {
      unavailable(l10n::text(l10n::Key::SnapshotIndexedAddressIncomplete));
      return std::nullopt;
    }
    const auto base = register_value(operand.reg);
    const auto index = register_value(operand.regdelta);
    if (!base || !index) {
      unavailable(l10n::text(l10n::Key::SnapshotRegisterValueUnavailable));
      return std::nullopt;
    }
    std::uint64_t value = operand.base + *base +
                          *index * std::max<std::uint64_t>(1, operand.mul) +
                          static_cast<std::uint64_t>(operand.delta);
    if (state.address_byte_size == 4 ||
        (x86 && memory &&
         ((operand.reg != nullptr && operand.reg->size == 32) ||
          (operand.regdelta != nullptr && operand.regdelta->size == 32)))) {
      value = static_cast<std::uint32_t>(value);
    }
    if (memory && operand.seg != nullptr) {
      const std::string_view segment =
          operand.seg->name != nullptr ? operand.seg->name : "";
      if (!x86 || state.address_byte_size != 8 ||
          (segment != "cs" && segment != "ds" && segment != "es" &&
           segment != "ss" && segment != "fs" && segment != "gs")) {
        unavailable(l10n::text(l10n::Key::SnapshotSegmentBaseUnavailable));
        return std::nullopt;
      }
      if (segment == "fs" || segment == "gs") {
        if (row.address != state.pc || state.state != SessionState::Stopped) {
          return std::nullopt;
        }
        auto segment_base = register_numeric(
            state, segment == "fs" ? "fs_base" : "gs_base");
        if (!segment_base) {
          segment_base =
              register_numeric(state, segment == "fs" ? "fsbase" : "gsbase");
        }
        if (!segment_base) {
          unavailable(l10n::text(l10n::Key::SnapshotSegmentBaseUnavailable));
          return std::nullopt;
        }
        runtime = true;
        value += *segment_base;
      }
    }
    return value;
  }

  static void capture_references(InstructionRow &row,
                                 const RzAnalysisOp &operation,
                                 InstructionReferences &references,
                                 const SessionSnapshot &state) {
    const auto type = operation.type & 0xffffU;
    constexpr auto indirect = RZ_ANALYSIS_OP_TYPE_IND |
                              RZ_ANALYSIS_OP_TYPE_REG |
                              RZ_ANALYSIS_OP_TYPE_MEM;
    if ((type == RZ_ANALYSIS_OP_TYPE_CALL ||
         type == RZ_ANALYSIS_OP_TYPE_JMP) &&
        (operation.type & indirect) == 0 && operation.jump != UT64_MAX) {
      references.append(row, operation.jump, false, false);
    }
    const auto append_value = [&](const RzAnalysisValue *operand,
                                  bool destination) {
      if (operand == nullptr || operand->type == RZ_ANALYSIS_VAL_UNK ||
          (destination && operand->type == RZ_ANALYSIS_VAL_REG &&
           operand->memref == 0)) {
        return;
      }
      bool runtime = false;
      if (const auto address = evaluate_operand(*operand, row, state, runtime)) {
        references.append(row, *address, runtime);
      }
    };
    append_value(operation.dst, true);
    for (const auto *source : operation.src) {
      append_value(source, false);
    }

    const bool x86 = is_x86_architecture(state.architecture);
    const bool control = type == RZ_ANALYSIS_OP_TYPE_CALL ||
                         type == RZ_ANALYSIS_OP_TYPE_UCALL ||
                         type == RZ_ANALYSIS_OP_TYPE_JMP ||
                         type == RZ_ANALYSIS_OP_TYPE_UJMP;
    // The x86 plugin has no src/dst values for indirect calls and jumps.
    // Its access list does include their complete memory operands (including
    // segments and scaled indexes), unlike operation.ptr, which can be only
    // a displacement. Ignore implicit stack writes.
    if (x86 && control) {
      std::optional<std::uint64_t> target_slot;
      bool target_runtime = false;
      std::size_t memory_operands = 0;
      for (const RzListIter *iterator = rz_list_head(operation.access);
           iterator != nullptr; iterator = iterator->next) {
        const auto *access =
            static_cast<const RzAnalysisValue *>(iterator->elem);
        if (access->type != RZ_ANALYSIS_VAL_MEM ||
            access->access == RZ_ANALYSIS_ACC_W) {
          continue;
        }
        ++memory_operands;
        RzAnalysisValue operand = *access;
        if (operand.reg != nullptr && operand.reg->name != nullptr &&
            (std::string_view{operand.reg->name} == "rip" ||
             std::string_view{operand.reg->name} == "eip")) {
          // Unlike src/dst values, access-list PC displacements for these
          // single-operand instructions already include the instruction size.
          operand.delta -= static_cast<st64>(row.bytes.size());
        }
        bool runtime = false;
        if (const auto address = evaluate_operand(operand, row, state, runtime)) {
          references.append(row, *address, runtime);
          if (operand.memref > 0 &&
              static_cast<std::uint32_t>(operand.memref) ==
                  state.address_byte_size) {
            target_slot = *address;
            target_runtime = runtime;
          }
        }
      }
      if (memory_operands == 1 && target_slot &&
          (type == RZ_ANALYSIS_OP_TYPE_UCALL ||
           type == RZ_ANALYSIS_OP_TYPE_UJMP ||
           (operation.type & indirect) != 0)) {
        // The branch consumes exactly one pointer, not the last symbol in
        // a pointer walk. Reuse the capture cache even for executable slots.
        row.flow_target = references.pointer_at(*target_slot);
        if (row.flow_target) {
          references.append(row, *row.flow_target, target_runtime, false);
        }
      }
    }
    // Rizin's explicit register destination is authoritative for register
    // branches (also AArch64 BR/BLR); a memory base register is not a target.
    if (control && operation.reg != nullptr && operation.ptr == -1 &&
        (operation.type & RZ_ANALYSIS_OP_TYPE_REG) != 0 &&
        (operation.type &
         (RZ_ANALYSIS_OP_TYPE_IND | RZ_ANALYSIS_OP_TYPE_MEM)) == 0 &&
        row.address == state.pc && state.state == SessionState::Stopped) {
      if (auto value = register_numeric(state, operation.reg)) {
        if (state.address_byte_size == 4) {
          *value = static_cast<std::uint32_t>(*value);
        }
        const auto *region = region_containing(state, *value);
        if (region != nullptr && (region->readable || region->executable)) {
          row.flow_target = *value;
        }
        references.append(row, *value, true);
      }
    }
    // Immediate PUSH has no src/dst values either. For other architectures,
    // only a LEA's decoded address is safe: LOAD ptr can be a bare displacement.
    if (operation.ptr != -1 &&
        ((x86 && type == RZ_ANALYSIS_OP_TYPE_PUSH) ||
         (!x86 && type == RZ_ANALYSIS_OP_TYPE_LEA))) {
      references.append(row, static_cast<std::uint64_t>(operation.ptr), false);
    }
  }

  static void append_operand(InstructionRow &row, std::string role,
                             const RzAnalysisValue *operand,
                             lldb::SBTarget &target, lldb::SBProcess &process,
                             const SessionSnapshot &state) {
    if (operand == nullptr || operand->type == RZ_ANALYSIS_VAL_UNK) {
      return;
    }
    ResolvedOperandInfo resolved{};
    resolved.role = std::move(role);
    resolved.expression = expression_for(*operand);
    resolved.memory =
        operand->type == RZ_ANALYSIS_VAL_MEM || operand->memref != 0;
    bool runtime = false;
    const auto value =
        evaluate_operand(*operand, row, state, runtime, &resolved.error);
    if (value) {
      resolved.value = *value;
      resolved.has_value = true;
      if (resolved.memory ||
          region_containing(state, resolved.value) != nullptr) {
        resolved.pointer_chain =
            resolve_pointer_chain(target, process, state, resolved.value);
      }
    }
    row.resolved_operands.push_back(std::move(resolved));
  }

  static void append_register_argument(InstructionRow &row,
                                       std::string_view name,
                                       lldb::SBTarget &target,
                                       lldb::SBProcess &process,
                                       const SessionSnapshot &state) {
    AbiArgumentInfo argument{};
    argument.name = name;
    if (const auto value = register_numeric(state, name)) {
      argument.value = *value;
      argument.available = true;
      if (region_containing(state, *value) != nullptr) {
        argument.pointer_chain =
            resolve_pointer_chain(target, process, state, *value);
      }
    } else {
      argument.error = l10n::text(l10n::Key::SnapshotRegisterUnavailable);
    }
    row.arguments.push_back(std::move(argument));
  }
  static void append_stack_argument(InstructionRow &row, std::size_t index,
                                    lldb::SBTarget &target,
                                    lldb::SBProcess &process,
                                    const SessionSnapshot &state) {
    AbiArgumentInfo argument{};
    argument.name = "arg" + std::to_string(index);
    const std::uint32_t width = state.address_byte_size;
    if (width == 0 || width > sizeof(std::uint64_t) ||
        state.sp >
            std::numeric_limits<std::uint64_t>::max() - (index + 1U) * width) {
      argument.error =
          l10n::text(l10n::Key::SnapshotStackArgumentAddressUnavailable);
      row.arguments.push_back(std::move(argument));
      return;
    }
    std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
    lldb::SBError error;
    const std::uint64_t address = state.sp + (index + 1U) * width;
    const std::size_t read =
        process.ReadMemory(address, bytes.data(), width, error);
    if (read != width || error.Fail()) {
      argument.error = error.Fail()
                           ? error_text(error)
                           : l10n::text(l10n::Key::SnapshotShortArgumentRead);
    } else {
      argument.value =
          decode_pointer(bytes.data(), width, target.GetByteOrder());
      argument.available = true;
      if (region_containing(state, argument.value) != nullptr) {
        argument.pointer_chain =
            resolve_pointer_chain(target, process, state, argument.value);
      }
    }
    row.arguments.push_back(std::move(argument));
  }

  static void capture_arguments(InstructionRow &row, lldb::SBTarget &target,
                                lldb::SBProcess &process,
                                const SessionSnapshot &state) {
    static constexpr std::array<std::string_view, 6> x86_call{
        "rdi", "rsi", "rdx", "rcx", "r8", "r9"};
    static constexpr std::array<std::string_view, 6> x86_syscall{
        "rdi", "rsi", "rdx", "r10", "r8", "r9"};
    static constexpr std::array<std::string_view, 7> x86_32_syscall{
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"};
    static constexpr std::array<std::string_view, 8> arm64{
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"};
    static constexpr std::array<std::string_view, 6> arm{
        "r0", "r1", "r2", "r3", "r4", "r5"};
    static constexpr std::array<std::string_view, 8> arguments{
        "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"};
    const bool syscall = row.flow_kind == InstructionFlowKind::Syscall;
    std::string_view syscall_register;
    std::span<const std::string_view> registers;
    if (state.architecture == "x86_64") {
      syscall_register = "rax";
      registers = syscall ? x86_syscall : x86_call;
    } else if (is_x86_architecture(state.architecture)) {
      if (!syscall) {
        for (std::size_t index = 0; index < 6; ++index) {
          append_stack_argument(row, index, target, process, state);
        }
        return;
      }
      registers = x86_32_syscall;
    } else if (state.architecture.find("aarch64") != std::string::npos ||
               state.architecture.find("arm64") != std::string::npos) {
      syscall_register = "x8";
      registers = std::span{arm64}.first(syscall ? 6 : 8);
    } else if (state.architecture.starts_with("arm")) {
      syscall_register = "r7";
      registers = std::span{arm}.first(syscall ? 6 : 4);
    } else if (state.architecture.find("riscv") != std::string::npos) {
      syscall_register = "a7";
      registers = std::span{arguments}.first(syscall ? 6 : 8);
    } else if (state.architecture.find("mips") != std::string::npos) {
      syscall_register = "v0";
      registers = std::span{arguments}.first(4);
    }
    if (syscall && !syscall_register.empty()) {
      append_register_argument(row, syscall_register, target, process, state);
    }
    for (const std::string_view name : registers) {
      append_register_argument(row, name, target, process, state);
    }
  }

  std::unique_ptr<RzAnalysis, decltype(&rz_analysis_free)> analysis_;
  std::string configuration_;
};

void capture_stack(lldb::SBTarget &target, lldb::SBProcess &process,
                   SessionSnapshot &state) {
  state.stack.clear();
  const std::uint32_t pointer_size = target.GetAddressByteSize();
  if (pointer_size == 0 || pointer_size > sizeof(std::uint64_t) ||
      state.sp == LLDB_INVALID_ADDRESS) {
    return;
  }

  constexpr std::size_t entry_count = 32;
  std::array<std::uint8_t, entry_count * sizeof(std::uint64_t)> bytes{};
  const std::size_t requested = entry_count * pointer_size;
  lldb::SBError error;
  const std::size_t bytes_read =
      process.ReadMemory(state.sp, bytes.data(), requested, error);
  const std::size_t available_entries = bytes_read / pointer_size;
  state.stack.reserve(available_entries);
  for (std::size_t index = 0; index < available_entries; ++index) {
    const std::uint64_t value =
        decode_pointer(bytes.data() + index * pointer_size, pointer_size,
                       target.GetByteOrder());
    state.stack.push_back(StackEntry{
        .address = state.sp + index * pointer_size,
        .value = value,
        .symbol = symbol_for_address(target, value),
        .pointer_chain = resolve_pointer_chain(target, process, state, value),
    });
  }
}

InstructionRow capture_instruction_row(lldb::SBInstruction instruction,
                                       lldb::SBTarget &target) {
  InstructionRow row;
  const lldb::SBAddress instruction_address = instruction.GetAddress();
  row.address = instruction_address.GetLoadAddress(target);
  const lldb::addr_t file_address = instruction_address.GetFileAddress();
  if (file_address != LLDB_INVALID_ADDRESS) {
    row.file_address = file_address;
    row.has_file_address = true;
  }
  row.mnemonic = safe_string(instruction.GetMnemonic(target));
  row.operands = safe_string(instruction.GetOperands(target));
  row.comment = safe_string(instruction.GetComment(target));
  row.flow_kind = convert_flow_kind(instruction.GetControlFlowKind(target));
  if (row.flow_kind == InstructionFlowKind::Call ||
      row.flow_kind == InstructionFlowKind::Jump ||
      row.flow_kind == InstructionFlowKind::ConditionalJump) {
    // LLDB already rendered this instruction in its per-address ISA mode.
    // Accept only a complete absolute destination, never a displacement or
    // an indirect expression. Conditional branches may have preceding
    // register/condition operands (CBZ, BEQ, etc.).
    auto operand = trim(row.operands);
    const bool indirect =
        operand.find_first_of("*[](){}!:+-/") != std::string_view::npos ||
        operand.find("ptr") != std::string_view::npos ||
        row.mnemonic.find("lr") != std::string::npos ||
        row.mnemonic.find("ctr") != std::string::npos ||
        row.mnemonic.find("tar") != std::string::npos;
    if (!indirect && row.flow_kind == InstructionFlowKind::ConditionalJump) {
      if (const auto comma = operand.rfind(',');
          comma != std::string_view::npos) {
        operand = trim(operand.substr(comma + 1));
      }
    }
    if (!indirect &&
        (operand.starts_with("0x") || operand.starts_with("0X"))) {
      row.flow_target = parse_integer(operand);
      if (row.flow_target == LLDB_INVALID_ADDRESS) {
        row.flow_target.reset();
      }
    }
  }

  lldb::SBData data = instruction.GetData(target);
  const std::size_t byte_count = data.GetByteSize();
  row.bytes.resize(byte_count);
  if (byte_count != 0) {
    lldb::SBError data_error;
    const std::size_t bytes_read =
        data.ReadRawData(data_error, 0, row.bytes.data(), byte_count);
    if (data_error.Fail()) {
      row.bytes.clear();
    } else {
      row.bytes.resize(bytes_read);
    }
  }
  return row;
}

void capture_instructions(lldb::SBTarget &target, lldb::addr_t start_address,
                          SessionSnapshot &state) {
  state.instructions.clear();
  state.disassembly_graph.reset();
  const lldb::SBAddress address = target.ResolveLoadAddress(start_address);
  if (!address.IsValid()) {
    return;
  }

  lldb::SBInstructionList instructions =
      state.supports_intel_syntax
          ? target.ReadInstructions(address, 48,
                                    state.intel_syntax ? "intel" : "att")
          : target.ReadInstructions(address, 48);
  const std::size_t instruction_count = instructions.GetSize();
  state.instructions.reserve(instruction_count);
  static thread_local InstructionAnalyzer analyzer;
  InstructionDebugMetadata debug(target);
  InstructionReferences references(target, state, debug);
  std::string failure;
  const bool configured = analyzer.configure_graph(state, failure);
  lldb::SBProcess process = target.GetProcess();
  for (std::size_t index = 0; index < instruction_count; ++index) {
    state.instructions.push_back(capture_instruction_row(
        instructions.GetInstructionAtIndex(static_cast<std::uint32_t>(index)),
        target));
    auto &row = state.instructions.back();
    if (configured) {
      analyzer.analyze_flow(row, &references, state);
    }
    if (row.address == state.pc && state.state == SessionState::Stopped) {
      analyzer.analyze(row, target, process, state);
    }
    debug.capture(row);
    if (!configured && row.flow_kind == InstructionFlowKind::Call &&
        row.flow_target) {
      references.append(row, *row.flow_target, false, false);
    }
    group_debug_metadata(row,
                         index == 0 ? nullptr : &state.instructions[index - 1]);
  }
}

void capture_disassembly_graph(lldb::SBTarget &target,
                               lldb::addr_t requested_address,
                               SessionSnapshot &state) {
  constexpr std::size_t maximum_bytes = 64 * 1024;
  constexpr std::size_t maximum_instructions = 4096;
  constexpr std::uint32_t maximum_ranges = 128;
  constexpr std::size_t fallback_bytes = 4096;
  constexpr std::size_t fallback_instructions = 256;
  auto graph = std::make_shared<DisassemblyGraph>();
  graph->address = requested_address;
  const auto partial = [&graph](std::string_view reason) {
    if (graph->status.find(reason) != std::string::npos) {
      return;
    }
    graph->status += graph->status.empty()
                         ? l10n::text(l10n::Key::SnapshotPartialGraphPrefix)
                         : "; ";
    graph->status += reason;
  };
  lldb::SBAddress requested = target.ResolveLoadAddress(requested_address);
  if (!requested.IsValid()) {
    graph->status = l10n::text(l10n::Key::SnapshotGraphAddressUnresolved);
    state.disassembly_graph = std::move(graph);
    return;
  }

  struct AddressRange {
    std::uint64_t start;
    std::uint64_t end;
  };
  std::vector<AddressRange> ranges;
  lldb::SBFunction function = requested.GetFunction();
  if (function.IsValid()) {
    graph->name = safe_string(function.GetName());
    lldb::SBAddressRangeList function_ranges = function.GetRanges();
    const std::uint32_t count = function_ranges.GetSize();
    if (count > maximum_ranges) {
      partial(l10n::text(l10n::Key::SnapshotGraphRangeLimitReached));
    }
    for (std::uint32_t index = 0; index < std::min(count, maximum_ranges);
         ++index) {
      lldb::SBAddressRange range =
          function_ranges.GetAddressRangeAtIndex(index);
      const auto start = range.GetBaseAddress().GetLoadAddress(target);
      const auto size = range.GetByteSize();
      if (start != LLDB_INVALID_ADDRESS && size != 0 &&
          size <= std::numeric_limits<std::uint64_t>::max() - start) {
        ranges.push_back({start, start + size});
      } else {
        partial(l10n::text(l10n::Key::SnapshotGraphRangesUnavailable));
      }
    }
  }
  if (ranges.empty()) {
    lldb::SBSymbol symbol = requested.GetSymbol();
    if (symbol.IsValid()) {
      graph->name = safe_string(symbol.GetName());
      const auto start = symbol.GetStartAddress().GetLoadAddress(target);
      const auto end = symbol.GetEndAddress().GetLoadAddress(target);
      if (start != LLDB_INVALID_ADDRESS && end != LLDB_INVALID_ADDRESS &&
          start <= requested_address && requested_address < end) {
        ranges.push_back({start, end});
      }
    }
  }
  const bool bounded_function = !ranges.empty();
  if (!bounded_function) {
    partial(l10n::text(l10n::Key::SnapshotGraphBoundsUnavailable));
    const auto size = std::min<std::uint64_t>(
        fallback_bytes,
        std::numeric_limits<std::uint64_t>::max() - requested_address);
    ranges.push_back({requested_address, requested_address + size});
  }
  std::sort(ranges.begin(), ranges.end(),
            [](const AddressRange &left, const AddressRange &right) {
              return left.start < right.start;
            });
  // Merge overlapping debug-info ranges, without inventing instructions in
  // the holes between discontiguous hot/cold fragments.
  std::size_t merged_count = 0;
  for (const AddressRange range : ranges) {
    if (merged_count != 0 && range.start <= ranges[merged_count - 1].end) {
      ranges[merged_count - 1].end =
          std::max(ranges[merged_count - 1].end, range.end);
    } else {
      ranges[merged_count++] = range;
    }
  }
  ranges.resize(merged_count);
  graph->address = ranges.front().start;
  const auto instruction_limit =
      bounded_function ? maximum_instructions : fallback_instructions;
  std::vector<InstructionRow> rows;
  std::size_t remaining_bytes = maximum_bytes;
  for (const AddressRange range : ranges) {
    if (remaining_bytes == 0 || rows.size() == instruction_limit) {
      partial(l10n::text(l10n::Key::SnapshotGraphCaptureLimitReached));
      break;
    }
    const auto byte_count = static_cast<std::size_t>(
        std::min<std::uint64_t>(range.end - range.start, remaining_bytes));
    if (byte_count < range.end - range.start) {
      partial(l10n::text(l10n::Key::SnapshotGraphByteLimitReached));
    }
    std::vector<std::uint8_t> bytes(byte_count);
    lldb::SBAddress base = target.ResolveLoadAddress(range.start);
    lldb::SBError read_error;
    const auto bytes_read =
        target.ReadMemory(base, bytes.data(), bytes.size(), read_error);
    remaining_bytes -= byte_count;
    if (bytes_read != byte_count || read_error.Fail()) {
      partial(l10n::text(l10n::Key::SnapshotGraphBytesUnreadable));
    }
    if (bytes_read == 0) {
      continue;
    }
    lldb::SBInstructionList instructions =
        state.supports_intel_syntax
            ? target.GetInstructionsWithFlavor(
                  base, state.intel_syntax ? "intel" : "att", bytes.data(),
                  bytes_read)
            : target.GetInstructions(base, bytes.data(), bytes_read);
    auto expected_address = range.start;
    for (std::uint32_t index = 0; index < instructions.GetSize(); ++index) {
      if (rows.size() == instruction_limit) {
        partial(
            bounded_function
                ? l10n::text(l10n::Key::SnapshotGraphInstructionLimitReached)
                : l10n::text(l10n::Key::SnapshotGraphFallbackLimitReached));
        break;
      }
      InstructionRow row =
          capture_instruction_row(instructions.GetInstructionAtIndex(index),
                                  target);
      if (row.address != expected_address || row.bytes.empty() ||
          row.bytes.size() > range.start + bytes_read - expected_address) {
        partial(l10n::text(l10n::Key::SnapshotGraphDecodingStopped));
        break;
      }
      expected_address += row.bytes.size();
      rows.push_back(std::move(row));
    }
    if (expected_address != range.end) {
      partial(l10n::text(l10n::Key::SnapshotGraphBytesNotDecoded));
    }
  }
  if (rows.empty()) {
    partial(l10n::text(l10n::Key::SnapshotGraphInstructionsUnavailable));
    state.disassembly_graph = std::move(graph);
    return;
  }

  InstructionAnalyzer analyzer;
  InstructionDebugMetadata debug(target);
  InstructionReferences references(target, state, debug);
  std::string failure;
  const bool configured = analyzer.configure_graph(state, failure);
  if (!configured) {
    partial(failure);
  }
  std::vector<StaticInstructionFlow> flows;
  flows.reserve(rows.size());
  std::vector<bool> leaders(rows.size(), false);
  leaders.front() = true;
  for (std::size_t index = 0; index < rows.size(); ++index) {
    // Reuse flat-view hints without rereading their operands; this also keeps
    // the views identical if the larger graph reaches its bounded read budget.
    const auto flat = std::lower_bound(
        state.instructions.begin(), state.instructions.end(), rows[index].address,
        [](const InstructionRow &row, std::uint64_t address) {
          return row.address < address;
        });
    const bool reuse = flat != state.instructions.end() &&
                       flat->address == rows[index].address &&
                       flat->bytes == rows[index].bytes;
    flows.push_back(
        configured ? analyzer.analyze_flow(
                         rows[index], reuse ? nullptr : &references, state)
                   : StaticInstructionFlow{});
    if (reuse) {
      rows[index].flow_target = flat->flow_target;
      rows[index].references = flat->references;
    }
    debug.capture(rows[index]);
    if (!configured && !reuse &&
        rows[index].flow_kind == InstructionFlowKind::Call &&
        rows[index].flow_target) {
      references.append(rows[index], *rows[index].flow_target, false, false);
    }
    group_debug_metadata(rows[index], index == 0 ? nullptr : &rows[index - 1]);
    if (index != 0 &&
        rows[index - 1].address + rows[index - 1].bytes.size() !=
            rows[index].address) {
      leaders[index] = true;
    }
  }
  const std::size_t no_instruction = rows.size();
  std::vector<std::size_t> terminators(rows.size(), no_instruction);
  std::vector<std::size_t> delay_owners(rows.size(), no_instruction);
  for (std::size_t index = 0; index < rows.size(); ++index) {
    StaticInstructionFlow &flow = flows[index];
    if (!flow.terminates) {
      continue;
    }
    auto end = index;
    for (unsigned slot = 0; slot < flow.delay_slots; ++slot) {
      if (end + 1 == rows.size() || leaders[end + 1] ||
          flows[end + 1].terminates ||
          rows[end + 1].flow_kind == InstructionFlowKind::Call) {
        flow.unsupported = true;
        partial(l10n::text(l10n::Key::SnapshotGraphDelaySlotUnsupported));
        end = index;
        break;
      }
      ++end;
    }
    if (flow.unsupported) {
      partial(l10n::text(l10n::Key::SnapshotGraphInstructionFlowUnsupported));
    } else {
      for (auto slot = index + 1; slot <= end; ++slot) {
        delay_owners[slot] = index;
      }
      if (flow.conditional && flow.delay_slots != 0) {
        // Rizin's basic operation records delay count, but not whether a
        // conditional instruction annuls the slot on its untaken path.
        partial(
            l10n::text(l10n::Key::SnapshotGraphDelaySlotAnnulmentUnsupported));
      }
    }
    const auto continuation = rows[end].address + rows[end].bytes.size();
    if (flow.conditional &&
        (!flow.fallthrough ||
         (flow.delay_slots != 0 && *flow.fallthrough < continuation))) {
      // Some Rizin plugins report fail at the delay instruction itself.
      flow.fallthrough = continuation;
    }
    terminators[end] = index;
    if (end + 1 < rows.size()) {
      leaders[end + 1] = true;
    }
  }
  const auto mark_destination = [&](std::optional<std::uint64_t> &address) {
    if (!address) {
      return;
    }
    const auto found = std::lower_bound(
        rows.begin(), rows.end(), *address,
        [](const InstructionRow &row, std::uint64_t value) {
          return row.address < value;
        });
    if (found != rows.end() && found->address == *address) {
      leaders[static_cast<std::size_t>(found - rows.begin())] = true;
    } else if (found != rows.begin()) {
      const InstructionRow &previous = *(found - 1);
      if (*address < previous.address + previous.bytes.size()) {
        partial(l10n::text(l10n::Key::SnapshotGraphBranchEntersInstruction));
        address.reset();
      }
    }
  };
  for (StaticInstructionFlow &flow : flows) {
    if (!flow.unsupported) {
      mark_destination(flow.target);
      mark_destination(flow.fallthrough);
    }
  }
  for (std::size_t index = 0; index < rows.size(); ++index) {
    if (!leaders[index] || delay_owners[index] == no_instruction) {
      continue;
    }
    const auto owner = delay_owners[index];
    flows[owner].unsupported = true;
    partial(l10n::text(l10n::Key::SnapshotGraphDelaySlotBranchUnsupported));
    for (auto end = owner + 1; end < rows.size() &&
                                   delay_owners[end] == owner; ++end) {
      terminators[end] = no_instruction;
    }
    terminators[owner] = owner;
    leaders[owner + 1] = true;
  }
  for (std::size_t start = 0; start < rows.size();) {
    auto end = start + 1;
    while (end < rows.size() && !leaders[end]) {
      ++end;
    }
    DisassemblyGraphBlock block;
    block.address = rows[start].address;
    // A block is also an independent reading entry point; retain its source
    // location even when the preceding block ended on the same source line.
    rows[start].begins_source = rows[start].source != nullptr;
    const auto last = end - 1;
    const auto continuation = rows[last].address + rows[last].bytes.size();
    if (configured) {
      if (terminators[last] != no_instruction) {
        const StaticInstructionFlow &flow = flows[terminators[last]];
        if (flow.unsupported) {
          block.edges.push_back({DisassemblyGraphEdge::Kind::Jump, std::nullopt});
        } else if (flow.conditional) {
          block.edges.push_back({DisassemblyGraphEdge::Kind::Taken, flow.target});
          block.edges.push_back(
              {DisassemblyGraphEdge::Kind::Fallthrough, flow.fallthrough});
        } else if (!flow.returns) {
          block.edges.push_back({DisassemblyGraphEdge::Kind::Jump, flow.target});
        }
        if (!flow.returns && !flow.target) {
          partial(
              l10n::text(l10n::Key::SnapshotGraphIndirectBranchesUnresolved));
        }
      } else {
        block.edges.push_back(
            {DisassemblyGraphEdge::Kind::Fallthrough, continuation});
      }
    }
    block.instructions.reserve(end - start);
    for (auto index = start; index < end; ++index) {
      block.instructions.push_back(std::move(rows[index]));
    }
    graph->blocks.push_back(std::move(block));
    start = end;
  }
  state.disassembly_graph = std::move(graph);
}

std::optional<std::uint64_t> fault_address_from_stop(std::string_view text) {
  const std::size_t marker = text.find("fault address");
  if (marker == std::string_view::npos) {
    return std::nullopt;
  }
  const std::size_t position = text.find("0x", marker);
  if (position == std::string_view::npos) {
    return std::nullopt;
  }
  std::size_t end = position + 2;
  while (end < text.size() &&
         std::isxdigit(static_cast<unsigned char>(text[end])) != 0) {
    ++end;
  }
  return end == position + 2
             ? std::nullopt
             : parse_integer(text.substr(position, end - position));
}

void find_cyclic_matches(lldb::SBTarget &target, lldb::SBProcess &process,
                         const SessionSnapshot &state, CrashInfo &crash) {
  constexpr std::size_t pattern_size = 65536;
  constexpr std::size_t subsequence_size = 4;
  constexpr std::size_t maximum_matches = 32;
  const std::string pattern = cyclic_pattern(pattern_size);
  std::unordered_set<std::string> seen;

  const auto add_bytes = [&](std::string source, const std::uint8_t *bytes,
                             std::size_t size, std::uint64_t memory_address,
                             bool has_address) {
    if (size < subsequence_size ||
        crash.cyclic_matches.size() >= maximum_matches) {
      return;
    }
    for (std::size_t index = 0; index + subsequence_size <= size &&
                                crash.cyclic_matches.size() < maximum_matches;
         ++index) {
      const std::string_view needle{
          reinterpret_cast<const char *>(bytes + index), subsequence_size};
      const std::size_t offset = pattern.find(needle);
      if (offset == std::string::npos) {
        continue;
      }
      const std::string key = source + ':' +
                              std::to_string(memory_address + index) + ':' +
                              std::to_string(offset);
      if (seen.insert(key).second) {
        crash.cyclic_matches.push_back(CyclicMatch{
            .source = source,
            .address = memory_address + index,
            .has_address = has_address,
            .offset = offset,
            .bytes = std::string{needle},
        });
      }
    }
  };

  for (const RegisterValue &value : state.registers) {
    if (!value.has_numeric_value) {
      continue;
    }
    std::array<std::uint8_t, sizeof(std::uint64_t)> bytes{};
    std::uint64_t remaining = value.numeric_value;
    for (std::size_t index = 0; index < state.address_byte_size; ++index) {
      bytes[index] = static_cast<std::uint8_t>(remaining & 0xffU);
      remaining >>= 8U;
    }
    if (target.GetByteOrder() == lldb::eByteOrderBig) {
      std::reverse(bytes.begin(), bytes.begin() + state.address_byte_size);
    }
    add_bytes("register " + value.name, bytes.data(), state.address_byte_size,
              0, false);

    const MemoryRegionInfo *region =
        region_containing(state, value.numeric_value);
    if (region == nullptr || !region->readable) {
      continue;
    }
    std::array<std::uint8_t, 64> pointed{};
    lldb::SBError error;
    const std::size_t read = process.ReadMemory(
        value.numeric_value, pointed.data(), pointed.size(), error);
    if (read != 0 && !error.Fail()) {
      add_bytes(value.name + " memory", pointed.data(), read,
                value.numeric_value, true);
    }
  }
}

void capture_crash(lldb::SBTarget &target, lldb::SBProcess &process,
                   lldb::SBThread &thread, SessionSnapshot &state) {
  state.crash = {};
  if (thread.GetStopReason() != lldb::eStopReasonSignal) {
    return;
  }
  const std::uint64_t signal = thread.GetStopReasonDataCount() == 0
                                   ? 0
                                   : thread.GetStopReasonDataAtIndex(0);
  if (signal != SIGSEGV && signal != SIGBUS && signal != SIGILL &&
      signal != SIGABRT && signal != SIGFPE) {
    return;
  }

  state.crash.crashed = true;
  state.crash.signal_number = static_cast<std::uint32_t>(signal);
  if (lldb::SBUnixSignals signals = process.GetUnixSignals();
      signals.IsValid()) {
    state.crash.signal_name =
        safe_string(signals.GetSignalAsCString(static_cast<int>(signal)));
  }
  if (state.crash.signal_name.empty()) {
    state.crash.signal_name =
        l10n::format(l10n::Key::SnapshotSignalNumber, signal);
  }
  if (const auto address = fault_address_from_stop(state.stop_reason)) {
    state.crash.fault_address = *address;
    state.crash.has_fault_address = true;
  }

  const MemoryRegionInfo *pc_region = region_containing(state, state.pc);
  state.crash.stack_executable = !state.security.nx;
  state.crash.control_flow_suspect =
      pc_region == nullptr || !pc_region->executable;
  find_cyclic_matches(target, process, state, state.crash);
  state.crash.control_flow_suspect =
      state.crash.control_flow_suspect ||
      std::any_of(state.crash.cyclic_matches.begin(),
                  state.crash.cyclic_matches.end(),
                  [](const CyclicMatch &match) {
                    return match.source == "register rip" ||
                           match.source == "register eip" ||
                           match.source == "register pc";
                  });
  std::ostringstream summary;
  if (state.crash.has_fault_address) {
    summary << l10n::format(l10n::Key::SnapshotSignalAtFaultAddress,
                            state.crash.signal_name.c_str(),
                            state.crash.fault_address);
  } else {
    summary << state.crash.signal_name;
  }
  if (state.crash.control_flow_suspect) {
    summary << l10n::text(l10n::Key::SnapshotControlFlowSuspectSummary);
  }
  if (!state.crash.cyclic_matches.empty()) {
    summary << l10n::text(l10n::Key::SnapshotCyclicEvidenceSummary);
  }
  state.crash.summary = summary.str();
}

void record_stop_history(SessionSnapshot &state) {
  StopHistoryEntry entry{
      .generation = state.generation,
      .stop_revision = state.stop_revision,
      .thread_id = state.thread_id,
      .pc = state.pc,
      .sp = state.sp,
      .stop_reason = state.stop_reason,
      .registers = state.registers,
  };
  for (RegisterValue &value : entry.registers) {
    value.pointer_chain.clear();
  }
  const auto existing =
      std::find_if(state.stop_history.begin(), state.stop_history.end(),
                   [&entry](const StopHistoryEntry &candidate) {
                     return candidate.generation == entry.generation &&
                            candidate.stop_revision == entry.stop_revision &&
                            candidate.thread_id == entry.thread_id;
                   });
  if (existing != state.stop_history.end()) {
    *existing = std::move(entry);
    return;
  }
  constexpr std::size_t maximum_entries = 32;
  state.stop_history.push_back(std::move(entry));
  while (state.stop_history.size() > maximum_entries) {
    state.stop_history.pop_front();
  }
}
namespace {

constexpr std::array<std::string_view, 32> mips_general_register_names{
    "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
    "t0",   "t1", "t2", "t3", "t4", "t5", "t6", "t7",
    "s0",   "s1", "s2", "s3", "s4", "s5", "s6", "s7",
    "t8",   "t9", "k0", "k1", "gp", "sp", "fp", "ra"};

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

std::optional<std::string>
send_remote_packet(lldb::SBTarget &target, std::string_view packet,
                   std::string &failure) {
  lldb::SBCommandReturnObject result;
  std::string command = "process plugin packet send ";
  command.append(packet);
  target.GetDebugger().GetCommandInterpreter().HandleCommand(
      command.c_str(), result, false);
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
  const auto [end, error] =
      std::from_chars(numbered.data(), numbered.data() + numbered.size(),
                      number, 10);
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
  const auto register_block =
      read_remote_packet(target, "g", failure);
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

} // namespace

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

bool write_frameless_qemu_mips_register(
    lldb::SBTarget &target, const SessionSnapshot &state,
    std::string_view register_name, std::uint64_t value,
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


void capture_stop(lldb::SBTarget &target, lldb::SBProcess &process,
                  std::optional<lldb::addr_t> memory_view_address,
                  std::optional<lldb::addr_t> instruction_view_address,
                  SessionSnapshot &state) {
  state.state = SessionState::Stopped;
  state.stop_revision = process.GetStopID();
  state.process_id = process.GetProcessID();
  state.registers.clear();
  state.disassembly_graph.reset();
  std::vector<InstructionRow> previous_instructions =
      std::move(state.instructions);
  state.memory.clear();
  state.has_pc_file_address = false;
  state.pc_file_address = 0;
  state.pc_module_load_bias = 0;
  state.pc_module_path.clear();
  state.error.clear();

  lldb::SBThread thread = process.GetSelectedThread();
  if (!thread.IsValid() && process.GetNumThreads() != 0) {
    thread = process.GetThreadAtIndex(0);
  }
  if (!thread.IsValid()) {
    state.error = l10n::text(l10n::Key::SnapshotStopThreadMissing);
    return;
  }

  state.thread_id = thread.GetThreadID();
  const StopHistoryEntry *previous_stop = nullptr;
  for (auto candidate = state.stop_history.rbegin();
       candidate != state.stop_history.rend(); ++candidate) {
    if (candidate->generation == state.generation &&
        candidate->thread_id == state.thread_id &&
        candidate->stop_revision != state.stop_revision) {
      previous_stop = &*candidate;
      break;
    }
  }
  std::array<char, 1024> stop_buffer{};
  const std::size_t stop_length =
      thread.GetStopDescription(stop_buffer.data(), stop_buffer.size());
  if (stop_length != 0) {
    state.stop_reason.assign(stop_buffer.data(),
                             std::min(stop_length, stop_buffer.size() - 1));
  } else {
    state.stop_reason = l10n::text(l10n::Key::SnapshotStopped);
  }

  lldb::SBFrame frame = thread.GetSelectedFrame();
  if (!frame.IsValid() && thread.GetNumFrames() != 0) {
    frame = thread.GetFrameAtIndex(0);
  }
  const bool frameless_mips = !frame.IsValid();
  if (frameless_mips) {
    if (!is_frameless_qemu_mips_stop(process, state) ||
        !capture_frameless_qemu_mips_registers(target, state)) {
      state.error = l10n::text(l10n::Key::SnapshotStopFrameMissing);
      return;
    }
  } else {
    state.pc = frame.GetPC();
    state.sp = frame.GetSP();
    lldb::SBValueList register_sets = frame.GetRegisters();
    for (std::uint32_t set_index = 0; set_index < register_sets.GetSize();
         ++set_index) {
      lldb::SBValue register_set = register_sets.GetValueAtIndex(set_index);
      const std::uint32_t register_count = register_set.GetNumChildren();
      for (std::uint32_t register_index = 0; register_index < register_count;
           ++register_index) {
        lldb::SBValue value = register_set.GetChildAtIndex(register_index);
        RegisterValue captured{};
        captured.name = safe_string(value.GetName());
        captured.value = register_value_text(value);
        captured.byte_size = value.GetByteSize();
        if (const auto numeric = register_value_as_unsigned(value)) {
          captured.numeric_value = *numeric;
          captured.has_numeric_value = true;
        }
        state.registers.push_back(std::move(captured));
      }
    }
  }

  lldb::SBAddress pc_address =
      frameless_mips ? target.ResolveLoadAddress(state.pc)
                     : frame.GetPCAddress();
  const lldb::addr_t pc_file_address = pc_address.GetFileAddress();
  const lldb::addr_t pc_load_address = pc_address.GetLoadAddress(target);
  if (pc_file_address != LLDB_INVALID_ADDRESS &&
      pc_load_address != LLDB_INVALID_ADDRESS) {
    state.has_pc_file_address = true;
    state.pc_file_address = pc_file_address;
    state.pc_module_load_bias = pc_load_address - pc_file_address;
    state.pc_module_path = module_path(pc_address.GetModule());
  }

  if (previous_stop != nullptr) {
    for (RegisterValue &captured : state.registers) {
      const auto previous = std::find_if(
          previous_stop->registers.begin(), previous_stop->registers.end(),
          [&captured](const RegisterValue &candidate) {
            return candidate.name == captured.name;
          });
      if (previous != previous_stop->registers.end()) {
        captured.previous_value = previous->value;
        captured.changed = captured.value != previous->value;
      }
    }
  }

  capture_memory_regions(target, process, state);
  capture_modules(target, state);
  for (RegisterValue &value : state.registers) {
    if (value.has_numeric_value &&
        region_containing(state, value.numeric_value) != nullptr) {
      value.pointer_chain =
          resolve_pointer_chain(target, process, state, value.numeric_value);
    }
  }

  std::optional<lldb::addr_t> instruction_start = instruction_view_address;
  if (!instruction_start) {
    const auto pc_instruction =
        std::find_if(previous_instructions.begin(), previous_instructions.end(),
                     [&state](const InstructionRow &instruction) {
                       return instruction.address == state.pc;
                     });
    if (pc_instruction != previous_instructions.end()) {
      const std::size_t pc_index = static_cast<std::size_t>(
          std::distance(previous_instructions.begin(), pc_instruction));
      constexpr std::size_t instructions_before_pc = 16;
      const std::size_t start_index = pc_index > instructions_before_pc
                                          ? pc_index - instructions_before_pc
                                          : 0;
      instruction_start = previous_instructions[start_index].address;
    }
  }
  if (!instruction_start && frame.IsValid()) {
    lldb::SBAddress context_start;
    lldb::SBFunction function = frame.GetFunction();
    if (function.IsValid()) {
      context_start = function.GetStartAddress();
    } else {
      lldb::SBSymbol symbol = frame.GetSymbol();
      if (symbol.IsValid()) {
        context_start = symbol.GetStartAddress();
      }
    }
    const lldb::addr_t context_load_address =
        context_start.IsValid() ? context_start.GetLoadAddress(target)
                                : LLDB_INVALID_ADDRESS;
    if (context_load_address != LLDB_INVALID_ADDRESS &&
        context_load_address <= state.pc) {
      instruction_start = context_load_address;
    }
  }

  capture_instructions(target, instruction_start.value_or(state.pc), state);
  if (!instruction_view_address &&
      std::none_of(state.instructions.begin(), state.instructions.end(),
                   [&state](const InstructionRow &instruction) {
                     return instruction.address == state.pc;
                   }) &&
      instruction_start != state.pc) {
    capture_instructions(target, state.pc, state);
  }

  const lldb::addr_t memory_address = memory_view_address.value_or(state.pc);
  if (memory_address != LLDB_INVALID_ADDRESS) {
    capture_memory(process, memory_address, state);
  }
  capture_threads(process, state);
  append_powerpc_fallback_frames(target, process, state);
  if (frameless_mips) {
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
  capture_heap(target, process, state);
  capture_stack(target, process, state);
  capture_crash(target, process, thread, state);
  record_stop_history(state);
}

} // namespace debugger::lldb_detail
