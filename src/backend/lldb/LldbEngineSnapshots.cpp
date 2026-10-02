#include "backend/lldb/LldbEngineInternal.h"
#include "backend/lldb/LldbInstructionCapture.h"
#include "backend/lldb/LldbRemoteArchitecture.h"
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

void append_output_chunk(SessionSnapshot &state, std::string_view data,
                         OutputStream stream) {
  if (data.empty()) {
    return;
  }
  constexpr std::size_t maximum_output_bytes = 1024U * 1024U;
  if (state.process_output.size() + data.size() > maximum_output_bytes) {
    const std::size_t discard =
        state.process_output.size() + data.size() - maximum_output_bytes;
    state.process_output.erase(0, discard);
  }
  state.process_output.append(data);

  state.output_chunks.push_back(OutputChunk{
      .sequence = ++state.output_sequence,
      .stream = stream,
      .data = std::string{data},
  });
  state.output_chunk_bytes += data.size();
  while (state.output_chunk_bytes > maximum_output_bytes &&
         !state.output_chunks.empty()) {
    state.output_chunk_bytes -= state.output_chunks.front().data.size();
    state.output_chunks.pop_front();
  }
  // Output-only updates still need to reach waiting consumers: the publish
  // guard compares revisions, so appends must look like changes.
  ++state.revision;
}

bool append_process_output(lldb::SBProcess &process, SessionSnapshot &state) {
  if (!process.IsValid()) {
    return false;
  }

  const auto append = [&state](OutputStream stream, const char *data,
                               std::size_t size) {
    append_output_chunk(state, std::string_view{data, size}, stream);
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

std::string debug_file_path(lldb::SBFileSpec file) {
  std::array<char, 4096> path{};
  const auto length = file.GetPath(path.data(), path.size());
  return length != 0 && length < path.size() ? std::string{path.data()}
                                             : std::string{};
}

namespace {
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

std::optional<std::uint64_t> register_value_as_unsigned(lldb::SBValue value) {
  if (!value.IsValid()) {
    return std::nullopt;
  }

  lldb::SBError conversion_error;
  const std::uint64_t converted = value.GetValueAsUnsigned(conversion_error);
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
  const auto [end, error] = std::from_chars(
      numeric.data(), numeric.data() + numeric.size(), parsed, base);
  if (error != std::errc{} || end == numeric.data()) {
    return std::nullopt;
  }
  return parsed;
}

std::string symbol_for_address(lldb::SBTarget &target,
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
    if (file_address != LLDB_INVALID_ADDRESS &&
        section.GetFileByteSize() != 0 && section.GetByteSize() != 0) {
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

struct ResolvedFileAddress {
  std::uint64_t file_address{};
  std::uint64_t load_bias{};
  std::string module_path;
};

std::optional<ResolvedFileAddress>
resolve_file_address(lldb::SBSection section, lldb::SBTarget &target,
                     lldb::addr_t load_address,
                     const std::string &module_file) {
  if (!section.IsValid()) {
    return std::nullopt;
  }
  const std::size_t child_count = section.GetNumSubSections();
  for (std::size_t index = 0; index < child_count; ++index) {
    if (auto child =
            resolve_file_address(section.GetSubSectionAtIndex(index), target,
                                 load_address, module_file)) {
      return child;
    }
  }
  const lldb::addr_t start = section.GetLoadAddress(target);
  const lldb::addr_t size = section.GetByteSize();
  const lldb::addr_t file_address = section.GetFileAddress();
  if (start == LLDB_INVALID_ADDRESS || file_address == LLDB_INVALID_ADDRESS ||
      size == 0 || load_address < start || load_address - start >= size ||
      start < file_address) {
    return std::nullopt;
  }
  const std::uint64_t bias = start - file_address;
  return ResolvedFileAddress{.file_address = load_address - bias,
                             .load_bias = bias,
                             .module_path = module_file};
}

std::optional<ResolvedFileAddress>
resolve_file_address(lldb::SBTarget &target, lldb::addr_t load_address) {
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
      if (auto resolved =
              resolve_file_address(module.GetSectionAtIndex(section_index),
                                   target, load_address, path)) {
        return resolved;
      }
    }
  }
  return std::nullopt;
}

bool resolve_pc_from_modules(SessionSnapshot &state) {
  const ModuleInfo *containing_module = nullptr;
  for (const ModuleInfo &module : state.modules) {
    if (module.path.empty() || state.pc < module.base ||
        state.pc >= module.end) {
      continue;
    }
    containing_module = &module;
    if (module.has_load_bias && state.pc >= module.load_bias) {
      state.has_pc_file_address = true;
      state.pc_file_address = state.pc - module.load_bias;
      state.pc_module_load_bias = module.load_bias;
      state.pc_module_path = module.path;
      return true;
    }
  }
  if (containing_module != nullptr && containing_module->base != 0 &&
      state.pc >= containing_module->base) {
    state.has_pc_file_address = true;
    state.pc_file_address = state.pc - containing_module->base;
    state.pc_module_load_bias = containing_module->base;
    state.pc_module_path = containing_module->path;
    return true;
  }
  return false;
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
          .readable = (permissions & lldb::ePermissionsReadable) != 0,
          .writable = (permissions & lldb::ePermissionsWritable) != 0,
          .executable = (permissions & lldb::ePermissionsExecutable) != 0,
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
                      std::size_t maximum_depth) {
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
      frameless_mips ? target.ResolveLoadAddress(state.pc) : frame.GetPCAddress();
  lldb::addr_t pc_file_address = pc_address.GetFileAddress();
  lldb::addr_t pc_load_address = pc_address.GetLoadAddress(target);
  if (!pc_address.IsValid() || pc_file_address == LLDB_INVALID_ADDRESS ||
      pc_load_address == LLDB_INVALID_ADDRESS) {
    pc_address = target.ResolveLoadAddress(state.pc);
    pc_file_address = pc_address.GetFileAddress();
    pc_load_address = pc_address.GetLoadAddress(target);
  }
  if (pc_file_address != LLDB_INVALID_ADDRESS &&
      pc_load_address != LLDB_INVALID_ADDRESS) {
    state.has_pc_file_address = true;
    state.pc_file_address = pc_file_address;
    state.pc_module_load_bias = pc_load_address - pc_file_address;
    state.pc_module_path = module_path(pc_address.GetModule());
  } else if (auto resolved = resolve_file_address(target, state.pc)) {
    state.has_pc_file_address = true;
    state.pc_file_address = resolved->file_address;
    state.pc_module_load_bias = resolved->load_bias;
    state.pc_module_path = resolved->module_path;
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
  if (!state.has_pc_file_address) {
    resolve_pc_from_modules(state);
  }
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
    append_frameless_qemu_mips_frame(target, state);
  }
  capture_heap(target, process, state);
  capture_stack(target, process, state);
  capture_crash(target, process, thread, state);
  record_stop_history(state);
}

} // namespace debugger::lldb_detail
