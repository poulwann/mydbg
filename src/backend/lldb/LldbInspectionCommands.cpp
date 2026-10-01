#include "backend/lldb/LldbEngineInternal.h"
#include "backend/lldb/LldbNativeCommands.h"
#include "localization/Localization.h"

namespace debugger::lldb_detail {

std::optional<std::string>
execute_inspection_command(std::string_view command, std::string_view arguments,
                           lldb::SBTarget &target, lldb::SBProcess &process,
                           const SessionSnapshot &state, bool &failed) {
  NativeCommandStatus status{failed};
  std::string response;
  if (command == "lm" || command == "modules" || command == "linkmap") {
    std::ostringstream modules;
    for (const ModuleInfo &module : state.modules) {
      modules << "0x" << std::hex << module.base << "-0x" << module.end << ' '
              << module.path << '\n';
    }
    response = modules.str();
  } else if (command == "pid") {
    response = state.process_id == 0 ? l10n::text(l10n::Key::EngineNoProcess)
                                     : std::to_string(state.process_id);
  } else if (command == "argc") {
    lldb::SBFrame frame = selected_frame(process);
    lldb::SBValue argc_value = frame.FindVariable("argc");
    if (!argc_value.IsValid()) {
      argc_value = frame.EvaluateExpression("(int)argc");
    }
    response =
        argc_value.IsValid() && argc_value.GetError().Success()
            ? safe_string(argc_value.GetValue())
            : l10n::text(l10n::Key::EngineArgcIsUnavailableInTheSelectedFrame);
  } else if (command == "syscalls") {
    struct SyscallEntry {
      int number;
      const char *name;
    };
    constexpr std::array<SyscallEntry, 20> x86_64_syscalls{{
        {0, "read"},         {1, "write"},    {2, "open"},
        {3, "close"},        {9, "mmap"},     {10, "mprotect"},
        {11, "munmap"},      {12, "brk"},     {16, "ioctl"},
        {39, "getpid"},      {56, "clone"},   {57, "fork"},
        {58, "vfork"},       {59, "execve"},  {60, "exit"},
        {61, "wait4"},       {62, "kill"},    {158, "arch_prctl"},
        {231, "exit_group"}, {257, "openat"},
    }};
    constexpr std::array<SyscallEntry, 16> generic_syscalls{{
        {29, "ioctl"},
        {56, "openat"},
        {57, "close"},
        {63, "read"},
        {64, "write"},
        {93, "exit"},
        {94, "exit_group"},
        {129, "kill"},
        {172, "getpid"},
        {198, "socket"},
        {214, "brk"},
        {215, "munmap"},
        {220, "clone"},
        {221, "execve"},
        {222, "mmap"},
        {226, "mprotect"},
    }};
    const bool x86 = state.architecture.find("x86_64") != std::string::npos;
    std::ostringstream listing;
    const auto append_matching = [&](const auto &entries) {
      for (const SyscallEntry &entry : entries) {
        if (!arguments.empty() && arguments != entry.name &&
            arguments != std::to_string(entry.number)) {
          continue;
        }
        listing << std::dec << entry.number << ' ' << entry.name << '\n';
      }
    };
    if (x86) {
      append_matching(x86_64_syscalls);
    } else {
      append_matching(generic_syscalls);
    }
    response = listing.str();
    if (response.empty()) {
      response = l10n::text(l10n::Key::EngineSystemCallNotFoundInBuiltInTable);
    }
  } else if (command == "sigreturn") {
    const bool x86 = state.architecture.find("x86_64") != std::string::npos;
    std::ostringstream frame;
    frame << l10n::format(l10n::Key::EngineSigreturnSnapshot, x86 ? 15 : 139,
                          state.sp);
    for (const RegisterValue &value : state.registers) {
      frame << value.name << '=' << value.value << ' ';
    }
    frame << l10n::text(l10n::Key::EngineInspectionOnlyNoReturnFrameWasWritten);
    response = frame.str();
  } else if (command == "hexdump") {
    const std::vector<std::string> values = split_arguments(arguments);
    if (values.empty()) {
      response = l10n::text(l10n::Key::EngineUsageHexdumpAddressCount);
    } else {
      std::string failure;
      const auto address = resolve_address(values[0], process, failure);
      const auto parsed_count = values.size() > 1
                                    ? parse_integer(values[1])
                                    : std::optional<std::uint64_t>{128};
      if (!address || !parsed_count) {
        response = status.error_detail(
            failure.empty()
                ? std::string{l10n::text(l10n::Key::EngineInvalidByteCount)}
                : failure);
      } else {
        const std::size_t count = static_cast<std::size_t>(
            std::clamp<std::uint64_t>(*parsed_count, 1, 4096));
        const auto bytes = read_memory_bytes(process, *address, count, failure);
        response = bytes ? format_hexdump(*address, *bytes)
                         : status.error_detail(failure);
      }
    }
  } else if (command == "telescope" || command == "teles" || command == "tel") {
    const std::vector<std::string> values = split_arguments(arguments);
    std::string failure;
    const auto address = values.empty()
                             ? std::optional<lldb::addr_t>{state.sp}
                             : resolve_address(values[0], process, failure);
    const auto parsed_count = values.size() > 1
                                  ? parse_integer(values[1])
                                  : std::optional<std::uint64_t>{8};
    if (!address || !parsed_count) {
      response = status.error_detail(
          failure.empty()
              ? std::string{l10n::text(l10n::Key::EngineInvalidTelescopeCount)}
              : failure);
    } else {
      const std::uint32_t pointer_size =
          std::max<std::uint32_t>(1, state.address_byte_size);
      const std::size_t count = static_cast<std::size_t>(
          std::clamp<std::uint64_t>(*parsed_count, 1, 64));
      std::ostringstream chain;
      for (std::size_t index = 0; index < count; ++index) {
        const lldb::addr_t slot = *address + index * pointer_size;
        const auto bytes =
            read_memory_bytes(process, slot, pointer_size, failure);
        if (!bytes) {
          chain << "0x" << std::hex << slot << " <" << failure << ">\n";
          break;
        }
        const std::uint64_t value =
            decode_pointer(bytes->data(), pointer_size, target.GetByteOrder());
        chain << "0x" << std::hex << slot << " -> 0x" << value;
        const std::string symbol = symbol_for_address(target, value);
        if (!symbol.empty()) {
          chain << " (" << symbol << ')';
        }
        if (const MemoryRegionInfo *pointed = region_containing(state, value);
            pointed != nullptr && pointed->readable) {
          lldb::SBError string_error;
          char text_buffer[65]{};
          const std::size_t bytes_read = process.ReadMemory(
              value, text_buffer, sizeof(text_buffer) - 1, string_error);
          std::size_t printable = 0;
          while (printable < bytes_read && text_buffer[printable] != '\0' &&
                 std::isprint(
                     static_cast<unsigned char>(text_buffer[printable])) != 0) {
            ++printable;
          }
          if (printable >= 4) {
            chain << " \"" << std::string_view{text_buffer, printable} << '"';
          }
        }
        chain << '\n';
      }
      response = chain.str();
    }
  } else if (command == "p2p") {
    const std::vector<std::string> values = split_arguments(arguments);
    if (values.empty()) {
      response = l10n::text(l10n::Key::EngineUsageP2pAddressDepth);
    } else {
      std::string failure;
      auto current = resolve_address(values[0], process, failure);
      const auto parsed_depth = values.size() > 1
                                    ? parse_integer(values[1])
                                    : std::optional<std::uint64_t>{5};
      if (!current || !parsed_depth) {
        response = status.error_response(
            l10n::text(l10n::Key::EngineErrorInvalidAddressOrDepth));
      } else {
        const std::uint32_t pointer_size =
            std::max<std::uint32_t>(1, state.address_byte_size);
        std::vector<std::uint64_t> visited;
        std::ostringstream chain;
        const std::size_t depth = static_cast<std::size_t>(
            std::clamp<std::uint64_t>(*parsed_depth, 1, 32));
        for (std::size_t level = 0; level < depth; ++level) {
          chain << "0x" << std::hex << *current;
          if (std::find(visited.begin(), visited.end(), *current) !=
              visited.end()) {
            chain << l10n::text(l10n::Key::EngineCycle);
            break;
          }
          visited.push_back(*current);
          const auto bytes =
              read_memory_bytes(process, *current, pointer_size, failure);
          if (!bytes) {
            chain << " <" << failure << '>';
            break;
          }
          const std::uint64_t next = decode_pointer(bytes->data(), pointer_size,
                                                    target.GetByteOrder());
          chain << " -> ";
          current = next;
        }
        response = chain.str();
      }
    }
  } else if (command == "cyclic") {
    const std::vector<std::string> values = split_arguments(arguments);
    if (values.size() == 2 && (values[0] == "-l" || values[0] == "--lookup")) {
      std::string query = values[1];
      if (const auto numeric = parse_integer(query)) {
        query.clear();
        for (std::size_t index = 0; index < 8; ++index) {
          const char byte = static_cast<char>((*numeric >> (index * 8)) & 0xff);
          if (byte == '\0') {
            break;
          }
          query.push_back(byte);
        }
      }
      const std::string pattern = cyclic_pattern(456976);
      std::size_t offset = pattern.find(query);
      if (offset == std::string::npos && query.size() > 4) {
        offset = pattern.find(query.substr(0, 4));
      }
      response = offset == std::string::npos
                     ? l10n::text(l10n::Key::EngineCyclicValueNotFound)
                     : std::to_string(offset);
    } else {
      const auto length = values.empty() ? std::optional<std::uint64_t>{100}
                                         : parse_integer(values[0]);
      response =
          length ? cyclic_pattern(static_cast<std::size_t>(
                       std::min<std::uint64_t>(*length, 456976)))
                 : l10n::text(l10n::Key::EngineUsageCyclicLengthCyclicLValue);
    }
  } else if (command == "stack_explore") {
    std::ostringstream candidates;
    for (const StackEntry &entry : state.stack) {
      const MemoryRegionInfo *destination =
          region_containing(state, entry.value);
      if (destination == nullptr || !destination->executable) {
        continue;
      }
      candidates << "0x" << std::hex << entry.address << " -> 0x" << entry.value
                 << ' ' << symbol_for_address(target, entry.value) << ' '
                 << destination->name << '\n';
    }
    response = candidates.str();
    if (response.empty()) {
      response = l10n::text(
          l10n::Key::EngineNoExecutablePointersInCapturedStackWindow);
    }
  } else if (command == "valist") {
    std::string failure;
    const auto address = resolve_address(arguments, process, failure);
    if (!address) {
      response = l10n::text(l10n::Key::EngineUsageValistVaListAddress);
    } else {
      const auto bytes = read_memory_bytes(process, *address, 24, failure);
      if (!bytes) {
        response = status.error_detail(failure);
      } else if (state.architecture.find("x86_64") != std::string::npos) {
        const std::uint64_t gp_offset =
            decode_pointer(bytes->data(), 4, target.GetByteOrder());
        const std::uint64_t fp_offset =
            decode_pointer(bytes->data() + 4, 4, target.GetByteOrder());
        const std::uint64_t overflow = decode_pointer(
            bytes->data() + 8, state.address_byte_size, target.GetByteOrder());
        const std::uint64_t register_save = decode_pointer(
            bytes->data() + 16, state.address_byte_size, target.GetByteOrder());
        std::ostringstream value;
        value << "gp_offset=" << std::dec << gp_offset
              << " fp_offset=" << fp_offset << " overflow_arg_area=0x"
              << std::hex << overflow << " reg_save_area=0x" << register_save;
        response = value.str();
      } else {
        response = format_hexdump(*address, *bytes);
      }
    }
  } else if (command == "search") {
    const std::vector<std::string> values = split_arguments(arguments);
    std::vector<std::uint8_t> needle;
    std::string mapping_filter;
    if (!values.empty() && values[0] == "-x") {
      if (values.size() < 2) {
        response = l10n::text(l10n::Key::EngineUsageSearchXAABBMapping);
      } else {
        const auto parsed = parse_hex_bytes(values[1]);
        if (parsed) {
          needle = *parsed;
        }
        if (values.size() > 2) {
          mapping_filter = values[2];
        }
      }
    } else if (values.size() >= 3 && values[0] == "-t") {
      const std::string type = lowercase(values[1]);
      if (type == "string" || type == "str") {
        needle.assign(values[2].begin(), values[2].end());
      } else {
        const auto numeric = parse_integer(values[2]);
        std::size_t width = 0;
        if (type == "byte" || type == "u8") {
          width = 1;
        } else if (type == "short" || type == "u16") {
          width = 2;
        } else if (type == "int" || type == "u32") {
          width = 4;
        } else if (type == "long" || type == "pointer" || type == "u64") {
          width = type == "pointer" ? state.address_byte_size : 8;
        }
        if (numeric && width != 0) {
          needle.resize(width);
          for (std::size_t index = 0; index < width; ++index) {
            const std::size_t byte_index =
                target.GetByteOrder() == lldb::eByteOrderBig ? width - 1 - index
                                                             : index;
            needle[byte_index] =
                static_cast<std::uint8_t>((*numeric >> (index * 8)) & 0xff);
          }
        }
      }
      if (values.size() > 3) {
        mapping_filter = values[3];
      }
    } else if (!values.empty()) {
      needle.assign(values[0].begin(), values[0].end());
      if (values.size() > 1) {
        mapping_filter = values[1];
      }
    }

    if (response.empty() && needle.empty()) {
      response = l10n::text(l10n::Key::EngineSearchUsage);
    } else if (response.empty()) {
      constexpr std::size_t chunk_size = 64 * 1024;
      constexpr std::uint64_t scan_limit = 256ULL * 1024 * 1024;
      constexpr std::size_t result_limit = 256;
      std::uint64_t scanned = 0;
      std::size_t result_count = 0;
      std::ostringstream matches;
      bool truncated = false;
      for (const MemoryRegionInfo &region : state.memory_regions) {
        if (!region.readable ||
            (!mapping_filter.empty() &&
             region.name.find(mapping_filter) == std::string::npos)) {
          continue;
        }
        std::vector<std::uint8_t> carry;
        for (std::uint64_t address = region.start; address < region.end;) {
          if (scanned >= scan_limit || result_count >= result_limit) {
            truncated = true;
            break;
          }
          const std::size_t count = static_cast<std::size_t>(
              std::min<std::uint64_t>(chunk_size, region.end - address));
          std::vector<std::uint8_t> buffer(carry.size() + count);
          std::copy(carry.begin(), carry.end(), buffer.begin());
          lldb::SBError read_error;
          const std::size_t bytes_read = process.ReadMemory(
              address, buffer.data() + carry.size(), count, read_error);
          if (bytes_read == 0) {
            break;
          }
          buffer.resize(carry.size() + bytes_read);
          auto cursor = buffer.begin();
          while (cursor != buffer.end()) {
            cursor =
                std::search(cursor, buffer.end(), needle.begin(), needle.end());
            if (cursor == buffer.end()) {
              break;
            }
            const std::uint64_t match_address =
                address - carry.size() +
                static_cast<std::uint64_t>(
                    std::distance(buffer.begin(), cursor));
            matches << "0x" << std::hex << match_address << ' ' << region.name
                    << '\n';
            ++result_count;
            if (result_count >= result_limit) {
              truncated = true;
              break;
            }
            ++cursor;
          }
          const std::size_t carry_size =
              std::min<std::size_t>(needle.size() - 1, buffer.size());
          carry.assign(buffer.end() - static_cast<std::ptrdiff_t>(carry_size),
                       buffer.end());
          address += bytes_read;
          scanned += bytes_read;
        }
        if (truncated) {
          break;
        }
      }
      if (result_count == 0) {
        matches << l10n::text(l10n::Key::EnginePatternNotFound);
      }
      if (truncated) {
        matches << l10n::format(l10n::Key::EngineSearchTruncated, result_count,
                                scanned);
      }
      response = matches.str();
    }
  } else if (command == "plist") {
    const std::vector<std::string> values = split_arguments(arguments);
    if (values.empty()) {
      response = l10n::text(
          l10n::Key::EngineUsagePlistHeadAddressNextPointerOffsetMaxNodes);
    } else {
      std::string failure;
      auto current = resolve_address(values[0], process, failure);
      const auto offset = values.size() > 1 ? parse_integer(values[1])
                                            : std::optional<std::uint64_t>{0};
      const auto maximum = values.size() > 2 ? parse_integer(values[2])
                                             : std::optional<std::uint64_t>{32};
      if (!current || !offset || !maximum) {
        response = status.error_response(
            l10n::text(l10n::Key::EngineErrorInvalidListAddressOffsetOrCount));
      } else {
        const std::uint32_t pointer_size =
            std::max<std::uint32_t>(1, state.address_byte_size);
        std::vector<std::uint64_t> visited;
        std::ostringstream nodes;
        for (std::uint64_t index = 0;
             index < std::min<std::uint64_t>(*maximum, 256) && *current != 0;
             ++index) {
          nodes << index << ": 0x" << std::hex << *current << '\n';
          if (std::find(visited.begin(), visited.end(), *current) !=
              visited.end()) {
            nodes << l10n::text(l10n::Key::EngineCycleDetected);
            break;
          }
          visited.push_back(*current);
          const auto bytes = read_memory_bytes(process, *current + *offset,
                                               pointer_size, failure);
          if (!bytes) {
            nodes << l10n::format(l10n::Key::EngineErrorDetail, failure.c_str())
                  << '\n';
            break;
          }
          current = decode_pointer(bytes->data(), pointer_size,
                                   target.GetByteOrder());
        }
        response = nodes.str();
      }
    }
  } else if (command == "vmmap" || command == "mmap" || command == "memmap" ||
             command == "!address") {
    std::string address_failure;
    const auto requested_address =
        arguments.empty()
            ? std::nullopt
            : resolve_address(arguments, process, address_failure);
    std::ostringstream mappings;
    for (const MemoryRegionInfo &region : state.memory_regions) {
      if (requested_address && (*requested_address < region.start ||
                                *requested_address >= region.end)) {
        continue;
      }
      if (!arguments.empty() && !requested_address &&
          region.name.find(arguments) == std::string::npos) {
        continue;
      }
      mappings << "0x" << std::hex << region.start << "-0x" << region.end << ' '
               << permission_text(region) << ' ' << region.name << '\n';
    }
    response = mappings.str();
    if (response.empty()) {
      response = l10n::text(l10n::Key::EngineNoMatchingMemoryMappings);
    }
  } else if (command == "xinfo" || command == "examine") {
    std::string address_failure;
    const auto address = resolve_address(arguments, process, address_failure);
    if (!address) {
      response =
          l10n::text(l10n::Key::EngineUsageXinfoAddressRegisterExpression);
    } else {
      std::ostringstream information;
      information << l10n::text(l10n::Key::EngineAddressAddress) << std::hex
                  << *address << '\n';
      if (const MemoryRegionInfo *region = region_containing(state, *address)) {
        information << l10n::text(l10n::Key::EngineMappingAddress)
                    << region->start << "-0x" << region->end << ' '
                    << permission_text(*region) << ' ' << region->name
                    << l10n::text(l10n::Key::EngineOffsetAddress)
                    << (*address - region->start) << '\n';
      }
      lldb::SBAddress resolved = target.ResolveLoadAddress(*address);
      if (resolved.IsValid()) {
        information << l10n::text(l10n::Key::EngineModule)
                    << module_path(resolved.GetModule())
                    << l10n::text(l10n::Key::EngineSection)
                    << safe_string(resolved.GetSection().GetName())
                    << l10n::text(l10n::Key::EngineFileAddressAddress)
                    << resolved.GetFileAddress() << '\n';
      }
      const std::string symbol = symbol_for_address(target, *address);
      if (!symbol.empty()) {
        information << l10n::text(l10n::Key::EngineSymbol) << symbol << '\n';
      }
      response = information.str();
    }
  } else if (command == "piebase") {
    std::ostringstream bases;
    for (std::size_t index = 0; index < target.GetNumModules(); ++index) {
      lldb::SBModule module =
          target.GetModuleAtIndex(static_cast<std::uint32_t>(index));
      const std::string path = module_path(module);
      if (!arguments.empty() && path.find(arguments) == std::string::npos) {
        continue;
      }
      lldb::SBAddress header = module.GetObjectFileHeaderAddress();
      const lldb::addr_t load = header.GetLoadAddress(target);
      if (load != LLDB_INVALID_ADDRESS) {
        bases << "0x" << std::hex << load << ' ' << path << '\n';
      }
      if (arguments.empty()) {
        break;
      }
    }
    response = bases.str();
    if (response.empty()) {
      response = l10n::text(l10n::Key::EngineModuleNotFoundOrNotLoaded);
    }
  } else if (command == "got" || command == "gotplt" || command == "plt") {
    const std::vector<std::string_view> wanted =
        command == "got" ? std::vector<std::string_view>{".got", ".got.plt"}
        : command == "gotplt"
            ? std::vector<std::string_view>{".got.plt"}
            : std::vector<std::string_view>{".plt", ".plt.sec"};
    std::ostringstream listing;
    for (std::size_t module_index = 0; module_index < target.GetNumModules();
         ++module_index) {
      lldb::SBModule module =
          target.GetModuleAtIndex(static_cast<std::uint32_t>(module_index));
      const std::string path = module_path(module);
      if (!arguments.empty() && path.find(arguments) == std::string::npos) {
        continue;
      }
      for (std::string_view section_name : wanted) {
        std::vector<lldb::SBSection> matches;
        for (std::size_t section_index = 0;
             section_index < module.GetNumSections(); ++section_index) {
          collect_matching_sections(module.GetSectionAtIndex(section_index),
                                    section_name, matches);
        }
        for (lldb::SBSection section : matches) {
          const lldb::addr_t load = section.GetLoadAddress(target);
          listing << path << ' ' << section_name << " 0x" << std::hex << load
                  << "-0x" << (load + section.GetByteSize()) << '\n';
          if (command == "plt") {
            lldb::SBInstructionList instructions =
                target.ReadInstructions(target.ResolveLoadAddress(load), 32);
            for (std::size_t instruction_index = 0;
                 instruction_index < instructions.GetSize();
                 ++instruction_index) {
              lldb::SBInstruction instruction =
                  instructions.GetInstructionAtIndex(
                      static_cast<std::uint32_t>(instruction_index));
              listing << "  0x"
                      << instruction.GetAddress().GetLoadAddress(target) << ' '
                      << safe_string(instruction.GetMnemonic(target)) << ' '
                      << safe_string(instruction.GetOperands(target)) << '\n';
            }
            continue;
          }
          const std::uint32_t pointer_size =
              std::max<std::uint32_t>(1, state.address_byte_size);
          const std::size_t slots =
              std::min<std::size_t>(section.GetByteSize() / pointer_size, 256);
          for (std::size_t slot = 0; slot < slots; ++slot) {
            std::string failure;
            const auto bytes = read_memory_bytes(
                process, load + slot * pointer_size, pointer_size, failure);
            if (!bytes) {
              listing << "  <" << failure << ">\n";
              break;
            }
            const std::uint64_t value = decode_pointer(
                bytes->data(), pointer_size, target.GetByteOrder());
            listing << "  0x" << (load + slot * pointer_size) << " -> 0x"
                    << value;
            const std::string symbol = symbol_for_address(target, value);
            if (!symbol.empty()) {
              listing << ' ' << symbol;
            }
            listing << '\n';
          }
        }
      }
    }
    response = listing.str();
    if (response.empty()) {
      response = l10n::text(l10n::Key::EngineMatchingSectionNotFound);
    }
  } else if (command == "checksec") {
    if (!state.security.available) {
      response = l10n::text(l10n::Key::EngineELFSecurityMetadataUnavailable);
    } else {
      std::ostringstream security;
      security << l10n::text(l10n::Key::EnginePIE)
               << (state.security.pie ? l10n::text(l10n::Key::EngineEnabled)
                                      : l10n::text(l10n::Key::EngineDisabled))
               << l10n::text(l10n::Key::EngineNX)
               << (state.security.nx ? l10n::text(l10n::Key::EngineEnabled)
                                     : l10n::text(l10n::Key::EngineDisabled))
               << l10n::text(l10n::Key::EngineRELRO)
               << (state.security.full_relro ? l10n::text(l10n::Key::EngineFull)
                   : state.security.relro ? l10n::text(l10n::Key::EnginePartial)
                                          : l10n::text(l10n::Key::EngineNone))
               << l10n::text(l10n::Key::EngineCanary)
               << (state.security.stack_canary
                       ? l10n::text(l10n::Key::EngineFound)
                       : l10n::text(l10n::Key::EngineNotFound))
               << l10n::text(l10n::Key::EngineSymbols)
               << (state.security.stripped
                       ? l10n::text(l10n::Key::EngineStripped)
                       : l10n::text(l10n::Key::EnginePresent));
      response = security.str();
    }
  } else if (command == "auxv") {
    if (state.mode != SessionMode::Local || state.process_is_remote) {
      response = status.error_response(l10n::text(
          l10n::Key::EngineErrorAuxvHostLookupIsUnavailableForRemoteSessions));
    } else if (state.process_id == 0) {
      response =
          status.error_response(l10n::text(l10n::Key::EngineErrorNoProcess));
    } else {
      const std::filesystem::path auxv_path = std::filesystem::path{"/proc"} /
                                              std::to_string(state.process_id) /
                                              "auxv";
      std::ifstream auxv_file{auxv_path, std::ios::binary};
      const std::vector<std::uint8_t> bytes{
          std::istreambuf_iterator<char>{auxv_file},
          std::istreambuf_iterator<char>{}};
      const std::uint32_t width = state.address_byte_size;
      std::ostringstream entries;
      if (width == 0 || bytes.size() % (width * 2) != 0) {
        response = status.error_response(
            l10n::text(l10n::Key::EngineErrorInvalidProcAuxiliaryVector));
      } else {
        const auto name_for_type = [](std::uint64_t type) {
          switch (type) {
          case 3:
            return "AT_PHDR";
          case 4:
            return "AT_PHENT";
          case 5:
            return "AT_PHNUM";
          case 6:
            return "AT_PAGESZ";
          case 7:
            return "AT_BASE";
          case 9:
            return "AT_ENTRY";
          case 11:
            return "AT_UID";
          case 12:
            return "AT_EUID";
          case 13:
            return "AT_GID";
          case 14:
            return "AT_EGID";
          case 15:
            return "AT_PLATFORM";
          case 16:
            return "AT_HWCAP";
          case 17:
            return "AT_CLKTCK";
          case 23:
            return "AT_SECURE";
          case 25:
            return "AT_RANDOM";
          case 26:
            return "AT_HWCAP2";
          case 31:
            return "AT_EXECFN";
          case 33:
            return "AT_SYSINFO_EHDR";
          default:
            return "AT_UNKNOWN";
          }
        };
        for (std::size_t offset = 0; offset + width * 2 <= bytes.size();
             offset += width * 2) {
          const std::uint64_t type = decode_pointer(
              bytes.data() + offset, width, target.GetByteOrder());
          const std::uint64_t value = decode_pointer(
              bytes.data() + offset + width, width, target.GetByteOrder());
          if (type == 0) {
            break;
          }
          entries << name_for_type(type) << '(' << std::dec << type << ") = 0x"
                  << std::hex << value << '\n';
        }
        response = entries.str();
      }
    }
  } else if (command == "kbase" || command == "kchecksec") {
    response = l10n::text(l10n::Key::EngineKernelSessionsUnsupported);
  } else if (command == "tls") {
    lldb::SBFrame frame = selected_frame(process);
    const std::array<const char *, 4> register_names{"fs_base", "tpidr_el0",
                                                     "tp", "gs_base"};
    std::ostringstream tls;
    for (const char *name : register_names) {
      lldb::SBValue value = frame.FindRegister(name);
      if (value.IsValid()) {
        tls << name << "=0x" << std::hex << value.GetValueAsUnsigned() << '\n';
      }
    }
    response = tls.str();
    if (response.empty()) {
      response = l10n::text(
          l10n::Key::EngineTLSBaseRegisterIsUnavailableForThisTarget);
    }
  } else if (command == "retaddr") {
    lldb::SBThread thread = process.GetSelectedThread();
    std::ostringstream addresses;
    for (std::uint32_t index = 1; index < thread.GetNumFrames(); ++index) {
      lldb::SBFrame frame = thread.GetFrameAtIndex(index);
      addresses << '#' << index << " 0x" << std::hex << frame.GetPC() << ' '
                << safe_string(frame.GetFunctionName()) << '\n';
    }
    response = addresses.str();
    if (response.empty()) {
      response = l10n::text(l10n::Key::EngineNoSavedReturnAddress);
    }
  } else if (command == "canary") {
    lldb::SBFrame frame = selected_frame(process);
    std::optional<std::uint64_t> canary_address;
    lldb::SBValue fs_base = frame.FindRegister("fs_base");
    if (fs_base.IsValid()) {
      canary_address = fs_base.GetValueAsUnsigned() + 0x28;
    } else {
      lldb::SBValue guard = frame.EvaluateExpression("&__stack_chk_guard");
      if (guard.IsValid() && guard.GetError().Success()) {
        canary_address = guard.GetValueAsUnsigned();
      }
    }
    if (!canary_address) {
      response = l10n::text(l10n::Key::EngineStackCanaryLocationUnavailable);
    } else {
      std::string failure;
      const auto bytes = read_memory_bytes(process, *canary_address,
                                           state.address_byte_size, failure);
      if (!bytes) {
        response = status.error_detail(failure);
      } else {
        std::ostringstream canary;
        canary << "0x" << std::hex << *canary_address << ": 0x"
               << decode_pointer(bytes->data(), state.address_byte_size,
                                 target.GetByteOrder());
        response = canary.str();
      }
    }
  } else if (command == "distance") {
    const std::vector<std::string> values = split_arguments(arguments);
    if (values.size() != 2) {
      response = l10n::text(l10n::Key::EngineUsageDistanceAddressAddress);
    } else {
      std::string first_failure;
      std::string second_failure;
      const auto first = resolve_address(values[0], process, first_failure);
      const auto second = resolve_address(values[1], process, second_failure);
      if (!first || !second) {
        response = status.error_response(
            l10n::text(l10n::Key::EngineErrorCouldNotResolveBothAddresses));
      } else {
        const std::int64_t delta = static_cast<std::int64_t>(*second - *first);
        std::ostringstream difference;
        difference << l10n::format(
            l10n::Key::EngineAddressDistance, delta,
            state.address_byte_size == 0
                ? std::int64_t{0}
                : delta / static_cast<std::int64_t>(state.address_byte_size),
            static_cast<std::uint64_t>(delta));
        response = difference.str();
      }
    }
  } else if (command == "procinfo") {
    if (state.mode != SessionMode::Local || state.process_is_remote) {
      response = status.error_response(l10n::text(
          l10n::Key::
              EngineErrorProcinfoHostLookupIsUnavailableForRemoteSessions));
    } else if (state.process_id == 0) {
      response =
          status.error_response(l10n::text(l10n::Key::EngineErrorNoProcess));
    } else {
      const std::filesystem::path process_root =
          std::filesystem::path{"/proc"} / std::to_string(state.process_id);
      std::ifstream status_file{process_root / "status"};
      std::ostringstream information;
      std::string line;
      while (std::getline(status_file, line)) {
        if (line.starts_with("Name:") || line.starts_with("State:") ||
            line.starts_with("Pid:") || line.starts_with("PPid:") ||
            line.starts_with("Uid:") || line.starts_with("Gid:") ||
            line.starts_with("Threads:") || line.starts_with("Seccomp:")) {
          information << line << '\n';
        }
      }
      std::ifstream command_file{process_root / "cmdline", std::ios::binary};
      std::string process_command_line{
          std::istreambuf_iterator<char>{command_file},
          std::istreambuf_iterator<char>{}};
      std::replace(process_command_line.begin(), process_command_line.end(),
                   '\0', ' ');
      information << l10n::text(l10n::Key::EngineCmdline)
                  << process_command_line << '\n';
      response = information.str();
    }
  } else if (command == "errno") {
    lldb::SBFrame frame = selected_frame(process);
    lldb::SBValue value = frame.EvaluateExpression("(int)errno");
    if (!value.IsValid() || value.GetError().Fail()) {
      response = status.error_response(
          l10n::text(l10n::Key::EngineErrorUnableToReadDebuggeeErrno));
    } else {
      const int error_number = static_cast<int>(value.GetValueAsSigned());
      response = std::to_string(error_number) + " (" +
                 std::strerror(error_number) + ')';
    }
  } else if (command == "?") {
    lldb::SBFrame frame = selected_frame(process);
    if (!frame.IsValid()) {
      response = status.error_response(
          l10n::text(l10n::Key::EngineErrorExpressionEvaluationRequiresAFrame));
    } else {
      const std::string expression{arguments};
      lldb::SBValue value = frame.EvaluateExpression(expression.c_str());
      const lldb::SBError expression_error = value.GetError();
      response = expression_error.Fail()
                     ? status.error_detail(error_text(expression_error))
                     : safe_string(value.GetValue());
    }
  } else {
    return std::nullopt;
  }
  return response;
}

} // namespace debugger::lldb_detail
