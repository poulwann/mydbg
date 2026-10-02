#include "backend/lldb/LldbEngineInternal.h"
#include "backend/lldb/LldbInstructionCapture.h"
#include "backend/lldb/LldbNativeCommands.h"
#include "localization/Localization.h"

namespace debugger::lldb_detail {

std::optional<std::uint64_t> file_offset_for_address(
    const BinaryImage &image, std::uint64_t file_address,
    std::size_t patch_size) {
  const auto segment = std::find_if(
      image.load_segments.begin(), image.load_segments.end(),
      [file_address, patch_size](const ElfLoadSegment &candidate) {
        if (file_address < candidate.virtual_address) {
          return false;
        }
        const std::uint64_t delta = file_address - candidate.virtual_address;
        return delta <= candidate.file_size &&
               patch_size <= candidate.file_size - delta;
      });
  if (segment == image.load_segments.end()) {
    return std::nullopt;
  }
  return segment->file_offset + (file_address - segment->virtual_address);
}

const ModuleInfo *module_for_patch(const SessionSnapshot &state,
                                   const PatchInfo &patch,
                                   std::string_view filter) {
  const std::uint64_t patch_end = patch.address + patch.replacement.size();
  const auto module =
      std::find_if(state.modules.begin(), state.modules.end(),
                   [&](const ModuleInfo &candidate) {
                     if (!candidate.has_load_bias || candidate.path.empty() ||
                         (!filter.empty() &&
                          candidate.path.find(filter) == std::string::npos)) {
                       return false;
                     }
                     return patch.address >= candidate.base &&
                            patch.address <= candidate.end &&
                            patch_end >= patch.address &&
                            patch_end <= candidate.end;
                   });
  return module == state.modules.end() ? nullptr : &*module;
}

std::string save_patches_to_file(const std::vector<PatchInfo> &patches,
                                 const SessionSnapshot &state,
                                 const std::filesystem::path &output_path,
                                 std::string_view module_filter,
                                 bool &failed) {
  NativeCommandStatus status{failed};
  if (patches.empty()) {
    return status.error_response(l10n::text(l10n::Key::EngineNoActivePatches));
  }
  const ModuleInfo *selected_module = nullptr;
  for (const PatchInfo &patch : patches) {
    const ModuleInfo *module = module_for_patch(state, patch, module_filter);
    if (module == nullptr) {
      return status.error_response(
          l10n::text(l10n::Key::EngineErrorPatchHasNoFileBackedElfSegment));
    }
    if (selected_module == nullptr) {
      selected_module = module;
    } else if (selected_module->path != module->path) {
      return status.error_response(
          l10n::text(l10n::Key::EngineErrorPatchSaveSingleModuleOnly));
    }
  }
  if (selected_module == nullptr) {
    return status.error_response(
        l10n::text(l10n::Key::EngineErrorPatchHasNoFileBackedElfSegment));
  }
  std::string error;
  auto image = read_binary_image(selected_module->path, error);
  if (!image) {
    return status.error_detail(error);
  }
  for (const PatchInfo &patch : patches) {
    if (patch.address < selected_module->load_bias) {
      return status.error_response(
          l10n::text(l10n::Key::EngineErrorPatchHasNoFileBackedElfSegment));
    }
    const std::uint64_t file_address =
        patch.address - selected_module->load_bias;
    const auto file_offset =
        file_offset_for_address(*image, file_address, patch.replacement.size());
    if (!file_offset ||
        *file_offset > image->bytes.size() ||
        patch.replacement.size() > image->bytes.size() - *file_offset) {
      return status.error_response(
          l10n::text(l10n::Key::EngineErrorPatchHasNoFileBackedElfSegment));
    }
    std::copy(patch.replacement.begin(), patch.replacement.end(),
              image->bytes.begin() +
                  static_cast<std::ptrdiff_t>(*file_offset));
  }
  std::ofstream output{output_path, std::ios::binary | std::ios::trunc};
  if (!output) {
    return status.error_response(
        l10n::text(l10n::Key::EngineErrorPatchSaveOpenFailed));
  }
  output.write(reinterpret_cast<const char *>(image->bytes.data()),
               static_cast<std::streamsize>(image->bytes.size()));
  if (!output) {
    return status.error_response(
        l10n::text(l10n::Key::EngineErrorPatchSaveWriteFailed));
  }
  const std::string output_name = output_path.string();
  return l10n::format(l10n::Key::EnginePatchSavedToFile, patches.size(),
                      output_name.c_str());
}

std::string
PatchCommands::apply_patch(lldb::addr_t address,
                           const std::vector<std::uint8_t> &replacement,
                           lldb::SBTarget &target, lldb::SBProcess &process,
                           SessionSnapshot &state, bool &failed) {
  NativeCommandStatus status{failed};
  if (state.state != SessionState::Stopped || !process.IsValid()) {
    return std::string{status.error_response(
        l10n::text(l10n::Key::EngineErrorPatchingRequiresAStoppedProcess))};
  }
  if (replacement.empty() ||
      replacement.size() >
          std::numeric_limits<std::uint64_t>::max() - address) {
    return std::string{status.error_response(
        l10n::text(l10n::Key::EngineErrorPatchBytesAreEmptyOrOutOfRange))};
  }

  std::uint64_t merged_start = address;
  std::uint64_t merged_end = address + replacement.size();
  std::vector<std::uint32_t> merged_ids;
  bool found_overlap = true;
  while (found_overlap) {
    found_overlap = false;
    for (const PatchInfo &patch : state.patches) {
      if (std::find(merged_ids.begin(), merged_ids.end(), patch.id) !=
          merged_ids.end()) {
        continue;
      }
      const std::uint64_t patch_end = patch.address + patch.replacement.size();
      if (merged_start < patch_end && patch.address < merged_end) {
        merged_ids.push_back(patch.id);
        merged_start = std::min(merged_start, patch.address);
        merged_end = std::max(merged_end, patch_end);
        found_overlap = true;
      }
    }
  }

  std::string failure;
  const std::size_t merged_size =
      static_cast<std::size_t>(merged_end - merged_start);
  auto current = read_memory_bytes(process, merged_start, merged_size, failure);
  if (!current) {
    return status.error_detail(failure);
  }
  std::vector<std::uint8_t> original = *current;
  for (const PatchInfo &patch : state.patches) {
    if (std::find(merged_ids.begin(), merged_ids.end(), patch.id) ==
        merged_ids.end()) {
      continue;
    }
    const std::size_t offset =
        static_cast<std::size_t>(patch.address - merged_start);
    std::copy(patch.original.begin(), patch.original.end(),
              original.begin() + static_cast<std::ptrdiff_t>(offset));
  }
  const std::size_t replacement_offset =
      static_cast<std::size_t>(address - merged_start);
  std::copy(replacement.begin(), replacement.end(),
            current->begin() + static_cast<std::ptrdiff_t>(replacement_offset));

  lldb::SBError write_error;
  const std::size_t written = process.WriteMemory(merged_start, current->data(),
                                                  current->size(), write_error);
  state.disassembly_graph.reset();
  if (write_error.Fail() || written != current->size()) {
    return status.error_detail(error_text(write_error));
  }

  const std::uint32_t id =
      merged_ids.empty()
          ? next_patch_id_++
          : *std::min_element(merged_ids.begin(), merged_ids.end());
  std::erase_if(state.patches, [&merged_ids](const PatchInfo &patch) {
    return std::find(merged_ids.begin(), merged_ids.end(), patch.id) !=
           merged_ids.end();
  });
  const bool restored = *current == original;
  if (!restored) {
    state.patches.push_back(PatchInfo{
        .id = id,
        .address = merged_start,
        .original = std::move(original),
        .replacement = std::move(*current),
    });
  }
  if (!state.memory.empty()) {
    capture_memory(process, state.memory_base, state);
  }
  if (!state.instructions.empty()) {
    capture_instructions(target, state.instructions.front().address, state);
  }

  if (restored) {
    return l10n::format(l10n::Key::EnginePatchRestored, id);
  }
  return l10n::format(l10n::Key::EnginePatchWritten, id, replacement.size(),
                      static_cast<std::uint64_t>(address));
}

std::optional<std::string>
PatchCommands::execute(std::string_view command, std::string_view arguments,
                       lldb::SBTarget &target, lldb::SBProcess &process,
                       SessionSnapshot &state, bool &failed) {
  NativeCommandStatus status{failed};
  std::string response;
  if (command == "nop" || command == "syscall") {
    const std::vector<std::string> values = split_arguments(arguments);
    if (values.empty()) {
      response = l10n::text(
          l10n::Key::EngineUsageNopAddressInstructionCountSyscallAddress);
    } else {
      std::string failure;
      const auto address = resolve_address(values[0], process, failure);
      const auto count = values.size() > 1 ? parse_integer(values[1])
                                           : std::optional<std::uint64_t>{1};
      if (!address || !count) {
        response = status.error_response(
            l10n::text(l10n::Key::EngineErrorInvalidAddressOrCount));
      } else {
        std::vector<std::uint8_t> instruction;
        if (state.architecture.find("x86") != std::string::npos) {
          instruction = command == "nop"
                            ? std::vector<std::uint8_t>{0x90}
                            : std::vector<std::uint8_t>{0x0f, 0x05};
        } else if (state.architecture.find("aarch64") != std::string::npos) {
          instruction = command == "nop"
                            ? std::vector<std::uint8_t>{0x1f, 0x20, 0x03, 0xd5}
                            : std::vector<std::uint8_t>{0x01, 0x00, 0x00, 0xd4};
        } else if (state.architecture.find("riscv") != std::string::npos) {
          instruction = command == "nop"
                            ? std::vector<std::uint8_t>{0x13, 0x00, 0x00, 0x00}
                            : std::vector<std::uint8_t>{0x73, 0x00, 0x00, 0x00};
        }
        if (instruction.empty()) {
          response = status.error_response(
              l10n::text(l10n::Key::EngineErrorNoInstructionEncodingForTarget));
        } else {
          std::vector<std::uint8_t> replacement;
          const std::size_t repetitions = static_cast<std::size_t>(
              std::clamp<std::uint64_t>(*count, 1, 256));
          replacement.reserve(instruction.size() * repetitions);
          for (std::size_t index = 0; index < repetitions; ++index) {
            replacement.insert(replacement.end(), instruction.begin(),
                               instruction.end());
          }
          response = apply_patch(*address, replacement, target, process, state,
                                 failed);
        }
      }
    }
  } else if (command == "patch") {
    const std::vector<std::string> values = split_arguments(arguments);
    if (values.size() < 2) {
      response = l10n::text(l10n::Key::EngineUsagePatchAddressHexBytes);
    } else {
      std::string failure;
      const auto address = resolve_address(values[0], process, failure);
      std::string byte_text;
      for (std::size_t index = 1; index < values.size(); ++index) {
        if (!byte_text.empty()) {
          byte_text.push_back(' ');
        }
        byte_text += values[index];
      }
      const auto replacement = parse_hex_bytes(byte_text);
      response =
          address && replacement
              ? apply_patch(*address, *replacement, target, process, state,
                            failed)
              : status.error_response(l10n::text(
                    l10n::Key::EngineErrorInvalidAddressOrHexadecimalBytes));
    }
  } else if (command == "assemble" || command == "asm") {
    const std::size_t instruction_separator = arguments.find_first_of(" \t");
    const std::string_view address_text =
        instruction_separator == std::string_view::npos
            ? arguments
            : arguments.substr(0, instruction_separator);
    const std::string_view instruction =
        instruction_separator == std::string_view::npos
            ? std::string_view{}
            : trim(arguments.substr(instruction_separator + 1));
    if (address_text.empty() || instruction.empty()) {
      response = l10n::text(
          l10n::Key::EngineUsageAssembleAddressIntelSyntaxInstruction);
    } else {
      std::string failure;
      const auto address = resolve_address(address_text, process, failure);
      const auto replacement =
          address ? assemble_intel_instruction(instruction, *address,
                                               state.architecture,
                                               state.address_byte_size, failure)
                  : std::nullopt;
      response = address && replacement
                     ? apply_patch(*address, *replacement, target, process,
                                   state, failed)
                     : status.error_detail(failure);
    }
  } else if (command == "patch_list") {
    std::ostringstream patches;
    for (const PatchInfo &patch : state.patches) {
      patches << patch.id << " 0x" << std::hex << patch.address
              << l10n::text(l10n::Key::EngineOriginal);
      for (std::uint8_t byte : patch.original) {
        patches << std::setw(2) << std::setfill('0')
                << static_cast<unsigned int>(byte);
      }
      patches << l10n::text(l10n::Key::EngineReplacement);
      for (std::uint8_t byte : patch.replacement) {
        patches << std::setw(2) << std::setfill('0')
                << static_cast<unsigned int>(byte);
      }
      patches << '\n';
    }
    response = patches.str();
    if (response.empty()) {
      response = l10n::text(l10n::Key::EngineNoActivePatches);
    }
  } else if (command == "patch_save") {
    const std::vector<std::string> values = split_arguments(arguments);
    if (values.empty()) {
      response = l10n::text(l10n::Key::EngineUsagePatchSaveOutputElfModule);
    } else {
      response = save_patches_to_file(
          state.patches, state, values[0],
          values.size() > 1 ? std::string_view{values[1]} : std::string_view{},
          failed);
    }
  } else if (command == "patch_revert") {
    const auto requested = parse_integer(arguments);
    if (!requested) {
      response = l10n::text(l10n::Key::EngineUsagePatchRevertIdAddress);
    } else {
      auto patch = std::find_if(state.patches.begin(), state.patches.end(),
                                [requested](const PatchInfo &candidate) {
                                  return candidate.id == *requested ||
                                         candidate.address == *requested;
                                });
      if (patch == state.patches.end()) {
        response = status.error_response(
            l10n::text(l10n::Key::EngineErrorPatchNotFound));
      } else {
        lldb::SBError write_error;
        const std::size_t written =
            process.WriteMemory(patch->address, patch->original.data(),
                                patch->original.size(), write_error);
        state.disassembly_graph.reset();
        if (write_error.Fail() || written != patch->original.size()) {
          response = status.error_detail(error_text(write_error));
        } else {
          const std::uint32_t patch_id = patch->id;
          state.patches.erase(patch);
          if (!state.memory.empty()) {
            capture_memory(process, state.memory_base, state);
          }
          if (!state.instructions.empty()) {
            capture_instructions(target, state.instructions.front().address,
                                 state);
          }
          response = l10n::format(l10n::Key::EnginePatchReverted, patch_id);
        }
      }
    }
  } else {
    return std::nullopt;
  }
  return response;
}

} // namespace debugger::lldb_detail
