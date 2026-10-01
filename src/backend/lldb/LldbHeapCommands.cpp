#include "backend/lldb/LldbEngineInternal.h"
#include "backend/lldb/LldbNativeCommands.h"
#include "localization/Localization.h"

namespace debugger::lldb_detail {

std::optional<std::string>
execute_heap_command(std::string_view command, std::string_view arguments,
                     lldb::SBTarget &target, lldb::SBProcess &process,
                     const SessionSnapshot &state, bool &failed) {
  NativeCommandStatus status{failed};
  std::string response;
  if (command == "heap_config") {
    std::ostringstream configuration;
    const auto libc_module =
        std::find_if(state.modules.begin(), state.modules.end(),
                     [](const ModuleInfo &module) {
                       return module.path.find("libc.so") != std::string::npos;
                     });
    configuration << "allocator=glibc\n"
                  << "pointer-size=" << state.address_byte_size << '\n'
                  << "byte-order=" << state.byte_order << '\n'
                  << "safe-linking-decode=enabled\n"
                  << "heap-chunk-limit=256\n"
                  << "libc="
                  << (libc_module == state.modules.end()
                          ? l10n::text(l10n::Key::EngineNotDetected)
                          : libc_module->path)
                  << "\nwalk-status="
                  << (state.heap_error.empty() ? l10n::text(l10n::Key::EngineOk)
                                               : state.heap_error);
    response = configuration.str();
  } else if (command == "heap" || command == "vis_heap_chunks" ||
             command == "malloc_chunk" || command == "bins" ||
             command == "fastbins" || command == "tcachebins" ||
             command == "unsortedbin" || command == "smallbins" ||
             command == "largebins") {
    std::optional<std::uint64_t> requested_address;
    if (!arguments.empty() && command != "vis_heap_chunks") {
      std::string failure;
      requested_address = resolve_address(arguments, process, failure);
      if (!requested_address && command == "malloc_chunk") {
        response = status.error_detail(failure);
      }
    }
    if (response.empty()) {
      std::ostringstream chunks;
      const std::uint64_t fast_max = state.address_byte_size == 4 ? 0x50 : 0x90;
      const std::uint64_t small_max =
          state.address_byte_size == 4 ? 0x200 : 0x400;
      for (const HeapChunkInfo &chunk : state.heap_chunks) {
        if (requested_address &&
            (*requested_address < chunk.address ||
             *requested_address >= chunk.address + chunk.size)) {
          continue;
        }
        if (command == "fastbins" && (chunk.in_use || chunk.size > fast_max)) {
          continue;
        }
        if (command == "tcachebins" &&
            (chunk.in_use || chunk.size > small_max)) {
          continue;
        }
        if (command == "unsortedbin" &&
            (chunk.in_use || chunk.size <= fast_max)) {
          continue;
        }
        if (command == "smallbins" && (chunk.in_use || chunk.size <= fast_max ||
                                       chunk.size > small_max)) {
          continue;
        }
        if (command == "largebins" &&
            (chunk.in_use || chunk.size <= small_max)) {
          continue;
        }
        chunks << "0x" << std::hex << chunk.address
               << l10n::text(l10n::Key::EngineSizeAddress) << chunk.size
               << l10n::text(l10n::Key::EnginePrevSizeAddress)
               << chunk.previous_size << l10n::text(l10n::Key::EngineFlags)
               << ((chunk.flags & 1U) != 0 ? 'P' : '-')
               << ((chunk.flags & 2U) != 0 ? 'M' : '-')
               << ((chunk.flags & 4U) != 0 ? 'A' : '-') << ' '
               << (chunk.in_use ? l10n::text(l10n::Key::EngineInUse)
                                : l10n::text(l10n::Key::EngineFree));
        if (!chunk.in_use) {
          const std::uint64_t user_address =
              chunk.address + state.address_byte_size * 2;
          chunks << l10n::text(l10n::Key::EngineFdAddress) << chunk.forward
                 << l10n::text(l10n::Key::EngineSafeFdAddress)
                 << (chunk.forward ^ (user_address >> 12))
                 << l10n::text(l10n::Key::EngineBkAddress) << chunk.backward;
        }
        chunks << '\n';
        if (command == "vis_heap_chunks") {
          chunks << l10n::text(l10n::Key::EngineNextAddress)
                 << (chunk.address + chunk.size) << '\n';
        }
      }
      if (!state.heap_error.empty()) {
        chunks << '[' << state.heap_error << "]\n";
      }
      response = chunks.str();
      if (response.empty()) {
        response = l10n::text(l10n::Key::EngineNoMatchingGlibcHeapChunks);
      }
    }
  } else if (command == "arena" || command == "arenas" || command == "mp") {
    std::ostringstream allocator;
    std::size_t used = 0;
    std::size_t free = 0;
    std::uint64_t bytes = 0;
    for (const HeapChunkInfo &chunk : state.heap_chunks) {
      bytes += chunk.size;
      if (chunk.in_use) {
        ++used;
      } else {
        ++free;
      }
    }
    allocator << l10n::format(l10n::Key::EngineHeapSummary,
                              state.heap_chunks.size(), used, free, bytes);
    if (const auto heap = std::find_if(state.memory_regions.begin(),
                                       state.memory_regions.end(),
                                       [](const MemoryRegionInfo &region) {
                                         return region.name == "[heap]";
                                       });
        heap != state.memory_regions.end()) {
      allocator << l10n::format(l10n::Key::EngineArenaMapping, heap->start,
                                heap->end);
    }
    if (!state.heap_error.empty()) {
      allocator << state.heap_error;
    }
    response = allocator.str();
  } else if (command == "find_fake_fast") {
    std::string failure;
    const auto target_address = resolve_address(arguments, process, failure);
    if (!target_address) {
      response = l10n::text(l10n::Key::EngineUsageFindFakeFastAddress);
    } else {
      const std::uint32_t pointer_size =
          std::max<std::uint32_t>(1, state.address_byte_size);
      const std::uint64_t alignment = pointer_size * 2;
      const std::uint64_t fast_max = pointer_size == 4 ? 0x50 : 0x90;
      const std::uint64_t search_start =
          *target_address > 0x100 ? *target_address - 0x100 : 0;
      std::ostringstream candidates;
      for (std::uint64_t header =
               (search_start + alignment - 1) & ~(alignment - 1);
           header + pointer_size * 2 <= *target_address; header += alignment) {
        const auto bytes = read_memory_bytes(process, header + pointer_size,
                                             pointer_size, failure);
        if (!bytes) {
          continue;
        }
        const std::uint64_t size_and_flags =
            decode_pointer(bytes->data(), pointer_size, target.GetByteOrder());
        const std::uint64_t size = size_and_flags & ~0x7ULL;
        if (size >= alignment && size <= fast_max &&
            header + size >= *target_address) {
          candidates << "0x" << std::hex << header
                     << l10n::text(l10n::Key::EngineSizeAddress) << size
                     << '\n';
        }
      }
      response = candidates.str();
      if (response.empty()) {
        response =
            l10n::text(l10n::Key::EngineNoPlausibleFastbinSizedFakeChunk);
      }
    }
  } else if (command == "try_free") {
    std::string failure;
    const auto user_address = resolve_address(arguments, process, failure);
    if (!user_address) {
      response = l10n::text(l10n::Key::EngineUsageTryFreeUserPointer);
    } else {
      const std::uint64_t header_size = state.address_byte_size * 2;
      const auto chunk = std::find_if(
          state.heap_chunks.begin(), state.heap_chunks.end(),
          [user_address, header_size](const HeapChunkInfo &candidate) {
            return candidate.address + header_size == *user_address;
          });
      if (chunk == state.heap_chunks.end()) {
        response = l10n::text(
            l10n::Key::EngineUnsafePointerIsNotADiscoveredChunkPayload);
      } else if (!chunk->in_use) {
        response = l10n::text(l10n::Key::EngineUnsafeChunkAppearsAlreadyFree);
      } else if ((chunk->size % (state.address_byte_size * 2)) != 0) {
        response = l10n::text(l10n::Key::EngineUnsafeChunkSizeIsMisaligned);
      } else {
        std::ostringstream result;
        result << l10n::format(l10n::Key::EnginePlausibleFree, *user_address,
                               chunk->address, chunk->size);
        response = result.str();
      }
    }
  } else {
    return std::nullopt;
  }
  return response;
}

} // namespace debugger::lldb_detail
