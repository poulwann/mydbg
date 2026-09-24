#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace mydbg::app {

enum class MemoryCopyFormat {
  Hex,
  Escaped,
  CArray,
  PythonBytearray,
  JavaScriptUint8Array,
  RustArray,
};

enum class MemoryByteOrder { AsStored, LittleEndian, BigEndian };

// Explicit conversion changes byte order within each complete word relative to
// the target's "little" or "big" order. AsStored preserves address order.
bool can_format_memory_bytes(std::size_t byte_count, MemoryByteOrder order,
                             std::size_t word_size,
                             std::string_view target_byte_order);
std::optional<std::string> format_memory_bytes(
    std::span<const std::uint8_t> bytes, MemoryCopyFormat format,
    MemoryByteOrder order = MemoryByteOrder::AsStored,
    std::size_t word_size = 1, std::string_view target_byte_order = {});

// Interpret exactly 1..8 bytes as an unsigned integer with explicit LE/BE
// order. The hexadecimal result keeps two digits per input byte, including
// zeros.
std::optional<std::string>
format_memory_integer(std::span<const std::uint8_t> bytes,
                      MemoryByteOrder interpretation);

} // namespace mydbg::app
