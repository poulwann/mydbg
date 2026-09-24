#include "app/MemoryData.h"

#include <charconv>
#include <limits>

namespace mydbg::app {
namespace {

void append_hex_byte(std::string &text, std::uint8_t byte) {
  constexpr char digits[] = "0123456789ABCDEF";
  text += digits[byte >> 4];
  text += digits[byte & 0x0F];
}

} // namespace

bool can_format_memory_bytes(std::size_t byte_count, MemoryByteOrder order,
                             std::size_t word_size,
                             std::string_view target_byte_order) {
  if (byte_count == 0 ||
      (word_size != 1 && word_size != 2 && word_size != 4 && word_size != 8))
    return false;
  switch (order) {
  case MemoryByteOrder::AsStored:
    return true;
  case MemoryByteOrder::LittleEndian:
  case MemoryByteOrder::BigEndian:
    return word_size == 1 ||
           (byte_count % word_size == 0 &&
            (target_byte_order == "little" || target_byte_order == "big"));
  }
  return false;
}

std::optional<std::string>
format_memory_bytes(std::span<const std::uint8_t> bytes,
                    MemoryCopyFormat format, MemoryByteOrder order,
                    std::size_t word_size, std::string_view target_byte_order) {
  if (!can_format_memory_bytes(bytes.size(), order, word_size,
                               target_byte_order))
    return std::nullopt;

  std::string_view prefix;
  std::string_view suffix;
  std::string_view byte_prefix = "0x";
  std::string_view separator = ", ";
  std::string_view array_size;
  std::string_view array_size_suffix;
  char size_digits[std::numeric_limits<std::size_t>::digits10 + 1];
  switch (format) {
  case MemoryCopyFormat::Hex:
    byte_prefix = {};
    separator = " ";
    break;
  case MemoryCopyFormat::Escaped:
    prefix = "\"";
    suffix = "\"";
    byte_prefix = "\\x";
    separator = {};
    break;
  case MemoryCopyFormat::CArray:
    prefix = "unsigned char data[] = {";
    suffix = "};";
    break;
  case MemoryCopyFormat::PythonBytearray:
    prefix = "data = bytearray([";
    suffix = "])";
    break;
  case MemoryCopyFormat::JavaScriptUint8Array:
    prefix = "const data = new Uint8Array([";
    suffix = "]);";
    break;
  case MemoryCopyFormat::RustArray: {
    prefix = "let data: [u8; ";
    const auto result = std::to_chars(
        size_digits, size_digits + sizeof(size_digits), bytes.size());
    array_size = std::string_view(
        size_digits, static_cast<std::size_t>(result.ptr - size_digits));
    array_size_suffix = "] = [";
    suffix = "];";
    break;
  }
  default:
    return std::nullopt;
  }

  std::string text;
  const auto overhead = prefix.size() + array_size.size() +
                        array_size_suffix.size() + suffix.size();
  const auto stride = byte_prefix.size() + 2 + separator.size();
  if (bytes.size() > (text.max_size() - overhead) / stride)
    return std::nullopt;
  text.reserve(overhead + bytes.size() * stride - separator.size());
  text += prefix;
  text += array_size;
  text += array_size_suffix;
  const bool reverse_words =
      word_size > 1 && order != MemoryByteOrder::AsStored &&
      ((order == MemoryByteOrder::LittleEndian && target_byte_order == "big") ||
       (order == MemoryByteOrder::BigEndian && target_byte_order == "little"));
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    if (index != 0)
      text += separator;
    const auto source = reverse_words ? index - index % word_size +
                                            (word_size - 1 - index % word_size)
                                      : index;
    text += byte_prefix;
    append_hex_byte(text, bytes[source]);
  }
  text += suffix;
  return text;
}

std::optional<std::string>
format_memory_integer(std::span<const std::uint8_t> bytes,
                      MemoryByteOrder interpretation) {
  if (bytes.empty() || bytes.size() > sizeof(std::uint64_t) ||
      (interpretation != MemoryByteOrder::LittleEndian &&
       interpretation != MemoryByteOrder::BigEndian))
    return std::nullopt;
  std::string text;
  text.reserve(2 + bytes.size() * 2);
  text += "0x";
  for (std::size_t index = 0; index < bytes.size(); ++index) {
    const auto source = interpretation == MemoryByteOrder::LittleEndian
                            ? bytes.size() - 1 - index
                            : index;
    append_hex_byte(text, bytes[source]);
  }
  return text;
}

} // namespace mydbg::app
