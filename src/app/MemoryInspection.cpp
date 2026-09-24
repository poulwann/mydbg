#include "app/MemoryInspection.h"
#include "app/DebuggerController.h"
#include "backend/lldb/LldbEngine.h"

#include <charconv>
#include <utility>

namespace mydbg::app {

bool address_in_dump(const debugger::SessionSnapshot &snapshot,
                     std::uint64_t address, std::size_t width) {
  return address >= snapshot.memory_base &&
         address - snapshot.memory_base <= snapshot.memory.size() &&
         width <= snapshot.memory.size() - (address - snapshot.memory_base);
}

std::optional<std::uint64_t>
read_memory_unsigned(const debugger::SessionSnapshot &snapshot,
                     std::uint64_t address, std::size_t width) {
  if (width == 0 || width > sizeof(std::uint64_t) ||
      !address_in_dump(snapshot, address, width)) {
    return std::nullopt;
  }
  const std::size_t offset =
      static_cast<std::size_t>(address - snapshot.memory_base);
  std::uint64_t value = 0;
  if (snapshot.byte_order == "big") {
    for (std::size_t index = 0; index < width; ++index) {
      value = (value << 8U) | snapshot.memory[offset + index];
    }
  } else {
    for (std::size_t index = 0; index < width; ++index) {
      value |= static_cast<std::uint64_t>(snapshot.memory[offset + index])
               << (index * 8U);
    }
  }
  return value;
}

std::optional<std::string>
memory_inspection_string_at(const debugger::SessionSnapshot &snapshot,
                            std::uint64_t address) {
  if (!address_in_dump(snapshot, address)) {
    return std::nullopt;
  }
  const std::size_t offset =
      static_cast<std::size_t>(address - snapshot.memory_base);
  std::string result;
  for (std::size_t index = offset;
       index < snapshot.memory.size() && result.size() < 128; ++index) {
    const unsigned char value = snapshot.memory[index];
    if (value == 0) {
      break;
    }
    result.push_back(value >= 0x20U && value <= 0x7eU ? static_cast<char>(value)
                                                      : '.');
  }
  return result;
}

std::size_t primitive_type_width(std::string_view type,
                                 std::uint32_t pointer_width) {
  type = trim_view(type);
  if (type.find('*') != std::string_view::npos) {
    return pointer_width;
  }
  if (type == "char" || type == "int8_t" || type == "uint8_t" ||
      type == "byte" || type == "bool") {
    return 1;
  }
  if (type == "short" || type == "int16_t" || type == "uint16_t" ||
      type == "word") {
    return 2;
  }
  if (type == "int" || type == "unsigned int" || type == "int32_t" ||
      type == "uint32_t" || type == "float" || type == "dword") {
    return 4;
  }
  if (type == "long" || type == "unsigned long" || type == "long long" ||
      type == "unsigned long long" || type == "int64_t" || type == "uint64_t" ||
      type == "double" || type == "qword") {
    return 8;
  }
  return 0;
}

std::vector<ParsedField>
parse_inline_struct_fields(std::string_view type, std::uint32_t pointer_width) {
  const std::size_t open = type.find('{');
  const std::size_t close = type.rfind('}');
  if (open == std::string_view::npos || close == std::string_view::npos ||
      close <= open) {
    return {};
  }
  std::vector<ParsedField> fields;
  std::string_view body = type.substr(open + 1, close - open - 1);
  while (!body.empty()) {
    const std::size_t separator = body.find(';');
    std::string_view declaration = trim_view(body.substr(0, separator));
    if (!declaration.empty()) {
      std::size_t array_count = 1;
      const std::size_t array_open = declaration.rfind('[');
      if (array_open != std::string_view::npos && declaration.ends_with(']')) {
        const std::string_view count_text = declaration.substr(
            array_open + 1, declaration.size() - array_open - 2);
        std::from_chars(count_text.data(),
                        count_text.data() + count_text.size(), array_count);
        declaration = trim_view(declaration.substr(0, array_open));
      }
      const std::size_t name_start = declaration.find_last_of(" \t*&");
      if (name_start != std::string_view::npos &&
          name_start + 1 < declaration.size()) {
        const std::string name{trim_view(declaration.substr(name_start + 1))};
        std::string type_text{trim_view(declaration.substr(0, name_start + 1))};
        if (name_start > 0 && declaration[name_start] == '*') {
          type_text.push_back('*');
        }
        const std::size_t width =
            primitive_type_width(type_text, pointer_width) * array_count;
        if (width != 0) {
          fields.push_back(
              {.type = std::move(type_text), .name = name, .width = width});
        }
      }
    }
    if (separator == std::string_view::npos) {
      break;
    }
    body.remove_prefix(separator + 1);
  }
  return fields;
}

} // namespace mydbg::app
