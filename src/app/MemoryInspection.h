#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace debugger {
struct SessionSnapshot;
}

namespace mydbg::app {

struct ParsedField {
  std::string type;
  std::string name;
  std::size_t width{};
};

bool address_in_dump(const debugger::SessionSnapshot &snapshot,
                     std::uint64_t address, std::size_t width = 1);

std::optional<std::uint64_t>
read_memory_unsigned(const debugger::SessionSnapshot &snapshot,
                     std::uint64_t address, std::size_t width);

std::optional<std::string>
memory_inspection_string_at(const debugger::SessionSnapshot &snapshot,
                            std::uint64_t address);

std::size_t primitive_type_width(std::string_view type,
                                 std::uint32_t pointer_width);

std::vector<ParsedField>
parse_inline_struct_fields(std::string_view type, std::uint32_t pointer_width);

} // namespace mydbg::app
