#include "app/MemoryData.h"
#include "TestSupport.h"

#include <array>
#include <cstdio>
#include <stdexcept>

namespace {
using mydbg::app::can_format_memory_bytes;
using mydbg::app::format_memory_bytes;
using mydbg::app::format_memory_integer;
using mydbg::app::MemoryByteOrder;
using mydbg::app::MemoryCopyFormat;

using debugger::test::require;

void check_word_order_and_selection() {
  const std::array<std::uint8_t, 10> dump{0xDE, 0x00, 0x80, 0xFF, 0x01,
                                          0x23, 0x45, 0x67, 0x89, 0xAD};
  const auto selected = std::span{dump}.subspan(1, 8);
  for (const auto target :
       {std::string_view{"little"}, std::string_view{"big"}}) {
    const auto matching = target == "little" ? MemoryByteOrder::LittleEndian
                                             : MemoryByteOrder::BigEndian;
    const auto opposite = target == "little" ? MemoryByteOrder::BigEndian
                                             : MemoryByteOrder::LittleEndian;
    require(format_memory_bytes(selected, MemoryCopyFormat::Hex, matching, 4,
                                target) == "00 80 FF 01 23 45 67 89",
            "matching endian must preserve the selected bytes only");
    require(format_memory_bytes(selected, MemoryCopyFormat::Hex, opposite, 4,
                                target) == "01 FF 80 00 89 67 45 23",
            "32-bit conversion must reverse each word, not the selection");
    require(format_memory_bytes(selected, MemoryCopyFormat::Hex, opposite, 2,
                                target) == "80 00 01 FF 45 23 89 67",
            "16-bit conversion must use selection-relative word boundaries");
    require(format_memory_bytes(selected, MemoryCopyFormat::Hex, opposite, 8,
                                target) == "89 67 45 23 01 FF 80 00",
            "64-bit conversion must preserve all eight bytes");
  }
  require(
      format_memory_bytes(selected.first(3), MemoryCopyFormat::Hex,
                          MemoryByteOrder::AsStored, 4,
                          "unknown") == "00 80 FF",
      "raw copy must preserve partial words without target endian metadata");
  require(format_memory_bytes(std::span{dump}.last(1), MemoryCopyFormat::Hex) ==
              "AD",
          "a selection ending at the dump boundary must include its last byte");
  require(!format_memory_bytes(std::span{dump}.subspan(dump.size()),
                               MemoryCopyFormat::Hex),
          "an empty selection at the dump boundary is invalid");
}

void check_rejected_conversions() {
  const std::array<std::uint8_t, 8> bytes{0, 0x80, 0xFF, 1, 2, 3, 4, 5};
  struct Case {
    std::size_t count;
    std::size_t width;
    std::string_view target;
  };
  const Case invalid[] = {
      {0, 4, "little"}, {3, 2, "little"}, {7, 4, "big"}, {8, 4, "unknown"},
      {8, 8, ""},       {8, 0, "little"}, {8, 3, "big"},
  };
  for (const auto &test : invalid) {
    for (const auto order :
         {MemoryByteOrder::LittleEndian, MemoryByteOrder::BigEndian}) {
      require(
          !can_format_memory_bytes(test.count, order, test.width, test.target),
          "conversion availability must reject ambiguous or partial words");
      require(!format_memory_bytes(std::span{bytes}.first(test.count),
                                   MemoryCopyFormat::Hex, order, test.width,
                                   test.target),
              "conversion must not truncate, pad, or assume unknown endian");
    }
  }
  require(format_memory_bytes(std::span{bytes}.first(3), MemoryCopyFormat::Hex,
                              MemoryByteOrder::BigEndian, 1,
                              "unknown") == "00 80 FF",
          "one-byte words do not require target endian information");
}

void check_unsigned_integers() {
  const std::array<std::uint8_t, 8> bytes{0x80, 0, 0, 0, 0, 0, 0, 0};
  require(format_memory_integer(bytes, MemoryByteOrder::BigEndian) ==
              "0x8000000000000000",
          "64-bit integers must preserve the unsigned high bit");
  require(format_memory_integer(bytes, MemoryByteOrder::LittleEndian) ==
              "0x0000000000000080",
          "integer output must retain leading zeros for the selected width");
  const std::array<std::uint8_t, 8> maximum{0xFF, 0xFF, 0xFF, 0xFF,
                                            0xFF, 0xFF, 0xFF, 0xFF};
  require(format_memory_integer(maximum, MemoryByteOrder::LittleEndian) ==
              "0xFFFFFFFFFFFFFFFF",
          "the maximum uint64 value must not overflow or gain a sign");
  require(format_memory_integer(std::span{bytes}.first(1),
                                MemoryByteOrder::LittleEndian) == "0x80",
          "one-byte integers must remain unsigned");
  require(format_memory_integer(std::span{bytes}.last(3),
                                MemoryByteOrder::BigEndian) == "0x000000",
          "non-native integer widths must keep all leading zeros");
  const std::array<std::uint8_t, 9> too_wide{};
  require(!format_memory_integer(too_wide, MemoryByteOrder::LittleEndian),
          "integer copies must reject values wider than uint64");
  require(!format_memory_integer({}, MemoryByteOrder::BigEndian),
          "integer copies must reject empty selections");
  require(!format_memory_integer(bytes, MemoryByteOrder::AsStored),
          "integer copies must require explicit interpretation");
}
} // namespace

int main() {
  try {
    check_word_order_and_selection();
    check_rejected_conversions();
    check_unsigned_integers();
    return 0;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "memory_data: %s\n", error.what());
    return 1;
  }
}
