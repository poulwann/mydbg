#include "backend/lldb/LldbEngineInternal.h"
#include "localization/Localization.h"

namespace debugger::lldb_detail {

using namespace std::chrono_literals;

std::optional<BinaryImage> read_binary_image(const std::filesystem::path &path,
                                             std::string &error) {
  constexpr std::uintmax_t maximum_binary_size = 512ULL * 1024ULL * 1024ULL;
  std::error_code size_error;
  const std::uintmax_t binary_size =
      std::filesystem::file_size(path, size_error);
  if (!size_error && binary_size > maximum_binary_size) {
    error = l10n::text(l10n::Key::ScanBinaryTooLarge);
    return std::nullopt;
  }
  std::ifstream file{path, std::ios::binary};
  if (!file) {
    error = l10n::text(l10n::Key::ScanBinaryOpenFailed);
    return std::nullopt;
  }
  BinaryImage image;
  image.bytes.assign(std::istreambuf_iterator<char>{file},
                     std::istreambuf_iterator<char>{});
  if (image.bytes.size() < EI_NIDENT || image.bytes[EI_MAG0] != ELFMAG0 ||
      image.bytes[EI_MAG1] != ELFMAG1 || image.bytes[EI_MAG2] != ELFMAG2 ||
      image.bytes[EI_MAG3] != ELFMAG3) {
    error = l10n::text(l10n::Key::ScanBinaryNotElf);
    return std::nullopt;
  }
  const bool elf64 = image.bytes[EI_CLASS] == ELFCLASS64;
  const bool elf32 = image.bytes[EI_CLASS] == ELFCLASS32;
  image.big_endian = image.bytes[EI_DATA] == ELFDATA2MSB;
  if ((!elf64 && !elf32) ||
      (image.bytes[EI_DATA] != ELFDATA2LSB && !image.big_endian)) {
    error = l10n::text(l10n::Key::ScanUnsupportedElfFormat);
    return std::nullopt;
  }
  const auto read_value =
      [&image](std::size_t offset,
               std::size_t size) -> std::optional<std::uint64_t> {
    if (size == 0 || size > sizeof(std::uint64_t) ||
        offset > image.bytes.size() || size > image.bytes.size() - offset) {
      return std::nullopt;
    }
    return decode_pointer(image.bytes.data() + offset,
                          static_cast<std::uint32_t>(size),
                          image.big_endian ? lldb::eByteOrderBig
                                           : lldb::eByteOrderLittle);
  };
  const std::size_t program_offset_field = elf64 ? 32 : 28;
  const std::size_t program_entry_size_field = elf64 ? 54 : 42;
  const std::size_t program_count_field = elf64 ? 56 : 44;
  const auto program_offset = read_value(program_offset_field, elf64 ? 8 : 4);
  const auto program_entry_size = read_value(program_entry_size_field, 2);
  const auto program_count = read_value(program_count_field, 2);
  if (!program_offset || !program_entry_size || !program_count ||
      *program_entry_size == 0) {
    error = l10n::text(l10n::Key::ScanInvalidElfProgramHeaders);
    return std::nullopt;
  }
  image.load_segments.reserve(static_cast<std::size_t>(*program_count));
  for (std::uint64_t index = 0; index < *program_count; ++index) {
    if (index > (std::numeric_limits<std::uint64_t>::max() - *program_offset) /
                    *program_entry_size) {
      break;
    }
    const std::uint64_t raw_entry =
        *program_offset + index * *program_entry_size;
    if (raw_entry > std::numeric_limits<std::size_t>::max()) {
      break;
    }
    const std::size_t entry = static_cast<std::size_t>(raw_entry);
    const auto type = read_value(entry, 4);
    const auto file_offset = read_value(entry + (elf64 ? 8 : 4), elf64 ? 8 : 4);
    const auto virtual_address =
        read_value(entry + (elf64 ? 16 : 8), elf64 ? 8 : 4);
    const auto file_size = read_value(entry + (elf64 ? 32 : 16), elf64 ? 8 : 4);
    if (!type || !file_offset || !virtual_address || !file_size) {
      break;
    }
    if (*type == PT_LOAD && *file_offset <= image.bytes.size() &&
        *file_size <= image.bytes.size() - *file_offset) {
      image.load_segments.push_back(ElfLoadSegment{
          .file_offset = *file_offset,
          .file_size = *file_size,
          .virtual_address = *virtual_address,
      });
    }
  }
  error.clear();
  return image;
}

std::optional<std::uint64_t>
file_address_for_offset(const BinaryImage &image, std::uint64_t file_offset) {
  const auto segment = std::find_if(
      image.load_segments.begin(), image.load_segments.end(),
      [file_offset](const ElfLoadSegment &candidate) {
        return file_offset >= candidate.file_offset &&
               file_offset - candidate.file_offset < candidate.file_size;
      });
  if (segment == image.load_segments.end()) {
    return std::nullopt;
  }
  const std::uint64_t delta = file_offset - segment->file_offset;
  if (delta >
      std::numeric_limits<std::uint64_t>::max() - segment->virtual_address) {
    return std::nullopt;
  }
  return segment->virtual_address + delta;
}

bool is_binary_string_character(std::uint8_t value) {
  return value == '\t' || (value >= 0x20U && value <= 0x7eU);
}

std::vector<BinaryStringInfo> extract_binary_strings(const BinaryImage &image,
                                                     std::size_t minimum_length,
                                                     bool include_utf16,
                                                     std::size_t &total,
                                                     bool &truncated) {
  constexpr std::size_t maximum_results = 50'000;
  std::vector<BinaryStringInfo> results;
  total = 0;
  truncated = false;
  const auto append = [&](std::uint64_t offset, std::string encoding,
                          std::string value) {
    ++total;
    if (results.size() == maximum_results) {
      truncated = true;
      return;
    }
    BinaryStringInfo result{
        .file_offset = offset,
        .encoding = std::move(encoding),
        .value = std::move(value),
    };
    if (const auto address = file_address_for_offset(image, offset)) {
      result.file_address = *address;
      result.has_file_address = true;
    }
    results.push_back(std::move(result));
  };

  for (std::size_t offset = 0; offset < image.bytes.size();) {
    const std::size_t begin = offset;
    while (offset < image.bytes.size() &&
           is_binary_string_character(image.bytes[offset])) {
      ++offset;
    }
    if (offset - begin >= minimum_length) {
      append(begin, "ASCII",
             std::string{
                 reinterpret_cast<const char *>(image.bytes.data() + begin),
                 offset - begin});
    }
    if (offset == begin) {
      ++offset;
    }
  }

  if (include_utf16) {
    for (std::size_t parity = 0; parity < 2; ++parity) {
      for (std::size_t offset = parity; offset + 1 < image.bytes.size();) {
        const std::size_t begin = offset;
        std::string value;
        while (offset + 1 < image.bytes.size()) {
          const std::uint8_t character =
              image.bytes[offset + (image.big_endian ? 1U : 0U)];
          const std::uint8_t zero =
              image.bytes[offset + (image.big_endian ? 0U : 1U)];
          if (zero != 0 || !is_binary_string_character(character)) {
            break;
          }
          value.push_back(static_cast<char>(character));
          offset += 2;
        }
        if (value.size() >= minimum_length) {
          append(begin, image.big_endian ? "UTF-16BE" : "UTF-16LE",
                 std::move(value));
        }
        if (offset == begin) {
          offset += 2;
        }
      }
    }
  }
  std::sort(results.begin(), results.end(),
            [](const BinaryStringInfo &left, const BinaryStringInfo &right) {
              if (left.file_offset != right.file_offset) {
                return left.file_offset < right.file_offset;
              }
              return left.encoding < right.encoding;
            });
  return results;
}


std::size_t value_scan_width(ValueScanType type) {
  switch (type) {
  case ValueScanType::Byte:
    return 1;
  case ValueScanType::Word:
    return 2;
  case ValueScanType::Dword:
  case ValueScanType::Float:
    return 4;
  case ValueScanType::Qword:
  case ValueScanType::Double:
    return 8;
  }
  return 0;
}

std::uint64_t decode_scan_unsigned(const ScanValueBytes &bytes,
                                   std::size_t width, bool big_endian) {
  std::uint64_t value = 0;
  for (std::size_t index = 0; index < width; ++index) {
    const std::size_t byte_index = big_endian ? index : width - 1 - index;
    value = (value << 8U) | bytes[byte_index];
  }
  return value;
}

std::int64_t decode_scan_signed(const ScanValueBytes &bytes, std::size_t width,
                                bool big_endian) {
  const std::uint64_t raw = decode_scan_unsigned(bytes, width, big_endian);
  if (width == sizeof(std::uint64_t)) {
    return std::bit_cast<std::int64_t>(raw);
  }
  const std::size_t bits = width * 8;
  const std::uint64_t sign = std::uint64_t{1} << (bits - 1);
  return static_cast<std::int64_t>((raw ^ sign) - sign);
}

void encode_scan_unsigned(std::uint64_t value, std::size_t width,
                          bool big_endian, ScanValueBytes &bytes) {
  bytes.fill(0);
  for (std::size_t index = 0; index < width; ++index) {
    const std::size_t byte_index = big_endian ? width - 1 - index : index;
    bytes[byte_index] = static_cast<std::uint8_t>(value & 0xffU);
    value >>= 8U;
  }
}

std::optional<ScanValueBytes>
parse_scan_value(std::string_view text, ValueScanType type, bool signed_values,
                 bool big_endian, std::string &error) {
  text = trim(text);
  if (text.empty()) {
    error = l10n::text(l10n::Key::ScanValueRequired);
    return std::nullopt;
  }
  ScanValueBytes bytes{};
  if (type == ValueScanType::Float || type == ValueScanType::Double) {
    std::string owned{text};
    char *end = nullptr;
    errno = 0;
    if (type == ValueScanType::Float) {
      const float value = std::strtof(owned.c_str(), &end);
      if (end == owned.c_str() || *end != '\0' || errno == ERANGE ||
          !std::isfinite(value)) {
        error = l10n::text(l10n::Key::ScanInvalidFloat);
        return std::nullopt;
      }
      encode_scan_unsigned(std::bit_cast<std::uint32_t>(value), 4, big_endian,
                           bytes);
    } else {
      const double value = std::strtod(owned.c_str(), &end);
      if (end == owned.c_str() || *end != '\0' || errno == ERANGE ||
          !std::isfinite(value)) {
        error = l10n::text(l10n::Key::ScanInvalidDouble);
        return std::nullopt;
      }
      encode_scan_unsigned(std::bit_cast<std::uint64_t>(value), 8, big_endian,
                           bytes);
    }
    error.clear();
    return bytes;
  }

  const std::size_t width = value_scan_width(type);
  bool negative = false;
  if (text.front() == '-') {
    negative = true;
    text.remove_prefix(1);
  } else if (text.front() == '+') {
    text.remove_prefix(1);
  }
  int base = 10;
  if (text.starts_with("0x") || text.starts_with("0X")) {
    text.remove_prefix(2);
    base = 16;
  }
  std::uint64_t magnitude = 0;
  const auto [end, parse_error] =
      std::from_chars(text.data(), text.data() + text.size(), magnitude, base);
  if (text.empty() || parse_error != std::errc{} ||
      end != text.data() + text.size()) {
    error = l10n::text(l10n::Key::ScanInvalidInteger);
    return std::nullopt;
  }
  const std::uint64_t maximum = width == sizeof(std::uint64_t)
                                    ? std::numeric_limits<std::uint64_t>::max()
                                    : (std::uint64_t{1} << (width * 8U)) - 1U;
  std::uint64_t encoded = magnitude;
  if (negative) {
    if (!signed_values) {
      error = l10n::text(l10n::Key::ScanNegativeRequiresSigned);
      return std::nullopt;
    }
    const std::uint64_t maximum_magnitude = std::uint64_t{1}
                                            << (width * 8U - 1U);
    if (magnitude > maximum_magnitude) {
      error = l10n::text(l10n::Key::ScanSignedValueOutOfRange);
      return std::nullopt;
    }
    encoded = std::uint64_t{0} - magnitude;
  } else {
    const std::uint64_t positive_maximum =
        signed_values ? maximum >> 1U : maximum;
    if (magnitude > positive_maximum) {
      error = signed_values ? l10n::text(l10n::Key::ScanSignedValueOutOfRange)
                            : l10n::text(l10n::Key::ScanValueOutOfRange);
      return std::nullopt;
    }
  }
  encode_scan_unsigned(encoded & maximum, width, big_endian, bytes);
  error.clear();
  return bytes;
}

double decode_scan_float(const ScanValueBytes &bytes, ValueScanType type,
                         bool big_endian) {
  if (type == ValueScanType::Float) {
    return static_cast<double>(std::bit_cast<float>(static_cast<std::uint32_t>(
        decode_scan_unsigned(bytes, 4, big_endian))));
  }
  return std::bit_cast<double>(decode_scan_unsigned(bytes, 8, big_endian));
}

int compare_scan_values(const ScanValueBytes &left, const ScanValueBytes &right,
                        ValueScanType type, bool signed_values,
                        bool big_endian) {
  if (type == ValueScanType::Float || type == ValueScanType::Double) {
    const double left_value = decode_scan_float(left, type, big_endian);
    const double right_value = decode_scan_float(right, type, big_endian);
    if (std::isnan(left_value) || std::isnan(right_value)) {
      return 0;
    }
    return left_value < right_value ? -1 : left_value > right_value ? 1 : 0;
  }
  const std::size_t width = value_scan_width(type);
  if (signed_values) {
    const std::int64_t left_value = decode_scan_signed(left, width, big_endian);
    const std::int64_t right_value =
        decode_scan_signed(right, width, big_endian);
    return left_value < right_value ? -1 : left_value > right_value ? 1 : 0;
  }
  const std::uint64_t left_value =
      decode_scan_unsigned(left, width, big_endian);
  const std::uint64_t right_value =
      decode_scan_unsigned(right, width, big_endian);
  return left_value < right_value ? -1 : left_value > right_value ? 1 : 0;
}

std::string format_scan_value(const ScanValueBytes &bytes, ValueScanType type,
                              bool signed_values, bool big_endian) {
  std::ostringstream output;
  if (type == ValueScanType::Float || type == ValueScanType::Double) {
    output << std::setprecision(type == ValueScanType::Float ? 9 : 17)
           << decode_scan_float(bytes, type, big_endian);
  } else if (signed_values) {
    output << decode_scan_signed(bytes, value_scan_width(type), big_endian);
  } else {
    output << decode_scan_unsigned(bytes, value_scan_width(type), big_endian);
  }
  return output.str();
}

const MemoryRegionInfo *region_containing(const SessionSnapshot &state,
                                          std::uint64_t address) {
  const auto region = std::find_if(
      state.memory_regions.begin(), state.memory_regions.end(),
      [address](const MemoryRegionInfo &candidate) {
        return address >= candidate.start && address < candidate.end;
      });
  return region == state.memory_regions.end() ? nullptr : &*region;
}

std::string permission_text(const MemoryRegionInfo &region) {
  std::string permissions{"---"};
  permissions[0] = region.readable ? 'r' : '-';
  permissions[1] = region.writable ? 'w' : '-';
  permissions[2] = region.executable ? 'x' : '-';
  return permissions;
}


} // namespace debugger::lldb_detail
