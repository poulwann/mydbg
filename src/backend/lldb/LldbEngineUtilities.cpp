#include "backend/lldb/LldbEngineInternal.h"
#include "localization/Localization.h"

namespace debugger::lldb_detail {

using namespace std::chrono_literals;

std::string safe_string(const char *value) {
  return value == nullptr ? std::string{} : std::string{value};
}

std::string error_text(const lldb::SBError &error) {
  const char *message = error.GetCString();
  return message == nullptr
             ? std::string{l10n::text(l10n::Key::UtilityUnknownLldbError)}
             : std::string{message};
}

std::string byte_order_name(lldb::ByteOrder byte_order) {
  switch (byte_order) {
  case lldb::eByteOrderLittle:
    return "little";
  case lldb::eByteOrderBig:
    return "big";
  case lldb::eByteOrderPDP:
    return "PDP";
  case lldb::eByteOrderInvalid:
    return "invalid";
  }
  return "unknown";
}

bool is_x86_architecture(std::string_view architecture) {
  return architecture == "x86_64" || architecture == "x86" ||
         architecture == "i386" || architecture == "i486" ||
         architecture == "i586" || architecture == "i686";
}

bool is_inspectable_stop(lldb::StateType state) {
  return state == lldb::eStateStopped || state == lldb::eStateCrashed ||
         state == lldb::eStateSuspended;
}

bool should_destroy(lldb::StateType state) {
  return state != lldb::eStateInvalid && state != lldb::eStateExited &&
         state != lldb::eStateDetached && state != lldb::eStateUnloaded;
}
std::string_view trim(std::string_view text) {
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.front())) != 0) {
    text.remove_prefix(1);
  }
  while (!text.empty() &&
         std::isspace(static_cast<unsigned char>(text.back())) != 0) {
    text.remove_suffix(1);
  }
  return text;
}

std::string lowercase(std::string_view text) {
  std::string result{text};
  std::transform(result.begin(), result.end(), result.begin(), [](char value) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
  });
  return result;
}

std::optional<std::uint64_t> parse_integer(std::string_view text) {
  text = trim(text);
  int base = 10;
  if (text.starts_with("0x") || text.starts_with("0X")) {
    text.remove_prefix(2);
    base = 16;
  }
  if (text.empty()) {
    return std::nullopt;
  }

  std::uint64_t value = 0;
  const auto [end, error] =
      std::from_chars(text.data(), text.data() + text.size(), value, base);
  if (error != std::errc{} || end != text.data() + text.size()) {
    return std::nullopt;
  }
  return value;
}

std::vector<std::string> split_arguments(std::string_view text) {
  std::vector<std::string> arguments;
  std::string current;
  char quote = '\0';
  bool escaped = false;
  for (const char character : text) {
    if (escaped) {
      current.push_back(character);
      escaped = false;
    } else if (character == '\\' && quote != '\'') {
      escaped = true;
    } else if (quote != '\0') {
      if (character == quote) {
        quote = '\0';
      } else {
        current.push_back(character);
      }
    } else if (character == '\'' || character == '"') {
      quote = character;
    } else if (std::isspace(static_cast<unsigned char>(character)) != 0) {
      if (!current.empty()) {
        arguments.push_back(std::move(current));
        current.clear();
      }
    } else {
      current.push_back(character);
    }
  }
  if (escaped) {
    current.push_back('\\');
  }
  if (!current.empty()) {
    arguments.push_back(std::move(current));
  }
  return arguments;
}

std::string cyclic_pattern(std::size_t length) {
  constexpr std::string_view alphabet = "abcdefghijklmnopqrstuvwxyz";
  constexpr std::size_t subsequence_size = 4;
  const std::size_t maximum =
      alphabet.size() * alphabet.size() * alphabet.size() * alphabet.size();
  length = std::min(length, maximum);
  std::vector<std::size_t> state(alphabet.size() * subsequence_size + 1);
  std::string pattern;
  pattern.reserve(length);
  std::function<void(std::size_t, std::size_t)> generate =
      [&](std::size_t position, std::size_t period) {
        if (pattern.size() >= length) {
          return;
        }
        if (position > subsequence_size) {
          if (subsequence_size % period == 0) {
            for (std::size_t index = 1;
                 index <= period && pattern.size() < length; ++index) {
              pattern.push_back(alphabet[state[index]]);
            }
          }
          return;
        }
        state[position] = state[position - period];
        generate(position + 1, period);
        for (std::size_t value = state[position - period] + 1;
             value < alphabet.size(); ++value) {
          state[position] = value;
          generate(position + 1, position);
        }
      };
  generate(1, 1);
  return pattern;
}

std::optional<std::vector<std::uint8_t>>
parse_hex_bytes(std::string_view text) {
  std::vector<std::uint8_t> bytes;
  for (std::string token : split_arguments(text)) {
    if (token.starts_with("0x") || token.starts_with("0X")) {
      token.erase(0, 2);
    }
    if (token.empty() || token.size() % 2 != 0) {
      return std::nullopt;
    }
    for (std::size_t index = 0; index < token.size(); index += 2) {
      unsigned int value = 0;
      const auto parsed = std::from_chars(token.data() + index,
                                          token.data() + index + 2, value, 16);
      if (parsed.ec != std::errc{} || parsed.ptr != token.data() + index + 2 ||
          value > std::numeric_limits<std::uint8_t>::max()) {
        return std::nullopt;
      }
      bytes.push_back(static_cast<std::uint8_t>(value));
    }
  }
  if (bytes.empty()) {
    return std::nullopt;
  }
  return bytes;
}

std::optional<std::vector<std::uint8_t>>
assemble_intel_instruction(std::string_view instruction, std::uint64_t address,
                           std::string_view architecture,
                           std::uint32_t address_byte_size,
                           std::string &failure) {
  if (architecture.find("x86") == std::string_view::npos &&
      architecture.find("i386") == std::string_view::npos) {
    failure = l10n::text(l10n::Key::UtilityIntelAssemblyRequiresX86);
    return std::nullopt;
  }
  if (address_byte_size != 4 && address_byte_size != 8) {
    failure = l10n::text(l10n::Key::UtilityUnsupportedX86AddressSize);
    return std::nullopt;
  }

  const std::unique_ptr<RzAsm, decltype(&rz_asm_free)> assembler{rz_asm_new(),
                                                                 &rz_asm_free};
  if (!assembler || !rz_asm_use(assembler.get(), "x86") ||
      !rz_asm_set_arch(assembler.get(), "x86",
                       static_cast<int>(address_byte_size * 8)) ||
      !rz_asm_use_assembler(assembler.get(), "x86.nz") ||
      !rz_asm_set_syntax(assembler.get(), RZ_ASM_SYNTAX_INTEL)) {
    failure = l10n::text(l10n::Key::UtilityAssemblerInitializationFailed);
    return std::nullopt;
  }
  rz_asm_set_pc(assembler.get(), address);

  const std::string source{instruction};
  RzAsmCode *code = rz_asm_massemble(assembler.get(), source.c_str());
  if (code == nullptr || code->len <= 0 || code->bytes == nullptr) {
    if (code != nullptr) {
      rz_asm_code_free(code);
    }
    failure = l10n::text(l10n::Key::UtilityAssemblyFailed);
    return std::nullopt;
  }
  std::vector<std::uint8_t> bytes(
      code->bytes, code->bytes + static_cast<std::size_t>(code->len));
  rz_asm_code_free(code);
  return bytes;
}

std::optional<std::vector<std::uint8_t>>
read_memory_bytes(lldb::SBProcess &process, lldb::addr_t address,
                  std::size_t size, std::string &failure) {
  std::vector<std::uint8_t> bytes(size);
  lldb::SBError error;
  const std::size_t bytes_read =
      process.ReadMemory(address, bytes.data(), size, error);
  if (bytes_read != size) {
    failure = error.Fail() ? error_text(error)
                           : l10n::text(l10n::Key::UtilityShortMemoryRead);
    return std::nullopt;
  }
  return bytes;
}

std::string format_hexdump(lldb::addr_t address,
                           const std::vector<std::uint8_t> &bytes) {
  std::ostringstream output;
  for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
    output << "0x" << std::hex << std::setw(16) << std::setfill('0')
           << (address + offset) << "  ";
    const std::size_t line_size =
        std::min<std::size_t>(16, bytes.size() - offset);
    for (std::size_t index = 0; index < 16; ++index) {
      if (index < line_size) {
        output << std::setw(2)
               << static_cast<unsigned int>(bytes[offset + index]) << ' ';
      } else {
        output << "   ";
      }
    }
    output << " |";
    for (std::size_t index = 0; index < line_size; ++index) {
      const unsigned char character = bytes[offset + index];
      output << (std::isprint(character) != 0 ? static_cast<char>(character)
                                              : '.');
    }
    output << "|\n";
  }
  return output.str();
}

// FUNC symbol names and values from the target image's .symtab and .dynsym.
// Used for engine-side breakpoint symbol resolution on remote/qemu sessions,
// where LLDB cannot bind symbol breakpoints before the image maps (qemu-user
// stops at the dynamic loader). Non-PIE images use the value as-is; PIE
// values need the runtime base, which the caller resolves from the module
// list once the image is mapped.
std::vector<ElfSymbol> read_elf_symbols(const std::filesystem::path &path) {
  std::vector<ElfSymbol> symbols;
  std::ifstream file{path, std::ios::binary};
  const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>{file},
                                        std::istreambuf_iterator<char>{}};
  if (bytes.size() < EI_NIDENT || bytes[EI_MAG0] != ELFMAG0 ||
      bytes[EI_MAG1] != ELFMAG1 || bytes[EI_MAG2] != ELFMAG2 ||
      bytes[EI_MAG3] != ELFMAG3) {
    return symbols;
  }
  const bool elf64 = bytes[EI_CLASS] == ELFCLASS64;
  const bool big_endian = bytes[EI_DATA] == ELFDATA2MSB;
  if (!elf64 && bytes[EI_CLASS] != ELFCLASS32) {
    return symbols;
  }
  const auto read_value =
      [&bytes, big_endian](std::size_t offset,
                           std::size_t size) -> std::optional<std::uint64_t> {
    if (size == 0 || size > 8 || offset > bytes.size() ||
        size > bytes.size() - offset) {
      return std::nullopt;
    }
    return decode_pointer(bytes.data() + offset, static_cast<std::uint32_t>(size),
                          big_endian ? lldb::eByteOrderBig
                                     : lldb::eByteOrderLittle);
  };
  const auto read_required = [&read_value](std::size_t offset,
                                           std::size_t size) -> std::uint64_t {
    return read_value(offset, size).value_or(0);
  };

  const std::size_t header_size = elf64 ? sizeof(Elf64_Ehdr) : sizeof(Elf32_Ehdr);
  if (bytes.size() < header_size) {
    return symbols;
  }
  const std::size_t section_offset = static_cast<std::size_t>(
      read_required(elf64 ? 0x28 : 0x20, elf64 ? 8 : 4));
  const std::size_t section_entry = static_cast<std::size_t>(
      read_required(elf64 ? 0x3A : 0x2E, 2));
  const std::size_t section_count = static_cast<std::size_t>(
      read_required(elf64 ? 0x3C : 0x30, 2));
  if (section_count == 0 || section_entry == 0 ||
      section_offset > bytes.size() ||
      section_entry > bytes.size() - section_offset) {
    return symbols;
  }

  std::size_t symbol_size = elf64 ? sizeof(Elf64_Sym) : sizeof(Elf32_Sym);
  for (std::size_t index = 0; index < section_count; ++index) {
    const std::size_t base = section_offset + index * section_entry;
    const std::size_t header_size = elf64 ? 0x40 : 0x28;
    if (base > bytes.size() || header_size > bytes.size() - base) {
      continue;
    }
    const std::size_t type = static_cast<std::size_t>(
        read_required(base + (elf64 ? 0x04 : 0x04), 4));
    if (type != SHT_SYMTAB && type != SHT_DYNSYM) {
      continue;
    }
    // Read every symbol table: .dynsym has imports, .symtab has locals such
    // as the challenge functions; both are useful for breakpoints.
    const std::size_t offset = static_cast<std::size_t>(
        read_required(base + (elf64 ? 0x18 : 0x10), elf64 ? 8 : 4));
    const std::size_t table_bytes = static_cast<std::size_t>(
        read_required(base + (elf64 ? 0x20 : 0x14), elf64 ? 8 : 4));
    const std::size_t linked = static_cast<std::size_t>(
        read_required(base + (elf64 ? 0x28 : 0x18), 4));
    if (offset > bytes.size() || table_bytes > bytes.size() - offset) {
      continue;
    }
    const std::size_t string_base = section_offset + linked * section_entry;
    const std::size_t string_offset = static_cast<std::size_t>(
        read_required(string_base + (elf64 ? 0x18 : 0x10), elf64 ? 8 : 4));
    const std::size_t string_size = static_cast<std::size_t>(
        read_required(string_base + (elf64 ? 0x20 : 0x14), elf64 ? 8 : 4));
    if (string_offset > bytes.size() ||
        string_size > bytes.size() - string_offset) {
      continue;
    }
    const std::size_t count = table_bytes / symbol_size;
    symbols.reserve(std::min<std::size_t>(symbols.size() + count, 131072));
    for (std::size_t item = 0; item < count; ++item) {
      const std::size_t entry = offset + item * symbol_size;
      const std::uint64_t info = read_required(entry + (elf64 ? 0x04 : 0x0C), 1);
      if ((info & 0xF) != STT_FUNC) {
        continue;
      }
      const std::size_t name_offset = static_cast<std::size_t>(
          read_required(entry, 4));
      if (name_offset >= string_size) {
        continue;
      }
      const char *start = reinterpret_cast<const char *>(
          bytes.data() + string_offset + name_offset);
      const char *limit = reinterpret_cast<const char *>(
          bytes.data() + string_offset + string_size);
      std::string_view name{start, static_cast<std::size_t>(limit - start)};
      const std::size_t nul = name.find('\0');
      if (nul != std::string_view::npos) {
        name = name.substr(0, nul);
      }
      if (name.empty()) {
        continue;
      }
      symbols.push_back(ElfSymbol{
          .name = std::string{name},
          .value = read_required(entry + (elf64 ? 0x08 : 0x04),
                                 elf64 ? 8 : 4),
      });
    }
  }
  return symbols;
}

ElfSecurityInfo inspect_elf_security(const std::filesystem::path &path) {
  ElfSecurityInfo result;
  std::ifstream file{path, std::ios::binary};
  const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>{file},
                                        std::istreambuf_iterator<char>{}};
  if (bytes.size() < EI_NIDENT || bytes[EI_MAG0] != ELFMAG0 ||
      bytes[EI_MAG1] != ELFMAG1 || bytes[EI_MAG2] != ELFMAG2 ||
      bytes[EI_MAG3] != ELFMAG3) {
    return result;
  }
  const bool elf64 = bytes[EI_CLASS] == ELFCLASS64;
  const bool elf32 = bytes[EI_CLASS] == ELFCLASS32;
  const bool big_endian = bytes[EI_DATA] == ELFDATA2MSB;
  if ((!elf64 && !elf32) || (bytes[EI_DATA] != ELFDATA2LSB && !big_endian)) {
    return result;
  }
  const auto read_value =
      [&bytes, big_endian](std::size_t offset,
                           std::size_t size) -> std::optional<std::uint64_t> {
    if (size == 0 || size > 8 || offset > bytes.size() ||
        size > bytes.size() - offset) {
      return std::nullopt;
    }
    return decode_pointer(bytes.data() + offset, static_cast<std::uint32_t>(size),
                          big_endian ? lldb::eByteOrderBig
                                     : lldb::eByteOrderLittle);
  };
  const auto read_required = [&read_value](std::size_t offset,
                                           std::size_t size) -> std::uint64_t {
    return read_value(offset, size).value_or(0);
  };

  result.available = true;
  result.pie = read_required(16, 2) == ET_DYN;
  result.nx = true;
  result.stripped = true;

  const std::size_t program_offset_field = elf64 ? 32 : 28;
  const std::size_t program_entry_size_field = elf64 ? 54 : 42;
  const std::size_t program_count_field = elf64 ? 56 : 44;
  const std::uint64_t program_offset =
      read_required(program_offset_field, elf64 ? 8 : 4);
  const std::uint64_t program_entry_size =
      read_required(program_entry_size_field, 2);
  const std::uint64_t program_count = read_required(program_count_field, 2);
  std::optional<std::pair<std::uint64_t, std::uint64_t>> dynamic_segment;
  for (std::uint64_t index = 0; index < program_count; ++index) {
    const std::uint64_t entry = program_offset + index * program_entry_size;
    if (entry >= bytes.size()) {
      break;
    }
    const std::uint64_t type =
        read_required(static_cast<std::size_t>(entry), 4);
    const std::uint64_t flags =
        read_required(static_cast<std::size_t>(entry + (elf64 ? 4 : 24)), 4);
    const std::uint64_t file_offset = read_required(
        static_cast<std::size_t>(entry + (elf64 ? 8 : 4)), elf64 ? 8 : 4);
    const std::uint64_t file_size = read_required(
        static_cast<std::size_t>(entry + (elf64 ? 32 : 16)), elf64 ? 8 : 4);
    if (type == PT_GNU_STACK) {
      result.nx = (flags & PF_X) == 0;
    } else if (type == PT_GNU_RELRO) {
      result.relro = true;
    } else if (type == PT_DYNAMIC) {
      dynamic_segment = std::pair{file_offset, file_size};
    }
  }
  if (dynamic_segment) {
    const std::size_t dynamic_entry_size = elf64 ? 16 : 8;
    const std::uint64_t end = std::min<std::uint64_t>(
        bytes.size(), dynamic_segment->first + dynamic_segment->second);
    for (std::uint64_t offset = dynamic_segment->first;
         offset + dynamic_entry_size <= end; offset += dynamic_entry_size) {
      const std::uint64_t tag =
          read_required(static_cast<std::size_t>(offset), elf64 ? 8 : 4);
      const std::uint64_t value = read_required(
          static_cast<std::size_t>(offset + (elf64 ? 8 : 4)), elf64 ? 8 : 4);
      if (tag == DT_NULL) {
        break;
      }
      if (tag == DT_BIND_NOW ||
          (tag == DT_FLAGS && (value & DF_BIND_NOW) != 0) ||
          (tag == DT_FLAGS_1 && (value & DF_1_NOW) != 0)) {
        result.full_relro = result.relro;
      }
    }
  }

  const std::size_t section_offset_field = elf64 ? 40 : 32;
  const std::size_t section_entry_size_field = elf64 ? 58 : 46;
  const std::size_t section_count_field = elf64 ? 60 : 48;
  const std::uint64_t section_offset =
      read_required(section_offset_field, elf64 ? 8 : 4);
  const std::uint64_t section_entry_size =
      read_required(section_entry_size_field, 2);
  const std::uint64_t section_count = read_required(section_count_field, 2);
  for (std::uint64_t index = 0; index < section_count; ++index) {
    const std::uint64_t entry = section_offset + index * section_entry_size;
    if (entry + 8 > bytes.size()) {
      break;
    }
    if (read_required(static_cast<std::size_t>(entry + 4), 4) == SHT_SYMTAB) {
      result.stripped = false;
      break;
    }
  }

  constexpr std::string_view canary_name = "__stack_chk_fail";
  result.stack_canary =
      std::search(bytes.begin(), bytes.end(), canary_name.begin(),
                  canary_name.end()) != bytes.end();
  return result;
}

} // namespace debugger::lldb_detail

namespace debugger {

std::string_view operand_role_display(std::string_view role) {
  if (role == "analysis") {
    return l10n::text(l10n::Key::SnapshotOperandRoleAnalysis);
  }
  if (role == "destination") {
    return l10n::text(l10n::Key::SnapshotOperandRoleDestination);
  }
  if (role == "source") {
    return l10n::text(l10n::Key::SnapshotOperandRoleSource);
  }
  return role;
}

std::string cyclic_source_display(std::string_view source) {
  constexpr std::string_view register_prefix = "register ";
  constexpr std::string_view memory_suffix = " memory";
  if (source.starts_with(register_prefix)) {
    const auto name = source.substr(register_prefix.size());
    return l10n::format(l10n::Key::SnapshotCyclicRegisterSource,
                        static_cast<int>(name.size()), name.data());
  }
  if (source.ends_with(memory_suffix)) {
    const auto name = source.substr(0, source.size() - memory_suffix.size());
    return l10n::format(l10n::Key::SnapshotCyclicMemorySource,
                        static_cast<int>(name.size()), name.data());
  }
  return std::string{source};
}

} // namespace debugger
