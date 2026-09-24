#include "localization/Localization.h"
#include "LocalizationData.h"

#include <algorithm>
#include <array>
#include <cinttypes>
#include <cstdarg>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

namespace l10n {
namespace {
constexpr std::size_t key_count = static_cast<std::size_t>(Key::Count);

const generated::Entry &entry(Key key) {
  const auto index = static_cast<std::size_t>(key);
  if (index >= key_count) {
    throw std::out_of_range(generated::entries[static_cast<std::size_t>(
                                                   Key::LocalizationInvalidKey)]
                                .english.data());
  }
  return generated::entries[index];
}

template <typename... Args> std::string diagnostic(Key key, Args... args) {
  const char *pattern = entry(key).english.data();
  const int size = std::snprintf(nullptr, 0, pattern, args...);
  if (size < 0) {
    return entry(Key::LocalizationFormattingFailed).english.data();
  }
  std::string result(static_cast<std::size_t>(size), '\0');
  std::snprintf(result.data(), result.size() + 1, pattern, args...);
  return result;
}

[[noreturn]] void fail(Key key) {
  throw std::runtime_error(entry(key).english.data());
}

std::optional<std::size_t> find_key(std::string_view name) {
  const auto found = std::lower_bound(
      generated::entries.begin(), generated::entries.end(), name,
      [](const auto &candidate, std::string_view wanted) {
        return candidate.name < wanted;
      });
  if (found == generated::entries.end() || found->name != name) {
    return std::nullopt;
  }
  return static_cast<std::size_t>(found - generated::entries.begin());
}

std::string_view trim(std::string_view value) {
  const auto begin = value.find_first_not_of(" \t\r");
  if (begin == std::string_view::npos)
    return {};
  const auto end = value.find_last_not_of(" \t\r");
  return value.substr(begin, end - begin + 1);
}

bool valid_utf8(std::string_view value) {
  for (std::size_t offset = 0; offset < value.size();) {
    auto byte = static_cast<unsigned char>(value[offset++]);
    if (byte < 0x80)
      continue;
    unsigned count = 0;
    std::uint32_t codepoint = 0;
    std::uint32_t minimum = 0;
    if ((byte & 0xe0U) == 0xc0U) {
      count = 1;
      codepoint = byte & 0x1fU;
      minimum = 0x80;
    } else if ((byte & 0xf0U) == 0xe0U) {
      count = 2;
      codepoint = byte & 0x0fU;
      minimum = 0x800;
    } else if ((byte & 0xf8U) == 0xf0U) {
      count = 3;
      codepoint = byte & 0x07U;
      minimum = 0x10000;
    } else
      return false;
    if (value.size() - offset < count)
      return false;
    for (unsigned index = 0; index < count; ++index) {
      byte = static_cast<unsigned char>(value[offset++]);
      if ((byte & 0xc0U) != 0x80U)
        return false;
      codepoint = (codepoint << 6U) | (byte & 0x3fU);
    }
    if (codepoint < minimum || codepoint > 0x10ffff ||
        (codepoint >= 0xd800 && codepoint <= 0xdfff))
      return false;
  }
  return true;
}

void append_utf8(std::string &output, std::uint32_t value) {
  if (value < 0x80)
    output += static_cast<char>(value);
  else if (value < 0x800) {
    output += static_cast<char>(0xc0U | (value >> 6U));
    output += static_cast<char>(0x80U | (value & 0x3fU));
  } else if (value < 0x10000) {
    output += static_cast<char>(0xe0U | (value >> 12U));
    output += static_cast<char>(0x80U | ((value >> 6U) & 0x3fU));
    output += static_cast<char>(0x80U | (value & 0x3fU));
  } else {
    output += static_cast<char>(0xf0U | (value >> 18U));
    output += static_cast<char>(0x80U | ((value >> 12U) & 0x3fU));
    output += static_cast<char>(0x80U | ((value >> 6U) & 0x3fU));
    output += static_cast<char>(0x80U | (value & 0x3fU));
  }
}

std::string quoted_string(std::string_view input) {
  if (input.size() < 2 || input.front() != '"' || input.back() != '"')
    fail(Key::LocalizationInvalidQuotedString);
  std::string result;
  result.reserve(input.size() - 2);
  std::size_t position = 1;
  const auto hex_quad = [&]() {
    if (input.size() - position < 5)
      fail(Key::LocalizationInvalidQuotedString);
    std::uint32_t value = 0;
    for (unsigned index = 0; index < 4; ++index) {
      const char byte = input[position++];
      unsigned digit;
      if (byte >= '0' && byte <= '9')
        digit = static_cast<unsigned>(byte - '0');
      else if (byte >= 'a' && byte <= 'f')
        digit = static_cast<unsigned>(byte - 'a' + 10);
      else if (byte >= 'A' && byte <= 'F')
        digit = static_cast<unsigned>(byte - 'A' + 10);
      else {
        fail(Key::LocalizationInvalidQuotedString);
      }
      value = (value << 4U) | digit;
    }
    return value;
  };
  while (position < input.size() - 1) {
    const char byte = input[position++];
    if (static_cast<unsigned char>(byte) < 0x20 || byte == '"')
      fail(Key::LocalizationInvalidQuotedString);
    if (byte != '\\') {
      result += byte;
      continue;
    }
    if (position >= input.size() - 1)
      fail(Key::LocalizationInvalidQuotedString);
    switch (input[position++]) {
    case '"':
      result += '"';
      break;
    case '\\':
      result += '\\';
      break;
    case '/':
      result += '/';
      break;
    case 'b':
      result += '\b';
      break;
    case 'f':
      result += '\f';
      break;
    case 'n':
      result += '\n';
      break;
    case 'r':
      result += '\r';
      break;
    case 't':
      result += '\t';
      break;
    case 'u': {
      auto codepoint = hex_quad();
      if (codepoint >= 0xd800 && codepoint <= 0xdbff) {
        if (input.substr(position, 2) != "\\u")
          fail(Key::LocalizationInvalidQuotedString);
        position += 2;
        const auto low = hex_quad();
        if (low < 0xdc00 || low > 0xdfff)
          fail(Key::LocalizationInvalidQuotedString);
        codepoint = 0x10000 + ((codepoint - 0xd800) << 10U) + low - 0xdc00;
      } else if (codepoint >= 0xdc00 && codepoint <= 0xdfff) {
        fail(Key::LocalizationInvalidQuotedString);
      }
      append_utf8(result, codepoint);
      break;
    }
    default:
      fail(Key::LocalizationInvalidQuotedString);
    }
  }
  if (!valid_utf8(result))
    fail(Key::LocalizationInvalidQuotedString);
  return result;
}

std::string expand_integer_macros(std::string value) {
#define INTEGER_FORMAT(name)                                                   \
  std::pair<std::string_view, std::string_view>{"@" #name "@", name}
#define INTEGER_WIDTH(width)                                                   \
  INTEGER_FORMAT(PRId##width), INTEGER_FORMAT(PRIi##width),                    \
      INTEGER_FORMAT(PRIo##width), INTEGER_FORMAT(PRIu##width),                \
      INTEGER_FORMAT(PRIx##width), INTEGER_FORMAT(PRIX##width)
  static constexpr std::array macros{INTEGER_WIDTH(8),   INTEGER_WIDTH(16),
                                     INTEGER_WIDTH(32),  INTEGER_WIDTH(64),
                                     INTEGER_WIDTH(PTR), INTEGER_WIDTH(MAX)};
#undef INTEGER_WIDTH
#undef INTEGER_FORMAT
  std::size_t position = 0;
  while ((position = value.find("@PRI", position)) != std::string::npos) {
    const auto end = value.find('@', position + 1);
    const std::string_view token{value.data() + position,
                                 end == std::string::npos
                                     ? value.size() - position
                                     : end - position + 1};
    const auto found =
        std::find_if(macros.begin(), macros.end(), [token](const auto &macro) {
          return macro.first == token;
        });
    if (found == macros.end())
      throw std::runtime_error(diagnostic(Key::LocalizationUnknownIntegerMacro,
                                          std::string{token}.c_str()));
    value.replace(position, token.size(), found->second);
    position += found->second.size();
  }
  return value;
}

enum class Argument {
  None,
  Int,
  UInt,
  Long,
  ULong,
  LongLong,
  ULongLong,
  Double,
  LongDouble,
  String,
  WideString,
  Pointer
};

template <typename T> constexpr Argument integer_argument() {
  if constexpr (std::is_same_v<T, int>)
    return Argument::Int;
  else if constexpr (std::is_same_v<T, unsigned int>)
    return Argument::UInt;
  else if constexpr (std::is_same_v<T, long>)
    return Argument::Long;
  else if constexpr (std::is_same_v<T, unsigned long>)
    return Argument::ULong;
  else if constexpr (std::is_same_v<T, long long>)
    return Argument::LongLong;
  else
    return Argument::ULongLong;
}

std::vector<Argument> format_signature(std::string_view pattern) {
  std::vector<Argument> arguments;
  std::size_t offset = 0, sequential = 0;
  bool positional_used = false, sequential_used = false;
  const auto digit = [](char byte) { return byte >= '0' && byte <= '9'; };
  const auto argument_position = [&]() -> std::optional<std::size_t> {
    const auto begin = offset;
    std::size_t index = 0;
    while (offset < pattern.size() && digit(pattern[offset])) {
      index = std::min<std::size_t>(
          129, index * 10 + static_cast<std::size_t>(pattern[offset++] - '0'));
    }
    if (offset < pattern.size() && pattern[offset] == '$' && offset != begin) {
      ++offset;
      if (index == 0 || index > 128)
        fail(Key::LocalizationInvalidFormat);
      return index - 1;
    }
    offset = begin;
    return std::nullopt;
  };
  const auto add = [&](std::optional<std::size_t> index, Argument type) {
    if (index)
      positional_used = true;
    else {
      sequential_used = true;
      index = sequential++;
    }
    if ((positional_used && sequential_used) || *index >= 128)
      fail(Key::LocalizationInvalidFormat);
    if (arguments.size() <= *index)
      arguments.resize(*index + 1, Argument::None);
    if (arguments[*index] != Argument::None && arguments[*index] != type)
      fail(Key::LocalizationInvalidFormat);
    arguments[*index] = type;
  };
  while (offset < pattern.size()) {
    if (pattern[offset++] != '%')
      continue;
    if (offset < pattern.size() && pattern[offset] == '%') {
      ++offset;
      continue;
    }
    const auto value_position = argument_position();
    while (offset < pattern.size() &&
           std::string_view{"-+ #0'"}.find(pattern[offset]) !=
               std::string_view::npos)
      ++offset;
    if (offset < pattern.size() && pattern[offset] == '*') {
      ++offset;
      add(argument_position(), Argument::Int);
    } else
      while (offset < pattern.size() && digit(pattern[offset]))
        ++offset;
    if (offset < pattern.size() && pattern[offset] == '.') {
      ++offset;
      if (offset < pattern.size() && pattern[offset] == '*') {
        ++offset;
        add(argument_position(), Argument::Int);
      } else
        while (offset < pattern.size() && digit(pattern[offset]))
          ++offset;
    }
    std::string_view length;
    const auto pair = pattern.substr(offset, 2);
    if (pair == "hh" || pair == "ll") {
      length = pair;
      offset += 2;
    } else if (offset < pattern.size() &&
               std::string_view{"hljztL"}.find(pattern[offset]) !=
                   std::string_view::npos) {
      length = pattern.substr(offset++, 1);
    }
    if (offset == pattern.size())
      fail(Key::LocalizationInvalidFormat);
    const char conversion = pattern[offset++];
    Argument type = Argument::None;
    if (std::string_view{"diouxX"}.find(conversion) != std::string_view::npos) {
      const bool signed_value = conversion == 'd' || conversion == 'i';
      if (length.empty() || length == "h" || length == "hh")
        type = signed_value ? Argument::Int : Argument::UInt;
      else if (length == "l")
        type = signed_value ? Argument::Long : Argument::ULong;
      else if (length == "ll")
        type = signed_value ? Argument::LongLong : Argument::ULongLong;
      else if (length == "j")
        type = signed_value ? integer_argument<std::intmax_t>()
                            : integer_argument<std::uintmax_t>();
      else if (length == "z")
        type = signed_value
                   ? integer_argument<std::make_signed_t<std::size_t>>()
                   : integer_argument<std::size_t>();
      else if (length == "t")
        type = signed_value
                   ? integer_argument<std::ptrdiff_t>()
                   : integer_argument<std::make_unsigned_t<std::ptrdiff_t>>();
    } else if (std::string_view{"fFeEgGaA"}.find(conversion) !=
               std::string_view::npos) {
      if (length.empty() || length == "l")
        type = Argument::Double;
      else if (length == "L")
        type = Argument::LongDouble;
    } else if (conversion == 's') {
      if (length.empty())
        type = Argument::String;
      else if (length == "l")
        type = Argument::WideString;
    } else if (conversion == 'c' && length.empty())
      type = Argument::Int;
    else if (conversion == 'p' && length.empty())
      type = Argument::Pointer;
    if (type == Argument::None)
      fail(Key::LocalizationInvalidFormat); // Includes %n.
    add(value_position, type);
  }
  if (std::find(arguments.begin(), arguments.end(), Argument::None) !=
      arguments.end())
    fail(Key::LocalizationInvalidFormat);
  return arguments;
}

class Catalog final {
public:
  Catalog() {
    if (const char *configured = std::getenv("MYDBG_TRANSLATION");
        configured && *configured) {
      try {
        const std::filesystem::path path{configured};
        if (std::filesystem::is_directory(path)) {
          std::vector<std::filesystem::path> files;
          for (const auto &file : std::filesystem::directory_iterator(path)) {
            if (file.is_regular_file() && file.path().extension() == ".ini")
              files.push_back(file.path());
          }
          std::sort(files.begin(), files.end());
          if (files.empty())
            fail(Key::LocalizationEmptyDirectory);
          for (const auto &file : files)
            load(file);
        } else
          load(path);
      } catch (const std::exception &error) {
        // Do not call text()/format() while constructing their backing storage.
        std::fprintf(stderr,
                     entry(Key::LocalizationRejectedCatalog).english.data(),
                     configured, error.what());
        for (auto &value : translated_)
          value.clear();
        present_.fill(false);
      }
    }
    for (std::size_t index = 0; index < key_count; ++index) {
      const auto &definition = generated::entries[index];
      values_[index] = present_[index] ? translated_[index].c_str()
                                       : definition.english.data();
      if (definition.label) {
        labels_[index] = values_[index];
        labels_[index] += "###";
        labels_[index] += definition.name;
      }
    }
  }

  const char *text(Key key) const {
    entry(key);
    return values_[static_cast<std::size_t>(key)];
  }
  const char *label(Key key) const {
    if (!entry(key).label)
      fail(Key::LocalizationInvalidLabel);
    return labels_[static_cast<std::size_t>(key)].c_str();
  }

private:
  void load(const std::filesystem::path &path) {
    std::ifstream input{path, std::ios::binary};
    const std::string filename = path.string();
    if (!input)
      throw std::runtime_error(
          diagnostic(Key::LocalizationReadFailed, filename.c_str()));
    std::string line, section;
    std::size_t line_number = 0;
    while (std::getline(input, line)) {
      ++line_number;
      std::string_view content{line};
      if (line_number == 1 && content.starts_with("\xef\xbb\xbf"))
        content.remove_prefix(3);
      content = trim(content);
      if (content.empty() || content.front() == '#' || content.front() == ';')
        continue;
      try {
        if (content.front() == '[' && content.back() == ']') {
          section = content.substr(1, content.size() - 2);
          if (section != "strings" && section != "formats" &&
              section != "labels")
            fail(Key::LocalizationExpectedSection);
          continue;
        }
        if (section.empty())
          fail(Key::LocalizationExpectedSection);
        const auto equal = content.find('=');
        if (equal == std::string_view::npos)
          fail(Key::LocalizationExpectedAssignment);
        const auto name = trim(content.substr(0, equal));
        const auto index = find_key(name);
        if (!index)
          throw std::runtime_error(diagnostic(Key::LocalizationUnknownKey,
                                              std::string{name}.c_str()));
        if (present_[*index])
          throw std::runtime_error(diagnostic(Key::LocalizationDuplicateKey,
                                              std::string{name}.c_str()));
        const auto &definition = generated::entries[*index];
        if ((section == "formats") != definition.format ||
            (section == "labels") != definition.label)
          throw std::runtime_error(diagnostic(Key::LocalizationWrongSection,
                                              std::string{name}.c_str()));
        std::string value = expand_integer_macros(
            quoted_string(trim(content.substr(equal + 1))));
        if (definition.label && value.find("##") != std::string::npos)
          fail(Key::LocalizationInvalidLabel);
        if (std::count(value.begin(), value.end(), '\0') !=
                std::count(definition.english.begin(), definition.english.end(),
                           '\0') ||
            (!definition.english.empty() && definition.english.back() == '\0' &&
             (value.empty() || value.back() != '\0')))
          fail(Key::LocalizationInvalidNulls);
        if (definition.format &&
            format_signature(value) != format_signature(definition.english))
          fail(Key::LocalizationInvalidFormat);
        translated_[*index] = std::move(value);
        present_[*index] = true;
      } catch (const std::exception &error) {
        throw std::runtime_error(diagnostic(Key::LocalizationLineError,
                                            filename.c_str(), line_number,
                                            error.what()));
      }
    }
    if (input.bad())
      throw std::runtime_error(
          diagnostic(Key::LocalizationReadFailed, filename.c_str()));
  }

  std::array<std::string, key_count> translated_;
  std::array<std::string, key_count> labels_;
  std::array<bool, key_count> present_{};
  std::array<const char *, key_count> values_{};
};

const Catalog &catalog() {
  static const Catalog value;
  return value;
}
} // namespace

const char *text(Key key) { return catalog().text(key); }
const char *label(Key key) { return catalog().label(key); }
const char *english(Key key) { return entry(key).english.data(); }
std::span<const Key> window_keys() { return generated::windows; }
const char *format_string(Key key) {
  if (!entry(key).format)
    fail(Key::LocalizationInvalidFormat);
  return text(key);
}
std::string detail::format_message(const char *pattern, ...) {
  std::va_list arguments;
  va_start(arguments, pattern);
  const int size = std::vsnprintf(nullptr, 0, pattern, arguments);
  va_end(arguments);
  if (size < 0)
    fail(Key::LocalizationFormattingFailed);
  std::string result(static_cast<std::size_t>(size), '\0');
  va_start(arguments, pattern);
  std::vsnprintf(result.data(), result.size() + 1, pattern, arguments);
  va_end(arguments);
  return result;
}

const char *text_key(std::string_view name) {
  const auto index = find_key(name);
  if (!index)
    throw std::out_of_range(
        diagnostic(Key::LocalizationUnknownKey, std::string{name}.c_str()));
  return text(static_cast<Key>(*index));
}
} // namespace l10n
