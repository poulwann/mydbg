#pragma once

#include "LocalizationKeys.h"

#include <cstdio>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>

namespace l10n {

// Catalog storage is initialized once and remains immutable across UI/worker
// threads. MYDBG_TRANSLATION selects an optional INI file or directory of
// partial overrides.
const char *text(Key key);
const char *label(Key key);
const char *english(Key key);
const char *text_key(std::string_view name);
std::span<const Key> window_keys();
const char *format_string(Key key);

namespace detail {
std::string format_message(const char *pattern, ...);
}

// Values use printf conventions, including positional arguments in
// translations. Catalog loading verifies the argument signature before a format
// can be used.
template <typename... Args> std::string format(Key key, Args... args) {
  static_assert(((std::is_arithmetic_v<Args> || std::is_pointer_v<Args> ||
                  std::is_null_pointer_v<Args>) &&
                 ...),
                "Pass C strings, not string objects, to printf formats");
  return detail::format_message(format_string(key), args...);
}

} // namespace l10n
