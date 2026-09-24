#include "localization/Localization.h"
#include "TestSupport.h"

#include <cerrno>
#include <clocale>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <sys/wait.h>
#include <unistd.h>

namespace {

using l10n::Key;
namespace fs = std::filesystem;

using debugger::test::require;

class TemporaryDirectory {
public:
  TemporaryDirectory() {
    char pattern[] = "/tmp/mydbg-localization-XXXXXX";
    const char *created = ::mkdtemp(pattern);
    if (!created) {
      throw std::system_error(errno, std::generic_category(), "mkdtemp");
    }
    path = created;
  }

  ~TemporaryDirectory() {
    std::error_code error;
    fs::remove_all(path, error);
    if (error) {
      std::fprintf(stderr, "localization cleanup failed: %s\n",
                   error.message().c_str());
    }
  }

  fs::path path;
};

void write_catalog(const fs::path &path, std::string_view contents) {
  std::ofstream stream;
  stream.exceptions(std::ios::failbit | std::ios::badbit);
  stream.open(path, std::ios::binary);
  stream.write(contents.data(), static_cast<std::streamsize>(contents.size()));
  stream.close();
}

void set_environment(const char *name, const char *value) {
  if (::setenv(name, value, 1) != 0) {
    throw std::system_error(errno, std::generic_category(), name);
  }
}

template <typename Check>
bool run_case(const char *name, const fs::path &catalog, Check check) {
  const pid_t child = ::fork();
  if (child < 0) {
    throw std::system_error(errno, std::generic_category(), "fork");
  }
  if (child == 0) {
    try {
      set_environment("MYDBG_TRANSLATION", catalog.c_str());
      set_environment("LC_ALL", "C");
      set_environment("LANG", "C");
      set_environment("LANGUAGE", "C");
      require(std::setlocale(LC_ALL, "C") != nullptr, "cannot select C locale");
      check();
      ::_exit(0);
    } catch (const std::exception &error) {
      std::fprintf(stderr, "localization case '%s': %s\n", name, error.what());
      ::_exit(1);
    } catch (...) {
      std::fprintf(stderr, "localization case '%s': unexpected exception\n",
                   name);
      ::_exit(1);
    }
  }

  int status = 0;
  while (::waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) {
      throw std::system_error(errno, std::generic_category(), "waitpid");
    }
  }
  if (WIFEXITED(status)) {
    std::fprintf(stderr, "localization case '%s': exit %d\n", name,
                 WEXITSTATUS(status));
    return WEXITSTATUS(status) == 0;
  }
  if (WIFSIGNALED(status)) {
    std::fprintf(stderr, "localization case '%s': signal %d\n", name,
                 WTERMSIG(status));
  } else {
    std::fprintf(stderr, "localization case '%s': wait status %d\n", name,
                 status);
  }
  return false;
}

void require_text(Key key, std::string_view expected) {
  require(l10n::text(key) == expected,
          "unexpected translated text or fallback");
}

void require_label(Key key, std::string_view visible, const char *suffix) {
  require(std::string_view{l10n::label(key)} == std::string{visible} + suffix,
          "label lost its display text or stable identity");
}

} // namespace

int main() {
  try {
    TemporaryDirectory temporary;
    // Metadata must not initialize the catalog inherited by any forked child.
    // Never call text(), label(), or format() in the parent.
    const std::string english_session = l10n::english(Key::WindowSession);
    const std::string english_registers = l10n::english(Key::WindowRegisters);
    const std::string english_line_error =
        l10n::english(Key::LocalizationLineError);
    (void)l10n::window_keys();

    int failures = 0;
    const auto rollback = [&] {
      require_text(Key::WindowSession, english_session);
      require_text(Key::WindowRegisters, english_registers);
      require_text(Key::LocalizationLineError, english_line_error);
      require_label(Key::WindowSession, english_session, "###WindowSession");
    };

    const fs::path partial = temporary.path / "partial.ini";
    write_catalog(partial, "[labels]\nWindowSession = \"调试 S\\u00e9ance\"\n");
    failures += !run_case("partial UTF-8 override", partial, [&] {
      require_text(Key::WindowSession, "调试 Séance");
      require_text(Key::WindowRegisters, english_registers);
      require_label(Key::WindowSession, "调试 Séance", "###WindowSession");
      require_label(Key::WindowRegisters, english_registers,
                    "###WindowRegisters");
      require(std::string_view{l10n::text_key("WindowSession")} ==
                  "调试 Séance",
              "named lookup did not use the translation");
    });

    const fs::path positional = temporary.path / "positional.ini";
    write_catalog(positional,
                  "[formats]\nLocalizationLineError = \"%3$s [%1$s:%2$zu]\"\n");
    failures += !run_case("positional printf reorder", positional, [] {
      require(l10n::format(Key::LocalizationLineError, "source.ini",
                           std::size_t{27},
                           "details") == "details [source.ini:27]",
              "positional printf arguments were not safely reordered");
    });

    // Each rejection follows an accepted entry: retaining even that earlier
    // translation would violate atomic rollback of the entire override.
    const struct {
      const char *name;
      const char *invalid;
    } rejected[] = {
        {"signature mismatch",
         "[formats]\nLocalizationLineError = \"%s:%s:%s\"\n"},
        {"write-through printf conversion",
         "[formats]\nLocalizationLineError = \"%s:%zu:%s%n\"\n"},
        {"unknown catalog key",
         "[labels]\n__UnknownLocalizationKey = \"bad\"\n"},
        {"duplicate key", "[labels]\nWindowSession = \"second value\"\n"},
        {"unpaired unicode surrogate",
         "[labels]\nWindowRegisters = \"\\uD800\"\n"},
        {"invalid UTF-8 bytes", "[labels]\nWindowRegisters = \"\xc0\xaf\"\n"},
        {"injected label identity",
         "[labels]\nWindowRegisters = \"bad###other\"\n"},
    };
    std::size_t index = 0;
    for (const auto &test : rejected) {
      const fs::path path =
          temporary.path / ("rejected-" + std::to_string(index++) + ".ini");
      write_catalog(
          path, std::string{"[labels]\nWindowSession = \"accepted first\"\n"} +
                    test.invalid);
      failures += !run_case(test.name, path, rollback);
    }

    const fs::path merged = temporary.path / "merged";
    fs::create_directory(merged);
    write_catalog(merged / "a.ini", "[labels]\nWindowSession = \"会话\"\n");
    write_catalog(merged / "b.ini",
                  "[labels]\nWindowRegisters = \"Registres\"\n");
    failures += !run_case("directory merging", merged, [&] {
      require_text(Key::WindowSession, "会话");
      require_text(Key::WindowRegisters, "Registres");
      require_text(Key::LocalizationLineError, english_line_error);
      require_label(Key::WindowSession, "会话", "###WindowSession");
      require_label(Key::WindowRegisters, "Registres", "###WindowRegisters");
    });

    // Duplicate definitions in different files must reject the whole directory,
    // not silently let filename order pick a winner or retain unrelated
    // entries.
    write_catalog(merged / "c.ini",
                  "[labels]\nWindowSession = \"replacement\"\n");
    failures += !run_case("cross-file duplicate rollback", merged, rollback);

    failures += !run_case("unknown named lookup", partial, [] {
      bool threw = false;
      try {
        (void)l10n::text_key("__UnknownLocalizationKey");
      } catch (const std::out_of_range &) {
        threw = true;
      }
      require(threw, "unknown named lookup did not throw out_of_range");
      require_text(Key::WindowSession, "调试 Séance");
    });
    return failures == 0 ? 0 : 1;
  } catch (const std::exception &error) {
    std::fprintf(stderr, "localization test setup failed: %s\n", error.what());
    return 1;
  }
}
