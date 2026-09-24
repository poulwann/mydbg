#pragma once

#include <cstdio>
#include <stdexcept>
#include <string>
#include <string_view>

namespace debugger::test {

[[noreturn]] inline void fail(std::string_view message) {
  throw std::runtime_error(std::string{message});
}

inline void require(bool condition, std::string_view message) {
  if (!condition) {
    fail(message);
  }
}

class Campaign final {
public:
  explicit Campaign(const char *architecture) : architecture_(architecture) {}

  void expect(bool condition, const std::string &message) {
    if (!condition) {
      ++failures_;
      std::fprintf(stderr, "%s deficiency: %s\n", architecture_, message.c_str());
    }
  }

  [[nodiscard]] int failures() const { return failures_; }

private:
  const char *architecture_;
  int failures_{};
};

} // namespace debugger::test
