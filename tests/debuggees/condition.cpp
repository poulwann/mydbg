#include <array>
#include <cstdint>
#include <cstdio>

namespace {

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
int condition_target(std::uint64_t marker, const std::uint8_t *bytes,
                     const char *text) {
  volatile std::uint64_t observed = marker +
                                    static_cast<std::uint64_t>(bytes[0]) +
                                    static_cast<std::uint64_t>(text[0]);
  return static_cast<int>(observed);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
int condition_secondary(std::uint64_t left, std::uint64_t right) {
  volatile std::uint64_t observed = left + right;
  return static_cast<int>(observed);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
int condition_truthy(std::uint64_t value) {
  volatile std::uint64_t observed = value;
  return static_cast<int>(observed);
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
int condition_error_target(std::uint64_t value) {
  volatile std::uint64_t observed = value;
  return static_cast<int>(observed);
}

} // namespace

int main() {
  constexpr std::array<std::uint8_t, 4> mismatch{0xDE, 0xAD, 0x11, 0x00};
  constexpr std::array<std::uint8_t, 4> match{0xDE, 0xAD, 0x42, 0xEF};
  volatile int result = 0;
  result += condition_target(0, mismatch.data(), "skip zero");
  result += condition_target(1, match.data(), "skip one");
  result += condition_target(2, match.data(), "skip two");
  result += condition_target(3, match.data(), "I am a string");
  result += condition_secondary(0x2A, 42);
  result += condition_truthy(1);
  result += condition_error_target(7);
  std::printf("condition result=%d\n", result);
  return 0;
}
