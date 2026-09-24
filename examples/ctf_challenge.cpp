#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <string_view>

#include <unistd.h>

#if defined(__clang__) || defined(__GNUC__)
#define CTF_NOINLINE __attribute__((noinline))
#else
#define CTF_NOINLINE
#endif

namespace {

constexpr std::size_t token_size = 32;

constexpr std::array<std::uint8_t, token_size> sealed_vault{
    0x17, 0xE3, 0x5A, 0x91, 0xC8, 0x2D, 0x74, 0x0B, 0xBE, 0x63, 0xD0,
    0x49, 0xA7, 0x3C, 0xF1, 0x86, 0x52, 0xCD, 0x28, 0x9F, 0x64, 0xB9,
    0x06, 0xDB, 0x31, 0x8A, 0xEF, 0x45, 0x9C, 0x13, 0x76, 0xA0,
};

constexpr std::array<std::uint8_t, token_size> permutation{
    11, 2,  29, 7,  19, 23, 5,  17, 31, 13, 3,  27, 0, 21, 9,  25,
    14, 30, 6,  18, 10, 1,  22, 12, 26, 4,  16, 28, 8, 20, 24, 15,
};

constexpr std::uint64_t rotate_left(std::uint64_t value, unsigned shift) {
  shift &= 63U;
  return (value << shift) | (value >> ((64U - shift) & 63U));
}

CTF_NOINLINE std::uint64_t fnv1a(std::string_view text) {
  std::uint64_t value = 1469598103934665603ULL;
  for (const char raw_character : text) {
    const auto character = static_cast<unsigned char>(raw_character);
    value ^= character;
    value *= 1099511628211ULL;
  }
  return value;
}

CTF_NOINLINE std::uint32_t tracer_pid() {
  std::ifstream status{"/proc/self/status"};
  std::string line;
  while (std::getline(status, line)) {
    if (!line.starts_with("TracerPid:")) {
      continue;
    }
    std::uint32_t result = 0;
    for (const char character : line.substr(10)) {
      if (character >= '0' && character <= '9') {
        result = result * 10U + static_cast<std::uint32_t>(character - '0');
      }
    }
    return result;
  }
  return 0;
}

CTF_NOINLINE std::uint64_t collect_runtime_seed(std::string_view program) {
  const auto ticks =
      std::chrono::steady_clock::now().time_since_epoch().count();
  std::uint64_t seed = fnv1a(program);
  seed ^= static_cast<std::uint64_t>(::getpid()) * 0x9E3779B185EBCA87ULL;
  seed ^= static_cast<std::uint64_t>(tracer_pid()) << 32U;
  seed ^= static_cast<std::uint64_t>(ticks);
  seed = rotate_left(seed ^ 0xD1B54A32D192ED03ULL, 23U);
  return seed == 0 ? 0xA5A5A5A5C3C3C3C3ULL : seed;
}

CTF_NOINLINE std::uint64_t next_stream_word(std::uint64_t &state) {
  state ^= state >> 12U;
  state ^= state << 25U;
  state ^= state >> 27U;
  return state * 0x2545F4914F6CDD1DULL;
}

CTF_NOINLINE std::array<std::uint8_t, token_size>
materialize_target(std::uint64_t seed) {
  std::array<std::uint8_t, token_size> stage{};
  std::uint64_t stream = seed;
  for (std::size_t index = 0; index < token_size; ++index) {
    if ((index & 7U) == 0) {
      next_stream_word(stream);
    }
    const unsigned shift = static_cast<unsigned>((index & 7U) * 8U);
    const auto key = static_cast<std::uint8_t>(stream >> shift);
    stage[index] = static_cast<std::uint8_t>(
        sealed_vault[index] ^ key ^ static_cast<std::uint8_t>(index * 0x3DU));
  }

  std::array<std::uint8_t, token_size> target{};
  for (std::size_t index = 0; index < token_size; ++index) {
    const std::uint8_t left = stage[permutation[index]];
    const std::uint8_t right = stage[(permutation[index] + 13U) % token_size];
    const unsigned rotation = static_cast<unsigned>((index % 7U) + 1U);
    target[index] = static_cast<std::uint8_t>(
        (static_cast<unsigned>(left) << rotation) |
        (static_cast<unsigned>(left) >> (8U - rotation)));
    target[index] ^= static_cast<std::uint8_t>(right + index * 17U);
  }
  return target;
}

int hex_nibble(char character) {
  if (character >= '0' && character <= '9') {
    return character - '0';
  }
  if (character >= 'a' && character <= 'f') {
    return character - 'a' + 10;
  }
  if (character >= 'A' && character <= 'F') {
    return character - 'A' + 10;
  }
  return -1;
}

CTF_NOINLINE bool parse_token(std::string_view text,
                              std::array<std::uint8_t, token_size> &token) {
  if (text.size() != token_size * 2U) {
    return false;
  }
  for (std::size_t index = 0; index < token_size; ++index) {
    const int high = hex_nibble(text[index * 2U]);
    const int low = hex_nibble(text[index * 2U + 1U]);
    if (high < 0 || low < 0) {
      return false;
    }
    token[index] = static_cast<std::uint8_t>((high << 4U) | low);
  }
  return true;
}

} // namespace

extern "C" CTF_NOINLINE bool ctf_gate(const std::uint8_t *candidate,
                                      const std::uint8_t *expected,
                                      std::size_t count) {
  std::uint8_t difference = 0;
  for (std::size_t index = 0; index < count; ++index) {
    difference |= static_cast<std::uint8_t>(candidate[index] ^ expected[index]);
  }
  return difference == 0;
}

int main(int argc, char **argv) {
  const std::string_view program = argc > 0 ? argv[0] : "ctf_challenge";
  const std::uint64_t seed = collect_runtime_seed(program);
  const std::array<std::uint8_t, token_size> expected =
      materialize_target(seed);

  std::puts("NEBULA-7 adaptive vault");
  std::printf("telemetry: pid=%ld tracer=%u seed-tag=%08llx\n",
              static_cast<long>(::getpid()), tracer_pid(),
              static_cast<unsigned long long>((seed >> 17U) & 0xFFFFFFFFULL));
  std::fputs("token> ", stdout);
  std::fflush(stdout);

  std::array<char, token_size * 2U + 8U> input{};
  if (std::fgets(input.data(), static_cast<int>(input.size()), stdin) ==
      nullptr) {
    std::puts("input channel closed");
    return 2;
  }
  input[std::strcspn(input.data(), "\r\n")] = '\0';

  std::array<std::uint8_t, token_size> candidate{};
  if (!parse_token(input.data(), candidate)) {
    std::puts("malformed token");
    return 3;
  }

  if (!ctf_gate(candidate.data(), expected.data(), token_size)) {
    std::puts("Access denied: the vault rekeys on every execution");
    return 1;
  }

  std::puts("Access granted");
  std::puts("flag{scripted_debuggers_turn_runtime_state_into_answers}");
  return 0;
}
