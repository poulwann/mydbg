#include <bit>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>

#if defined(__clang__) || defined(__GNUC__)
#define CRACKME_NOINLINE __attribute__((noinline))
#else
#define CRACKME_NOINLINE
#endif

namespace {

CRACKME_NOINLINE bool valid_name(std::string_view name) {
    if (name.size() < 3 || name.size() > 32) {
        return false;
    }

    for (const char raw_character : name) {
        const auto character =
            static_cast<unsigned char>(raw_character);
        const bool letter =
            (character >= 'a' && character <= 'z') ||
            (character >= 'A' && character <= 'Z');
        const bool digit = character >= '0' && character <= '9';
        if (!letter && !digit && character != '_' && character != '-') {
            return false;
        }
    }
    return true;
}

CRACKME_NOINLINE std::uint32_t hash_name(std::string_view name) {
    std::uint32_t hash = 2166136261U;
    for (const char raw_character : name) {
        const auto character =
            static_cast<unsigned char>(raw_character);
        hash ^= character;
        hash *= 16777619U;
    }
    return hash;
}

CRACKME_NOINLINE std::uint32_t mix_hash(std::uint32_t value,
                                        std::size_t name_length) {
    value ^= std::rotl(value, 13);
    value *= 0x9E3779B1U;
    value ^= static_cast<std::uint32_t>(name_length) * 0x45D9F3BU;
    value ^= value >> 16U;
    return value;
}

CRACKME_NOINLINE std::uint32_t generate_result(std::string_view name) {
    const std::uint32_t hashed = hash_name(name);
    const std::uint32_t mixed = mix_hash(hashed, name.size());
    return mixed ^ 0xC0DEC0DEU;
}

CRACKME_NOINLINE bool parse_result(std::string_view text,
                                   std::uint32_t& result) {
    if (text.size() != 8) {
        return false;
    }

    const char* const begin = text.data();
    const char* const end = begin + text.size();
    const auto parsed = std::from_chars(begin, end, result, 16);
    return parsed.ec == std::errc{} && parsed.ptr == end;
}

CRACKME_NOINLINE bool check_result(std::string_view name,
                                   std::string_view candidate) {
    if (!valid_name(name)) {
        return false;
    }

    std::uint32_t supplied = 0;
    if (!parse_result(candidate, supplied)) {
        return false;
    }

    const std::uint32_t expected = generate_result(name);
    return (expected ^ supplied) == 0;
}

void print_usage(const char* program) {
    std::fprintf(stderr,
                 "usage:\n"
                 "  %s                 # debugger demo input\n"
                 "  %s --generate NAME\n"
                 "  %s NAME RESULT\n",
                 program, program, program);
}

} // namespace

int main(int argc, char** argv) {
    std::string_view name{"debugger"};
    std::string_view candidate{"00000000"};

    if (argc == 1) {
        std::puts("Debugger demo: name=debugger result=00000000");
    } else if (argc != 3) {
        print_usage(argv[0]);
        return 2;
    } else {
        const std::string_view first{argv[1]};
        const std::string_view second{argv[2]};
        if (first == "--generate") {
            if (!valid_name(second)) {
                std::fprintf(stderr, "invalid name\n");
                return 2;
            }
            std::printf("%08X\n", generate_result(second));
            return 0;
        }
        name = first;
        candidate = second;
    }

    if (check_result(name, candidate)) {
        std::puts("Access granted");
        return 0;
    }

    std::puts("Access denied");
    return 1;
}
