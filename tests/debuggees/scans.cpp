#include <atomic>
#include <cstdint>
#include <cstdio>

namespace {

[[maybe_unused]] constexpr char binary_string_marker[] =
    "MYDBG_BINARY_STRING_SCAN_MARKER";

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
void scan_checkpoint() {
  std::atomic_signal_fence(std::memory_order_seq_cst);
}

volatile std::uint32_t scan_value = 0x13572468U;

} // namespace

int main() {
  scan_checkpoint();
  scan_value = 0x11223344U;
  scan_checkpoint();
  scan_value = 0x10203040U;
  scan_checkpoint();
  scan_checkpoint();
  scan_value = 0x708090a0U;
  scan_checkpoint();
  std::printf("%s value=%u\n", binary_string_marker,
              static_cast<unsigned int>(scan_value));
  return 0;
}
