#include <cstdint>

namespace {
volatile std::uint32_t branch_value = 7;
volatile std::uint32_t branch_sink{};
} // namespace

extern "C" __attribute__((noinline)) void intelligence_checkpoint() {
  if (branch_value == 7) {
    branch_sink = branch_value + 1;
  } else {
    branch_sink = branch_value - 1;
  }

#if defined(__x86_64__)
  asm volatile("movabs $0x6161616261616161, %%r12\n\t"
               "xor %%rax, %%rax\n\t"
               "movl $1, (%%rax)"
               :
               :
               : "rax", "r12", "memory");
#else
  *static_cast<volatile std::uint32_t *>(nullptr) = 1;
#endif
}

extern "C" __attribute__((noinline)) void call_site_checkpoint() {
  intelligence_checkpoint();
}

int main() {
  call_site_checkpoint();
  return static_cast<int>(branch_sink);
}
