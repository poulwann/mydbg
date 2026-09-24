#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if defined(__clang__) || defined(__GNUC__)
#define CRACKME_FUNCTION __attribute__((noinline, used))
#else
#define CRACKME_FUNCTION
#endif

#define CRACKME_SECRET UINT32_C(0x43544621)
#define CRACKME_XOR UINT32_C(0xa5c31f27)
#define CRACKME_MULTIPLIER UINT32_C(0x45d9f3b)
#define CRACKME_ADDEND UINT32_C(0x19e3779b)
#define CRACKME_TRANSFORM(value)                                                \
  ((uint32_t)((((uint32_t)(value) ^ CRACKME_XOR) * CRACKME_MULTIPLIER) +       \
              CRACKME_ADDEND))
#define CRACKME_EXPECTED CRACKME_TRANSFORM(CRACKME_SECRET)

volatile uint64_t crackme_writable_state = UINT64_C(0x1122334455667788);
volatile uint32_t crackme_last_seed = 0;
volatile uint32_t crackme_checkpoint_value = 0;

CRACKME_FUNCTION uint32_t crackme_checkpoint(uint32_t value) {
  volatile uint32_t stack_words[8];
  stack_words[0] = value;
  stack_words[1] = value ^ UINT32_C(0x6d5a56a9);
  stack_words[2] = value + UINT32_C(0x10203040);
  stack_words[3] = value - UINT32_C(0x01020304);
  stack_words[4] = stack_words[1] ^ stack_words[2];
  stack_words[5] = stack_words[3] + stack_words[4];
  stack_words[6] = stack_words[5] ^ UINT32_C(0xc001d00d);
  stack_words[7] = stack_words[6] + stack_words[0];

  crackme_checkpoint_value = stack_words[0];
  crackme_writable_state ^=
      ((uint64_t)stack_words[7] << 32U) | (uint64_t)stack_words[4];
  return stack_words[0];
}

CRACKME_FUNCTION uint32_t crackme_mix(uint32_t seed) {
  volatile uint32_t stack_lanes[6];
  stack_lanes[0] = seed;
  stack_lanes[1] = stack_lanes[0] ^ CRACKME_XOR;
  stack_lanes[2] = stack_lanes[1] * CRACKME_MULTIPLIER;
  stack_lanes[3] = stack_lanes[2] + CRACKME_ADDEND;

  const uint32_t checkpointed = crackme_checkpoint(stack_lanes[3]);
  stack_lanes[4] = checkpointed ^ stack_lanes[0];
  stack_lanes[5] = stack_lanes[4] + UINT32_C(0x31415926);
  crackme_writable_state += (uint64_t)stack_lanes[5];
  return checkpointed;
}

CRACKME_FUNCTION int crackme_verify(uint32_t seed) {
  volatile uint32_t verify_stack[4];
  verify_stack[0] = seed;
  verify_stack[1] = crackme_mix(verify_stack[0]);
  verify_stack[2] = CRACKME_EXPECTED;
  verify_stack[3] = verify_stack[1] ^ verify_stack[2];
  return verify_stack[3] == 0U;
}

CRACKME_FUNCTION int crackme_success(void) {
  printf("crackme_success seed=0x%08" PRIx32 " state=0x%016" PRIx64 "\n",
         crackme_last_seed, crackme_writable_state);
  return 0;
}

CRACKME_FUNCTION int crackme_failure(void) {
  printf("crackme_failure seed=0x%08" PRIx32 " state=0x%016" PRIx64 "\n",
         crackme_last_seed, crackme_writable_state);
  return 17;
}

CRACKME_FUNCTION int crackme_entry(uint32_t seed) {
  volatile uint64_t entry_stack[4];
  entry_stack[0] = UINT64_C(0xfeedfacecafebeef);
  entry_stack[1] = (uint64_t)seed;
  entry_stack[2] = entry_stack[0] ^ entry_stack[1];
  crackme_last_seed = seed;

  const int verified = crackme_verify(seed);
  entry_stack[3] = entry_stack[2] + (uint64_t)(unsigned int)verified;
  crackme_writable_state ^= entry_stack[3];
  return verified != 0 ? crackme_success() : crackme_failure();
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s CTF!\n", argv[0]);
    return 17;
  }

  const uint32_t seed =
      strcmp(argv[1], "CTF!") == 0 ? CRACKME_SECRET : UINT32_C(0);
  return crackme_entry(seed);
}
