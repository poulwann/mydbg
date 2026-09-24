typedef unsigned char arm_u8;
typedef unsigned int arm_u32;

_Static_assert(sizeof(arm_u32) == 4, "the ARM crackme requires 32-bit words");

#define CRACKME_KEEP                                                           \
  __attribute__((noinline, used, visibility("default")))
#define CRACKME_SECRET 0x43544621U
#define CRACKME_XOR 0xa5c31f27U
#define CRACKME_ADD 0x10293847U
#define CRACKME_ROTL5(value) (((value) << 5U) | ((value) >> 27U))
#define CRACKME_MIXED(value) (CRACKME_ROTL5((value) ^ CRACKME_XOR) + CRACKME_ADD)

volatile arm_u32 crackme_state = 0x13579bdfU;
volatile arm_u32 crackme_result;
volatile arm_u8 crackme_workspace[64];
const char crackme_architecture[] = "armv7-linux-gnueabi";

CRACKME_KEEP arm_u32 crackme_checkpoint(volatile arm_u32 *state,
                                        arm_u32 mixed, arm_u32 candidate) {
  volatile arm_u32 stack_words[8];
  stack_words[0] = mixed;
  stack_words[1] = candidate;
  stack_words[2] = stack_words[0] ^ stack_words[1];
  stack_words[3] = stack_words[2] + 0x31415926U;
  stack_words[4] = stack_words[3] ^ 0x27182818U;
  stack_words[5] = stack_words[4] + stack_words[1];
  stack_words[6] = stack_words[5] ^ stack_words[0];
  stack_words[7] = stack_words[6] + 1U;

  *state = stack_words[7];
  crackme_workspace[(candidate >> 24U) & 0x3fU] =
      (arm_u8)(stack_words[4] & 0xffU);
  __asm__ volatile("" : : "r"(stack_words[7]) : "memory");
  return stack_words[0];
}

CRACKME_KEEP arm_u32 crackme_mix(arm_u32 candidate) {
  volatile arm_u32 stack_words[4];
  stack_words[0] = candidate ^ CRACKME_XOR;
  stack_words[1] = CRACKME_ROTL5(stack_words[0]);
  stack_words[2] = stack_words[1] + CRACKME_ADD;
  stack_words[3] = stack_words[2] ^ candidate;
  crackme_workspace[1] = (arm_u8)(stack_words[3] & 0xffU);
  return crackme_checkpoint(&crackme_state, stack_words[2], candidate);
}

CRACKME_KEEP arm_u32 crackme_verify(arm_u32 candidate) {
  volatile arm_u32 stack_words[3];
  stack_words[0] = candidate;
  stack_words[1] = crackme_mix(stack_words[0]);
  stack_words[2] = CRACKME_MIXED(CRACKME_SECRET);
  crackme_result = stack_words[1];
  return stack_words[0] == CRACKME_SECRET && stack_words[1] == stack_words[2];
}

CRACKME_KEEP int crackme_success(arm_u32 seed) {
  volatile arm_u32 stack_words[2];
  stack_words[0] = seed;
  stack_words[1] = crackme_result;
  crackme_state ^= stack_words[0] + stack_words[1];
  crackme_workspace[2] = (arm_u8)(crackme_state & 0xffU);
  return 0;
}

CRACKME_KEEP int crackme_failure(arm_u32 seed) {
  volatile arm_u32 stack_words[2];
  stack_words[0] = seed;
  stack_words[1] = seed ^ CRACKME_SECRET;
  crackme_state = stack_words[1];
  crackme_result = 0U;
  crackme_workspace[3] = (arm_u8)(stack_words[1] & 0xffU);
  return 17;
}

CRACKME_KEEP int crackme_entry(arm_u32 seed) {
  volatile arm_u32 stack_words[4];
  stack_words[0] = seed;
  stack_words[1] = seed ^ 0xffffffffU;
  stack_words[2] = stack_words[0] + 0x01020304U;
  stack_words[3] = stack_words[1] ^ stack_words[2];
  crackme_workspace[0] = (arm_u8)(stack_words[3] & 0xffU);
  if (crackme_verify(stack_words[0]) != 0U) {
    return crackme_success(stack_words[0]);
  }
  return crackme_failure(stack_words[0]);
}

static CRACKME_KEEP int crackme_entry_from_stack(const arm_u32 *initial_stack) {
  const arm_u32 argc = initial_stack[0];
  if (argc != 2U) {
    return crackme_failure(0U);
  }

  const char *argument = (const char *)(unsigned long)initial_stack[2];
  if (argument[0] != 'C' || argument[1] != 'T' || argument[2] != 'F' ||
      argument[3] != '!' || argument[4] != '\0') {
    return crackme_failure(0U);
  }

  const arm_u32 seed = ((arm_u32)(arm_u8)argument[0] << 24U) |
                       ((arm_u32)(arm_u8)argument[1] << 16U) |
                       ((arm_u32)(arm_u8)argument[2] << 8U) |
                       (arm_u32)(arm_u8)argument[3];
  return crackme_entry(seed);
}

__attribute__((naked, noreturn, used, visibility("default"))) void _start(void) {
  __asm__ volatile("mov r0, sp\n"
                   "bl crackme_entry_from_stack\n"
                   "mov r7, #1\n"
                   "svc #0\n"
                   "udf #0\n");
}
