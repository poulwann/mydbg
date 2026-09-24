typedef __UINT32_TYPE__ crackme_u32;
typedef __UINTPTR_TYPE__ crackme_uptr;

#define CRACKME_NOINLINE __attribute__((noinline))
#define CRACKME_USED __attribute__((used, visibility("default")))

#define CRACKME_SECRET ((crackme_u32)0x43544621u)
#define CRACKME_MIXED_SECRET ((crackme_u32)0xb2d1ab5fu)

volatile crackme_u32 crackme_state;
volatile crackme_u32 crackme_visit_count;
volatile crackme_u32 crackme_observations[8];

CRACKME_NOINLINE CRACKME_USED void
crackme_checkpoint(crackme_u32 value) {
  volatile crackme_u32 frame[4];
  const crackme_u32 visit = crackme_visit_count;

  frame[0] = value;
  frame[1] = value ^ (crackme_u32)0x63686563u;
  frame[2] = frame[0] + frame[1];
  frame[3] = frame[2] ^ visit;
  crackme_state = frame[3];
  crackme_observations[visit & 7u] = frame[0];
  crackme_visit_count = visit + 1u;
  __asm__ volatile("" : : "r"(frame[3]) : "memory");
}

CRACKME_NOINLINE CRACKME_USED crackme_u32
crackme_mix(crackme_u32 seed) {
  volatile crackme_u32 lanes[4];

  lanes[0] = seed ^ (crackme_u32)0xa5a5a5a5u;
  lanes[1] = (lanes[0] << 5u) | (lanes[0] >> 27u);
  lanes[2] = lanes[1] + (crackme_u32)0x01020304u;
  lanes[3] = lanes[2] ^ (seed >> 7u);
  crackme_checkpoint(lanes[3]);
  return lanes[3] ^ (crackme_u32)0x6d697073u;
}

CRACKME_NOINLINE CRACKME_USED int
crackme_verify(crackme_u32 seed) {
  volatile crackme_u32 frame[3];

  frame[0] = seed;
  frame[1] = crackme_mix(frame[0]);
  frame[2] = frame[0] ^ frame[1];
  crackme_observations[6] = frame[2];
  return frame[0] == CRACKME_SECRET && frame[1] == CRACKME_MIXED_SECRET;
}

CRACKME_NOINLINE CRACKME_USED int
crackme_success(crackme_u32 seed) {
  volatile crackme_u32 frame[3];

  frame[0] = seed;
  frame[1] = crackme_state;
  frame[2] = frame[0] ^ frame[1];
  crackme_observations[7] = frame[2];
  crackme_state = (crackme_u32)0x53554343u;
  __asm__ volatile("" : : "r"(frame[2]) : "memory");
  return 0;
}

CRACKME_NOINLINE CRACKME_USED int
crackme_failure(crackme_u32 seed) {
  volatile crackme_u32 frame[3];

  frame[0] = seed;
  frame[1] = crackme_state;
  frame[2] = frame[0] + frame[1];
  crackme_observations[7] = frame[2];
  crackme_state = (crackme_u32)0x4641494cu;
  __asm__ volatile("" : : "r"(frame[2]) : "memory");
  return 17;
}

static CRACKME_NOINLINE crackme_u32 crackme_parse(const char *input) {
  volatile crackme_u32 bytes[4];

  if (input == (const char *)0 || input[0] == '\0' || input[1] == '\0' ||
      input[2] == '\0' || input[3] == '\0' || input[4] != '\0') {
    return 0u;
  }
  bytes[0] = (unsigned char)input[0];
  bytes[1] = (unsigned char)input[1];
  bytes[2] = (unsigned char)input[2];
  bytes[3] = (unsigned char)input[3];
  return (bytes[0] << 24u) | (bytes[1] << 16u) | (bytes[2] << 8u) |
         bytes[3];
}

CRACKME_NOINLINE CRACKME_USED int crackme_entry(const char *input) {
  volatile crackme_u32 frame[4];

  frame[0] = crackme_parse(input);
  frame[1] = frame[0] ^ (crackme_u32)0x4d495053u;
  frame[2] = frame[1] + (crackme_u32)0x10203040u;
  frame[3] = frame[2] ^ frame[0];
  crackme_observations[0] = frame[3];
  if (crackme_verify(frame[0])) {
    return crackme_success(frame[0]);
  }
  return crackme_failure(frame[0]);
}

CRACKME_NOINLINE CRACKME_USED int
crackme_bootstrap(const crackme_uptr *initial_stack) {
  const crackme_uptr argc = initial_stack[0];
  const char *input = (const char *)0;

  if (argc > 1u) {
    const crackme_uptr *argv = initial_stack + 1;
    input = (const char *)argv[1];
  }
  return crackme_entry(input);
}

__asm__(".section .text._start,\"ax\",@progbits\n"
        ".globl _start\n"
        ".type _start,@function\n"
        ".set noreorder\n"
        "_start:\n"
        "move $4, $29\n"
        "jal crackme_bootstrap\n"
        "nop\n"
        "move $4, $2\n"
        "li $2, 4001\n"
        "syscall\n"
        "break 0\n"
        ".set reorder\n"
        ".size _start, .-_start\n");
