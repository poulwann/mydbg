typedef unsigned char u8;
typedef unsigned int u32;

typedef char u32_must_be_four_bytes[(sizeof(u32) == 4) ? 1 : -1];

#define CRACKME_FUNCTION(section_name)                                      \
  __attribute__((noinline, used, visibility("default"), section(section_name)))

__attribute__((used, visibility("default"), section(".data.crackme_state")))
volatile u32 crackme_state[4] = {
    0x11223344U,
    0x55667788U,
    0x99aabbccU,
    0xddeeff00U,
};

CRACKME_FUNCTION(".text.crackme_checkpoint")
u32 crackme_checkpoint(u32 value) {
  volatile u32 frame[6];
  frame[0] = value;
  frame[1] = value ^ 0x11223344U;
  frame[2] = value + 0x01020304U;
  frame[3] = frame[1] ^ frame[2];
  frame[4] = 0x43544621U;
  frame[5] = frame[3] + frame[4];
  __asm__ volatile("" : : "r"(&frame[0]) : "memory");
  crackme_state[1] = frame[1];
  crackme_state[2] = frame[2];
  crackme_state[3] = frame[5];
  return frame[0];
}

CRACKME_FUNCTION(".text.crackme_mix")
u32 crackme_mix(u32 seed) {
  volatile u32 frame[4];
  frame[0] = seed ^ 0xa5a55a5aU;
  frame[1] = (frame[0] << 7U) | (frame[0] >> 25U);
  frame[2] = frame[1] + 0x13579bdfU;
  frame[3] = frame[2] ^ seed;
  __asm__ volatile("" : : "r"(&frame[0]) : "memory");
  return crackme_checkpoint(frame[2]);
}

CRACKME_FUNCTION(".text.crackme_verify")
u32 crackme_verify(const char *input) {
  volatile u32 frame[3];
  if (input == (const char *)0 || input[0] == '\0' || input[1] == '\0' ||
      input[2] == '\0' || input[3] == '\0' || input[4] != '\0') {
    return 0U;
  }

  frame[0] = ((u32)(u8)input[0] << 24U) | ((u32)(u8)input[1] << 16U) |
             ((u32)(u8)input[2] << 8U) | (u32)(u8)input[3];
  frame[1] = 0x43544621U;
  crackme_state[0] = frame[0];
  frame[2] = crackme_mix(frame[0]);
  __asm__ volatile("" : : "r"(&frame[0]) : "memory");
  return (frame[0] == frame[1] && frame[2] == 0x8be5d9d2U) ? 1U : 0U;
}

CRACKME_FUNCTION(".text.crackme_success")
u32 crackme_success(u32 mixed) {
  volatile u32 frame[3];
  frame[0] = mixed;
  frame[1] = crackme_state[3];
  frame[2] = frame[0] ^ frame[1];
  crackme_state[3] = frame[2];
  __asm__ volatile("" : : "r"(&frame[0]) : "memory");
  return 0U;
}

CRACKME_FUNCTION(".text.crackme_failure")
u32 crackme_failure(u32 observed) {
  volatile u32 frame[3];
  frame[0] = observed;
  frame[1] = 0xbad00badU;
  frame[2] = frame[0] ^ frame[1];
  crackme_state[3] = frame[2];
  __asm__ volatile("" : : "r"(&frame[0]) : "memory");
  return 17U;
}

CRACKME_FUNCTION(".text.crackme_entry")
u32 crackme_entry(const char *input) {
  volatile u32 frame[4];
  frame[0] = 0x43544621U;
  frame[1] = crackme_verify(input);
  frame[2] = crackme_state[0];
  frame[3] = frame[0] ^ frame[2];
  __asm__ volatile("" : : "r"(&frame[0]) : "memory");
  if (frame[1] != 0U) {
    return crackme_success(crackme_state[2]);
  }
  return crackme_failure(frame[2]);
}

__asm__(".section .text.startup,\"ax\",@progbits\n"
        ".balign 4\n"
        ".globl _start\n"
        ".type _start,@function\n"
        "_start:\n"
        "  lwz 3,0(1)\n"
        "  cmpwi 3,2\n"
        "  blt 1f\n"
        "  lwz 3,8(1)\n"
        "  bl crackme_entry\n"
        "  b 2f\n"
        "1:\n"
        "  li 3,17\n"
        "2:\n"
        "  li 0,1\n"
        "  sc\n"
        "  b .\n"
        ".size _start,.-_start\n"
        ".section .note.GNU-stack,\"\",@progbits\n");
