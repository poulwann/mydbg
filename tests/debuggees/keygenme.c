// Keygenme for the call-state symbolic pattern: the solver must synthesize a
// 16-byte serial whose two lanes hit the hardcoded constants. Lane 1 is
// arithmetic with range branches; lane 2 mixes XOR/rotate. The serial is
// printable ASCII with no spaces, so argv can carry it verbatim.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SERIAL_SIZE 16

static void report(const char *text) {
  ssize_t ignored = write(1, text, strlen(text));
  (void)ignored;
}

static int lane_arithmetic(const char *part) {
  int value = 7;
  for (int i = 0; i < 8; ++i) {
    char c = part[i];
    if (c >= 'a' && c <= 'z') {
      value = value * 5 + (c - 'a' + 1);
    } else if (c >= '0' && c <= '9') {
      value ^= c;
    } else {
      return -1;
    }
    value &= 0xffffff;
  }
  return value;
}

static unsigned int lane_rotate(const char *part) {
  unsigned int value = 0x3c3c3c3cU;
  for (int i = 0; i < 8; ++i) {
    unsigned char c = (unsigned char)part[i];
    value ^= c;
    value = (value << 3U) | (value >> 29U);
    value += 0x01010101U;
  }
  return value;
}

__attribute__((noinline)) int keygen_valid(const char *serial) {
  if (serial == NULL) {
    return 0;
  }
  for (int i = 0; i < SERIAL_SIZE; ++i) {
    if (serial[i] == '\0') {
      return 0;
    }
  }
  if (serial[SERIAL_SIZE] != '\0') {
    return 0;
  }
  if (lane_arithmetic(serial) != 0x2b95fb) {
    return 0;
  }
  if (lane_rotate(serial + 8) != 0xa2d9e04U) {
    return 0;
  }
  return 1;
}

int main(int argc, char **argv) {
  if (keygen_valid(argc > 1 ? argv[1] : NULL)) {
    report("keygen_ok\n");
    return 0;
  }
  report("keygen_bad\n");
  return 17;
}
