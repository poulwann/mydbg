// Symbolic-stdin flag checker: the solver must recover the exact 24 input
// bytes that survive the CBC-style byte chain.
//
// Reads from argv[1] when given (binary payloads cannot ride mydbg's pty
// stdin), otherwise from stdin, matching the semantics angr models with a
// symbolic stdin file. Success and failure call distinct noinline functions so
// exploration gets clean find/avoid addresses straight from the symbol table.

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INPUT_SIZE 24
static const unsigned char expected[INPUT_SIZE] = {
    0xb9, 0x06, 0x13, 0x8b, 0x67, 0xc1, 0x95, 0x67, 0x50, 0x91, 0x0d, 0x0b,
    0x13, 0x83, 0xe6, 0xac, 0xc6, 0x15, 0xe3, 0x6c, 0x99, 0x77, 0xf0, 0xf4,
};

static void report(const char *text) {
  ssize_t ignored = write(1, text, strlen(text));
  (void)ignored;
}

static unsigned char rotate_left(unsigned char value, unsigned count) {
  return (unsigned char)(((value << count) | (value >> (8U - count))) & 0xffU);
}

__attribute__((noinline)) void stdin_success(void) {
  report("stdin_flag_ok\n");
}

__attribute__((noinline)) void stdin_fail(const char *reason) {
  report("stdin_nope_");
  report(reason);
  report("\n");
}

static int check(const unsigned char *input, ssize_t size) {
  if (size != INPUT_SIZE) {
    stdin_fail("size");
    return 0;
  }
  unsigned char previous = 0x5a;
  for (int i = 0; i < INPUT_SIZE; ++i) {
    previous = rotate_left((unsigned char)(previous ^ input[i]), 3);
    if (previous != expected[i]) {
      stdin_fail("chain");
      return 0;
    }
  }
  stdin_success();
  return 1;
}

int main(int argc, char **argv) {
  unsigned char buffer[64];
  ssize_t received;
  if (argc > 1) {
    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
      report("stdin_open_error\n");
      return 1;
    }
    received = read(fd, buffer, sizeof(buffer));
    close(fd);
  } else {
    received = read(0, buffer, sizeof(buffer));
  }
  if (received < 0) {
    report("stdin_read_error\n");
    return 1;
  }
  return check(buffer, received) ? 0 : 17;
}
