// Deliberately overflowable target for ROP-loop testing.
//
// Reads 512 bytes from the file named by argv[1] into a 48-byte aligned
// buffer and returns into whatever the caller planted. The input rides on a
// file instead of stdin because mydbg launches with a pty whose canonical
// line discipline corrupts binary payloads (EOF, erase, and signal bytes are
// processed, not delivered). Built with -no-pie and no stack protector so the
// chain's gadget addresses are load-constant; rop_win validates a token
// argument so a landing must actually control rdi, not just PC.

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((noinline)) void rop_gadget(void) {
  __asm__ volatile("pop %rdi\n\tret");
}

static void report(const char *text) {
  // write() instead of printf: _exit() never flushes stdio buffers, and the
  // ROP test needs to observe this output after the process tears down.
  ssize_t ignored = write(1, text, strlen(text));
  (void)ignored;
}

__attribute__((noinline)) void rop_win(unsigned long token) {
  if (token == 0xC0DEC0DEUL) {
    report("rop_win_ok\n");
  } else {
    report("rop_win_bad\n");
  }
  _exit(0);
}

__attribute__((noinline)) int rop_main(const char *path) {
  char buffer[32];
  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    report("rop_open_error\n");
    return 1;
  }
  ssize_t received = read(fd, buffer, sizeof(buffer) * 16);
  close(fd);
  if (received < 0) {
    report("rop_read_error\n");
    return 1;
  }
  report("rop_read_done\n");
  return 0;
}

int main(int argc, char **argv) {
  return rop_main(argc > 1 ? argv[1] : "/dev/null");
}
