#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <unistd.h>

#include <cstdint>

extern "C" {
volatile std::uint64_t script_marker = 0x1122334455667788ULL;

__attribute__((noinline)) void script_checkpoint() {
  asm volatile("" : : : "memory");
}
}

int main(int argc, char **argv) {
  char working_directory[PATH_MAX]{};
  if (::getcwd(working_directory, sizeof(working_directory)) == nullptr) {
    return 2;
  }
  const char *environment = std::getenv("MYDBG_SCRIPT_TEST");
  std::printf("ready arg=%s env=%s cwd=%s\n", argc > 1 ? argv[1] : "",
              environment == nullptr ? "" : environment, working_directory);
  std::fprintf(stderr, "stderr-ready\n");
  std::fflush(stdout);
  std::fflush(stderr);

  unsigned char input[128]{};
  const ssize_t count = ::read(STDIN_FILENO, input, sizeof(input));
  if (count <= 0) {
    return 3;
  }
  std::size_t payload_size = static_cast<std::size_t>(count);
  while (payload_size > 0 &&
         (input[payload_size - 1] == '\n' || input[payload_size - 1] == '\r')) {
    --payload_size;
  }
  script_checkpoint();
  std::printf("echo=");
  std::fwrite(input, 1, payload_size, stdout);
  std::printf(" marker=0x%llx binary=",
              static_cast<unsigned long long>(script_marker));
  for (std::size_t index = 0; index < payload_size; ++index) {
    std::printf("%02x", static_cast<unsigned int>(input[index]));
  }
  std::printf("\n");
  std::fflush(stdout);
  return 0;
}
