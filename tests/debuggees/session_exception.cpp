#include <cstdio>
#include <unistd.h>

extern "C" __attribute__((noinline)) void session_throw() { throw 42; }

int main(int argc, char **argv) {
  char directory[4096]{};
  if (!getcwd(directory, sizeof(directory)))
    return 2;
  std::printf("session-argument:%s\nsession-directory:%s\n",
              argc > 1 ? argv[1] : "<none>", directory);
  std::fflush(stdout);
  try {
    session_throw();
  } catch (int) {
    return 0;
  }
  return 1;
}
