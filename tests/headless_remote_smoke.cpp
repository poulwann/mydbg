#include "RemoteProcessHarness.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <string>
#include <vector>

#include <sys/wait.h>

using namespace std::chrono_literals;

namespace {

void set_environment(const char *name, const std::string &value) {
  if (::setenv(name, value.c_str(), 1) != 0) {
    throw std::runtime_error(std::string{"unable to set "} + name);
  }
}

void run_smoke(const char *mydbg, const char *script, const char *architecture,
               const char *debuggee, const char *qemu) {
  debugger::test::QemuUserStub stub{qemu, debuggee, "CTF!"};
  set_environment("MYDBG_CROSS_MODE", "connected");
  set_environment("MYDBG_CROSS_ARCH", architecture);
  set_environment("MYDBG_CROSS_EXECUTABLE", debuggee);
  set_environment("MYDBG_CROSS_ENDPOINT", stub.endpoint());
  set_environment("MYDBG_CROSS_SEED", "CTF!");
  set_environment("MYDBG_CROSS_CASE", "success");
  set_environment("MYDBG_CROSS_EXPECTED_EXIT", "0");

  debugger::test::ChildProcess debugger = debugger::test::ChildProcess::spawn(
      {mydbg, "--headless-script", script});
  int status = 0;
  if (!debugger.wait_for_exit(120s, status)) {
    throw std::runtime_error("mydbg did not complete the remote smoke test");
  }
  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    throw std::runtime_error("mydbg remote smoke test exited with status " +
                             std::to_string(status));
  }
}

} // namespace

int main(int argc, char **argv) {
  if (argc != 6) {
    std::fprintf(stderr, "usage: %s MYDBG SCRIPT ARCH DEBUGGEE QEMU\n", argv[0]);
    return 2;
  }
  try {
    run_smoke(argv[1], argv[2], argv[3], argv[4], argv[5]);
  } catch (const std::exception &error) {
    std::fprintf(stderr, "actual mydbg smoke failure (%s): %s\n", argv[3],
                 error.what());
    return 1;
  }
  return 0;
}
