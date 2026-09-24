#include <cstdio>

namespace {

int calculate(int value) {
  volatile int doubled = value * 2;
  return doubled + 1;
}

} // namespace

int main() {
  const int result = calculate(20);
  std::printf("debuggee result=%d\n", result);
  return result == 41 ? 0 : 1;
}
