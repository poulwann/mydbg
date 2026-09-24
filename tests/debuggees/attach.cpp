#include <chrono>
#include <thread>
#include <sys/prctl.h>

int main() {
    ::prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY);
    std::this_thread::sleep_for(std::chrono::seconds(30));
    return 0;
}
