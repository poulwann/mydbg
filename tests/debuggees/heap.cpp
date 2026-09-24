#include <cstdio>
#include <atomic>
#include <cstdlib>

#if defined(__GNUC__) || defined(__clang__)
#define HEAP_NOINLINE __attribute__((noinline))
#else
#define HEAP_NOINLINE
#endif

volatile void* retained_allocation = nullptr;

HEAP_NOINLINE void heap_ready() {
    std::atomic_signal_fence(std::memory_order_seq_cst);
}

int main() {
    void* freed = std::malloc(0x40);
    void* retained = std::malloc(0x100);
    if (freed == nullptr || retained == nullptr) {
        return 2;
    }
    std::free(freed);
    retained_allocation = retained;
    heap_ready();
    std::printf("heap debuggee ready=%p\n",
                const_cast<void*>(retained_allocation));
    std::free(retained);
    return 0;
}
