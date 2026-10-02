// Native x86-64 fixture: none of these chains executes in the live process.
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

#if !defined(__x86_64__)
#error "rop_trace is an x86-64 fixture"
#endif

#define GADGET(name, body)                                                     \
  __attribute__((naked, noinline, used)) void name(void) {                     \
    __asm__ volatile(body);                                                    \
  }

GADGET(rop_trace_pop_rax, "pop %rax\n\tret")
GADGET(rop_trace_pop_rdi, "pop %rdi\n\tret")
GADGET(rop_trace_add7, "add $7, %rax\n\tret")
GADGET(rop_trace_store, "mov %rax, (%rdi)\n\tret")
GADGET(rop_trace_load, "mov (%rdi), %rax\n\tret")
GADGET(rop_trace_pivot, "pop %rsp\n\tret")
GADGET(rop_trace_syscall, "syscall\n\tret")
GADGET(rop_trace_loop, "jmp rop_trace_loop")
GADGET(rop_trace_control,
       "xor %eax, %eax\n\tcmp $0, %eax\n\tjne rop_trace_loop\n\t"
       "call rop_trace_add7\n\tjmp rop_trace_syscall")
GADGET(rop_trace_tls, "mov %fs:0, %rax\n\tret")
GADGET(rop_trace_undefined,
       "xor %eax, %eax\n\tmul %rax\n\tjz rop_trace_loop\n\tret")
GADGET(rop_trace_rep, "rep movsb\n\tret")
GADGET(rop_trace_rep_setup, "pop %rsi\n\tpop %rdi\n\tpop %rcx\n\tcld\n\tret")
GADGET(rop_trace_pop_flags, "popfq\n\tret")

uintptr_t rop_trace_value = 0x8877665544332211ULL;
uintptr_t rop_trace_chain[19];
uintptr_t rop_trace_pivot_stack[2];
uintptr_t rop_trace_invalid_target[1];
uintptr_t rop_trace_invalid_read[3];
uintptr_t rop_trace_invalid_write[5];
uintptr_t rop_trace_nx[1];
uintptr_t rop_trace_loop_stack[1];
uintptr_t rop_trace_control_stack[1];
uintptr_t rop_trace_tls_stack[1];
uintptr_t rop_trace_undefined_stack[1];
uintptr_t rop_trace_partial_stack[3];
uintptr_t rop_trace_rep_stack[6];
uintptr_t rop_trace_flags_stack[3];
unsigned char rop_trace_rep_source[8] = {0x81, 2, 3, 4, 5, 6, 7, 0xfe};
unsigned char rop_trace_rep_destination[8] = {0};
void *rop_trace_guarded;

__attribute__((noinline)) void rop_trace_ready(void) {
  __asm__ volatile("nop" ::: "memory");
}

int main(void) {
  const uintptr_t pop_rax = (uintptr_t)rop_trace_pop_rax;
  const uintptr_t pop_rdi = (uintptr_t)rop_trace_pop_rdi;
  const uintptr_t add7 = (uintptr_t)rop_trace_add7;
  const uintptr_t store = (uintptr_t)rop_trace_store;
  const uintptr_t load = (uintptr_t)rop_trace_load;
  const uintptr_t pivot = (uintptr_t)rop_trace_pivot;
  rop_trace_chain[0] = pop_rax;
  rop_trace_chain[1] = 5; // Pop data, not a return target.
  rop_trace_chain[2] = add7;
  rop_trace_chain[3] = pop_rdi;
  rop_trace_chain[4] = (uintptr_t)&rop_trace_value;
  rop_trace_chain[5] = store; // Store 12 into simulated memory.
  rop_trace_chain[6] = pop_rax;
  rop_trace_chain[7] = 0;
  rop_trace_chain[8] = load; // Must see simulated 12, not live bytes.
  rop_trace_chain[9] = add7; // Repeated occurrence, rax becomes 19.
  rop_trace_chain[10] = pop_rdi;
  rop_trace_chain[11] = (uintptr_t)&rop_trace_chain[17];
  rop_trace_chain[12] = pop_rax;
  rop_trace_chain[13] = pivot; // A gadget address consumed as DATA.
  rop_trace_chain[14] = store; // Rewrite a future return target.
  rop_trace_chain[15] = pop_rax;
  rop_trace_chain[16] = 19;
  rop_trace_chain[17] = 1; // Invalid live value; simulated write fixes it.
  rop_trace_chain[18] = (uintptr_t)rop_trace_pivot_stack;
  rop_trace_pivot_stack[0] = add7; // Third occurrence, rax becomes 26.
  rop_trace_pivot_stack[1] = (uintptr_t)rop_trace_syscall;

  rop_trace_invalid_target[0] = 1;
  rop_trace_invalid_read[0] = pop_rdi;
  rop_trace_invalid_read[1] = 1;
  rop_trace_invalid_read[2] = load;
  rop_trace_invalid_write[0] = pop_rax;
  rop_trace_invalid_write[1] = 42;
  rop_trace_invalid_write[2] = pop_rdi;
  rop_trace_invalid_write[3] = add7; // Executable, not writable.
  rop_trace_invalid_write[4] = store;
  rop_trace_nx[0] =
      (uintptr_t)&rop_trace_value; // Readable data, not executable.
  rop_trace_loop_stack[0] = (uintptr_t)rop_trace_loop;
  rop_trace_control_stack[0] = (uintptr_t)rop_trace_control;
  rop_trace_tls_stack[0] = (uintptr_t)rop_trace_tls;
  rop_trace_undefined_stack[0] = (uintptr_t)rop_trace_undefined;

  const long page = sysconf(_SC_PAGESIZE);
  if (page <= 0)
    return 2;
  rop_trace_guarded = mmap(0, (size_t)page * 2, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (rop_trace_guarded == MAP_FAILED)
    return 3;
  unsigned char *edge = (unsigned char *)rop_trace_guarded + page - 4;
  edge[0] = 0x11;
  edge[1] = 0x22;
  edge[2] = 0x33;
  edge[3] = 0x44;
  if (mprotect((unsigned char *)rop_trace_guarded + page, (size_t)page,
               PROT_NONE))
    return 4;
  rop_trace_partial_stack[0] = pop_rdi;
  rop_trace_partial_stack[1] = (uintptr_t)edge;
  rop_trace_partial_stack[2] = load;

  rop_trace_rep_stack[0] = (uintptr_t)rop_trace_rep_setup;
  rop_trace_rep_stack[1] = (uintptr_t)rop_trace_rep_source;
  rop_trace_rep_stack[2] = (uintptr_t)rop_trace_rep_destination;
  rop_trace_rep_stack[3] = sizeof(rop_trace_rep_source);
  rop_trace_rep_stack[4] = (uintptr_t)rop_trace_rep;
  rop_trace_rep_stack[5] = (uintptr_t)rop_trace_syscall;
  rop_trace_flags_stack[0] = (uintptr_t)rop_trace_pop_flags;
  rop_trace_flags_stack[1] = 2; // Ring 3 cannot clear IF using POPFQ.
  rop_trace_flags_stack[2] = (uintptr_t)rop_trace_syscall;
  rop_trace_ready();
  munmap(rop_trace_guarded, (size_t)page * 2);
  return 0;
}
