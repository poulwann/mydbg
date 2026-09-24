"""Symbolic find-a-way demo: solve the x86_64 crackme from a stopped PC.

Launch the crackme, stop at ``crackme_entry``, snapshot the live state into
angr, symbolize the seed register, explore to ``crackme_success`` under bounds,
and apply the solved model back into the live session. This is the scripted
version of the GUI's "find a way to here" flow: the GUI generates this text,
the reverser edits and re-runs it.

Run standalone:

    ./build/dev/mydbg --headless-script examples/solve_symbolic.py
"""

from __future__ import annotations

import os
from pathlib import Path

from mydbg import symbolic

SEED_TOKEN = 0x43544621  # "CTF!" as a little-endian dword


def target_path() -> str:
    configured = os.environ.get("MYDBG_SYMBOLIC_TARGET")
    if configured:
        return configured
    repository_build = Path(__file__).resolve().parents[1] / "build" / "crackme_x86_64"
    if repository_build.is_file():
        return str(repository_build)
    raise RuntimeError(
        "debuggee_crackme_x86_64 was not found; build it or set MYDBG_SYMBOLIC_TARGET"
    )


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    executable = target_path()

    process = dbg.launch([executable, "wrong"], stop_at="main")
    gate = dbg.set_breakpoint("crackme_entry")
    print(f"[+] launched {executable}, breakpoint {gate} on crackme_entry")

    dbg.continue_execution()
    stop = dbg.wait_for_stop(timeout=5)
    if stop.state != "stopped":
        raise RuntimeError(f"crackme_entry was not reached: {stop.state}")
    snapshot = dbg.snapshot()
    if snapshot.pc == 0:
        raise RuntimeError("no PC in the stopped snapshot")
    print(f"[+] stopped at 0x{snapshot.pc:x} ({snapshot.architecture}, "
          f"{snapshot.byte_order}-endian)")

    target = symbolic.resolve_symbol(dbg, "crackme_success")
    print(f"[+] crackme_success resolves to 0x{target:x}")

    # The crackme stores its seed argument into a stack slot before the
    # breakpoint address, so the seed has to be symbolized in memory. Reading
    # the disassembly to find that slot is exactly the manual setup step this
    # module exists to support.
    frame_base = dbg.read_register("rbp")
    seed_slot = frame_base - 0x44  # entry's `mov %edi,-0x44(%rbp)`
    solution = symbolic.find_way(
        dbg,
        target,
        symbolize=[f"{seed_slot:x}:4"],  # symbolic 4-byte seed
        timeout=120,
    )
    print(solution.summary())
    if solution.status != "found":
        raise RuntimeError(f"exploration failed: {solution.status}")

    model = solution.models[f"mem_{seed_slot:x}"]
    seed = int.from_bytes(model, "little")
    print(f"[+] symbolic model: seed = 0x{seed:08x}")
    if seed != SEED_TOKEN:
        raise RuntimeError(f"model seed 0x{seed:x} != expected 0x{SEED_TOKEN:x}")

    # Apply the solved model to the live session and prove it drives the
    # process to the success path.
    solution.apply(dbg)
    if int.from_bytes(dbg.read_memory(seed_slot, 4), "little") != SEED_TOKEN:
        raise RuntimeError("applied model did not stick")
    dbg.continue_execution()
    result = dbg.wait_for_exit(timeout=5)
    output = process.recv(4096)
    if result.exit_status != 0 or b"crackme_success" not in output:
        raise RuntimeError(
            f"applied solution did not reach crackme_success: "
            f"status={result.exit_status}, output={output!r}"
        )
    print("[+] crackme solved symbolically; live run reached crackme_success")
