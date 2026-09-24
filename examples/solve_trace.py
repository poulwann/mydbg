"""Trace-guided symbolic solve: replay the live trace, then solve the input.

The Tracer pattern from angr's CTF workflows: record the concrete run from a
breakpoint stop to the function of interest, replay it with angr's Tracer
(fast-forwarding through the concrete path with the live path history), and
solve the input from the traced state. Demonstrated on the x86_64 crackme:
trace from crackme_entry to crackme_verify, symbolize the seed slot on the
traced state, and drive the live process to crackme_success.

Run standalone:

    ./build/dev/mydbg --headless-script examples/solve_trace.py
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
    entry_gate = dbg.set_breakpoint("crackme_entry")
    dbg.continue_execution()
    if dbg.wait_for_stop(timeout=5).state != "stopped":
        raise RuntimeError("crackme_entry was not reached")
    frame_base = dbg.read_register("rbp")
    seed_slot = frame_base - 0x44

    # The replay target: the run stops here after the trace is recorded.
    verify = symbolic.resolve_symbol(dbg, "crackme_verify")
    verify_gate = dbg.set_breakpoint("crackme_verify")

    # Explore from the traced state to the success path; the trace itself
    # stops at crackme_verify's entry.
    success = symbolic.resolve_symbol(dbg, "crackme_success")
    solution = symbolic.trace_way(
        dbg,
        symbolize=["reg:edi"],  # the 32-bit seed argument at crackme_verify
        find=success,
        stop_at=verify,
        max_trace_steps=2000,
        timeout=120,
    )
    print(solution.summary())
    if solution.status != "found":
        raise RuntimeError(f"trace-guided solve failed: {solution.status}")
    seed = solution.model_int("edi") & 0xffffffff
    print(f"[+] traced model: seed = 0x{seed:08x}")
    if seed != SEED_TOKEN:
        raise RuntimeError(f"model seed 0x{seed:x} != expected 0x{SEED_TOKEN:x}")

    # Apply the model to the live session (stopped at crackme_verify after the
    # trace) and prove the live run reaches crackme_success.
    solution.apply(dbg)
    dbg.remove_breakpoint(entry_gate)
    dbg.remove_breakpoint(verify_gate)
    dbg.continue_execution()
    result = dbg.wait_for_exit(timeout=5)
    output = process.recv(4096)
    if result.exit_status != 0 or b"crackme_success" not in output:
        raise RuntimeError(f"applied solution did not succeed: "
                           f"status={result.exit_status}, output={output!r}")
    print("[+] trace-solve-ok live run reached crackme_success")
