"""Keygen solve with the call-state pattern and live verification.

Calls ``keygen_valid`` with a symbolic NUL-terminated printable serial, using
the guide's "nonzero return value is satisfiable" success condition. The
solved serial is then verified against the live target via a relaunch with the
serial as argv[1].

Run standalone:

    ./build/dev/mydbg --headless-script examples/solve_keygen.py
"""

from __future__ import annotations

import os
from pathlib import Path

from mydbg import rop, symbolic


def target_path() -> str:
    configured = os.environ.get("MYDBG_SYMBOLIC_TARGET")
    if configured:
        return configured
    repository_build = (Path(__file__).resolve().parents[1] / "build" /
                        "debuggee_keygenme")
    if repository_build.is_file():
        return str(repository_build)
    raise RuntimeError(
        "debuggee_keygenme was not found; build it or set MYDBG_SYMBOLIC_TARGET"
    )


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    executable = target_path()

    # A live stop anchors the state: globals, stack, and runtime bases come
    # from the snapshot, and resolve_symbol needs a session.
    process = dbg.launch([executable, "wrong"], stop_at="main", timeout=15)
    function = symbolic.resolve_symbol(dbg, "keygen_valid")
    print(f"[+] keygen_valid at {function:#x}")

    solution = symbolic.call_way(dbg, function, size=17, printable=True,
                                 timeout=300)
    print(solution.summary())
    if solution.status != "found":
        raise RuntimeError(f"keygen solve failed: {solution.status}")
    serial = solution.input_bytes.rstrip(b"\x00")
    if len(serial) != 16:
        raise RuntimeError(f"solved serial has wrong length: {serial!r}")

    # Verify against the live process: relaunch with the serial on argv.
    landing = rop.test_landing(
        dbg,
        rop.RunConfig(argv=[executable, serial.decode("ascii")], stop_at="main"),
        serial, 0, send_stdin=False, expect_output=b"keygen_ok",
        expect_exit=0, timeout=30,
    )
    print(landing.summary())
    if not landing.landed:
        raise RuntimeError("the solved serial did not validate on the live target")
    del process
    print("[+] keygen-solve-ok")
