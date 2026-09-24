"""Symbolic-stdin flag solve with live verification.

The classic CTF pattern from angr's solving guide: explore from the target's
entry with symbolic stdin, constrain the bytes to printable ASCII, find the
success branch, and dump the stdin model. mydbg closes the loop against the
live process: the solution is written to a file and the target is relaunched
with it (mydbg's pty stdin corrupts binary payloads, so the file route is the
reliable verification channel).

Run standalone:

    ./build/dev/mydbg --headless-script examples/solve_stdin.py
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from mydbg import rop, symbolic


def target_path() -> str:
    configured = os.environ.get("MYDBG_SYMBOLIC_TARGET")
    if configured:
        return configured
    repository_build = (Path(__file__).resolve().parents[1] / "build" /
                        "debuggee_symbolic_stdin")
    if repository_build.is_file():
        return str(repository_build)
    raise RuntimeError(
        "debuggee_symbolic_stdin was not found; build it or set MYDBG_SYMBOLIC_TARGET"
    )


def run(dbg):
    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    executable = target_path()

    project = symbolic._entry_project(dbg, binary=executable)  # noqa: SLF001
    find = symbolic.resolve_project_symbol(project, "stdin_success")
    avoid = [symbolic.resolve_project_symbol(project, "stdin_fail")]
    print(f"[+] stdin_success at {find:#x}, avoiding {avoid[0]:#x}")

    unicorn = os.environ.get("MYDBG_STDIN_UNICORN") == "1"
    solution = symbolic.solve_entry_stdin(dbg, find, avoid=avoid, size=24,
                                          printable=True, timeout=300,
                                          binary=executable, unicorn=unicorn)
    print(solution.summary())
    if solution.status != "found":
        raise RuntimeError(f"stdin solve failed: {solution.status}")

    # Close the loop against the live process: relaunch with the model as an
    # input file and require the success path.
    with tempfile.TemporaryDirectory(prefix="mydbg-stdin-") as workdir:
        input_path = str(Path(workdir) / "solution.bin")
        Path(input_path).write_bytes(solution.input_bytes)
        config = rop.RunConfig(argv=[executable, input_path], stop_at="main")
        landing = rop.test_landing(dbg, config, solution.input_bytes, 0,
                                   send_stdin=False,
                                   expect_output=b"stdin_flag_ok",
                                   expect_exit=0, timeout=30)
        print(landing.summary())
        if not landing.landed:
            raise RuntimeError("the solved stdin did not drive the live target")
    print("[+] stdin-solve-ok")
