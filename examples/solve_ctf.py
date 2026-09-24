"""Live script-debugger demo for the NEBULA-7 CTF challenge.

Open this file with the Python Script Debugger and choose Debug. Step through
this script while it launches the vault, waits for ctf_gate, extracts the
per-process target from the stopped frame, and patches the submitted candidate.
"""

from __future__ import annotations

import os
from pathlib import Path

TOKEN_SIZE = 32
DUMMY_TOKEN = b"00" * TOKEN_SIZE
FLAG = b"flag{scripted_debuggers_turn_runtime_state_into_answers}"


def challenge_path() -> str:
    configured = os.environ.get("MYDBG_CTF_CHALLENGE")
    if configured:
        return configured

    repository_build = Path(__file__).resolve().parents[1] / "build" / "ctf_challenge"
    if repository_build.is_file():
        return str(repository_build)

    beside_script = Path(__file__).resolve().with_name("ctf_challenge")
    if beside_script.is_file():
        return str(beside_script)

    raise RuntimeError(
        "ctf_challenge was not found; build it or set MYDBG_CTF_CHALLENGE"
    )


def pointer_value(dbg, expression: str) -> int:
    result = dbg.evaluate(expression)
    if result.numeric_value is None:
        raise RuntimeError(f"{expression} did not evaluate to an address: {result}")
    return result.numeric_value


def run(dbg):
    executable = challenge_path()
    process = dbg.launch([executable], stop_at="main")

    gate = dbg.set_breakpoint("ctf_gate")
    print(f"[+] launched {executable}")
    print(f"[+] breakpoint {gate} set on ctf_gate")

    dbg.continue_execution()
    banner = process.recvuntil(b"token> ", timeout=5)
    print(banner.decode("utf-8", errors="replace"), end="")

    # A deliberately wrong token gets the vault as far as its final gate.
    process.sendline(DUMMY_TOKEN)
    stop = dbg.wait_for_stop(timeout=5)
    if stop.state != "stopped":
        raise RuntimeError(f"ctf_gate was not reached: {stop.state}")

    candidate_address = pointer_value(dbg, "candidate")
    expected_address = pointer_value(dbg, "expected")
    count = pointer_value(dbg, "count")
    if count != TOKEN_SIZE:
        raise RuntimeError(f"unexpected gate width: {count}")

    expected = dbg.read_memory(expected_address, count)
    original = dbg.read_memory(candidate_address, count)
    print(f"[+] candidate @ 0x{candidate_address:x}: {original.hex()}")
    print(f"[+] runtime target @ 0x{expected_address:x}: {expected.hex()}")

    # Patch the live candidate rather than reimplementing the rekey algorithm.
    dbg.write_memory(candidate_address, expected)
    patched = dbg.read_memory(candidate_address, count)
    if patched != expected:
        raise RuntimeError("candidate patch did not stick")
    print("[+] patched the candidate with the per-process target")

    dbg.continue_execution()
    result = process.recvuntil(FLAG + b"\r\n", timeout=5)
    print(result.decode("utf-8", errors="replace"), end="")
    exited = dbg.wait_for_exit(timeout=5)
    if exited.exit_status != 0 or FLAG not in result:
        raise RuntimeError(
            f"vault solve failed: status={exited.exit_status}, output={result!r}"
        )

    print("[+] NEBULA-7 solved entirely through debugger state")
