"""Cross-architecture symbolic solve: find the 4-byte input from a stopped PC.

Connects to a QEMU-user session, stops at ``crackme_entry``, symbolizes the
4-byte input string pointed to by the first-argument register, explores to
``crackme_success`` under bounds, asserts the model is ``CTF!``, applies it to
the live session, and proves the live process reaches the success path.

Used by tests/symbolic_solver.py; see docs/manual/11-symbolic-execution.md.
"""

from __future__ import annotations

import os
import time


def _read_register(dbg, candidates: list[str]) -> tuple[str, int]:
    errors: list[str] = []
    for name in candidates:
        try:
            value = dbg.read_register(name)
        except Exception as error:  # noqa: BLE001 - try the next spelling
            errors.append(f"{name}: {error}")
            continue
        if value:
            return name, value
        errors.append(f"{name}: zero")
    raise RuntimeError(f"no first-argument register readable: {'; '.join(errors)}")


def _input_pointer(dbg, snapshot, candidates: list[str], slot: str | None) -> int:
    """Recover the input string pointer at the stopped PC.

    LLDB function breakpoints land after the prologue, which on some
    architectures (ppc32) has already consumed the argument register; the
    caller can then name the stack slot that holds the saved pointer
    (``REG:HEXOFFSET``), read honoring the target's byte order.
    """
    if slot:
        register, _, offset_text = slot.partition(":")
        base = dbg.read_register(register)
        offset = int(offset_text, 16)
        width = snapshot.address_byte_size
        raw = dbg.read_memory(base + offset, width)
        value = int.from_bytes(raw, "big" if snapshot.byte_order == "big" else "little")
        if not value:
            raise RuntimeError(f"saved pointer at {register}+{offset_text} is null")
        return value
    name, value = _read_register(dbg, candidates)
    print(f"[+] input pointer in {name}")
    return value


def run(dbg):
    from mydbg import symbolic

    if not symbolic.requires_angr():
        raise RuntimeError(symbolic.BOOTSTRAP_HINT)
    target = os.environ["MYDBG_SYMBOLIC_TARGET"]
    endpoint = os.environ["MYDBG_SYMBOLIC_ENDPOINT"]
    wrong = os.environ.get("MYDBG_SYMBOLIC_WRONG", "ABCD")
    register_candidates = os.environ.get(
        "MYDBG_SYMBOLIC_PTR_REGS", "a0,r4,r3"
    ).split(",")
    pointer_slot = os.environ.get("MYDBG_SYMBOLIC_PTR_SLOT") or None
    timeout = float(os.environ.get("MYDBG_SYMBOLIC_TIMEOUT", "240"))

    last_error: str | None = None
    for attempt in range(3):
        try:
            process = dbg.connect_remote(target, endpoint, mode="qemu-user",
                                         timeout=30)
            last_error = None
            break
        except RuntimeError as error:
            last_error = str(error)
            time.sleep(0.5)
    if last_error is not None:
        raise RuntimeError(f"failed to connect to {endpoint}: {last_error}")
    gate = dbg.set_breakpoint("crackme_entry")
    dbg.continue_execution()
    stop = dbg.wait_for_stop(timeout=30)
    if stop.state != "stopped":
        raise RuntimeError(f"crackme_entry was not reached: {stop.state}")
    snapshot = dbg.snapshot()
    print(f"[+] connected to {endpoint}; stopped at 0x{snapshot.pc:x} "
          f"({snapshot.architecture}, {snapshot.byte_order}-endian)")

    input_pointer = _input_pointer(dbg, snapshot, register_candidates,
                                   pointer_slot)
    print(f"[+] input pointer at 0x{input_pointer:x}")

    solution = symbolic.find_way(
        dbg,
        symbolic.resolve_symbol(dbg, "crackme_success"),
        symbolize=[f"{input_pointer:x}:4"],
        timeout=timeout,
    )
    print(solution.summary())
    if solution.status != "found":
        raise RuntimeError(f"exploration failed: {solution.status}")
    model = solution.models[f"mem_{input_pointer:x}"]
    if model != b"CTF!":
        raise RuntimeError(f"model {model!r} != expected b'CTF!'")

    solution.apply(dbg)
    if dbg.read_memory(input_pointer, 4) != b"CTF!":
        raise RuntimeError("applied model did not stick")
    dbg.continue_execution()
    result = dbg.wait_for_exit(timeout=30)
    if result.exit_status != 0:
        raise RuntimeError(f"applied solution did not reach the success path: "
                           f"status={result.exit_status}")
    del process
    print("[+] symbolic-solve-ok input=CTF!")
