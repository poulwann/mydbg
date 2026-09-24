"""CTest driver for mydbg's symbolic-execution scripts.

Ensures the angr backend is importable (skipping with code 77 otherwise),
optionally spawns a QEMU-user stub, runs mydbg headless with the requested
script under an isolated session directory, and asserts the script's success
marker. See docs/manual/11-symbolic-execution.md.

Usage:
  symbolic_solver.py <mydbg> --script <solve-script> --target <elf>
                     [--qemu <qemu-binary>] [--ptr-regs a0,r4,r3]
                     [--timeout-seconds N] [--expect <marker>]
"""

import importlib.util
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SKIP_CODE = 77


def ensure_angr() -> None:
    site = os.environ.get("MYDBG_SYMBOLIC_PYTHONPATH", "")
    if site:
        sys.path.insert(0, site)
    if importlib.util.find_spec("angr") is None:
        print("skip: angr backend is not installed "
              "(run scripts/bootstrap-symbolic.sh)")
        raise SystemExit(SKIP_CODE)


def wait_for_port(port: int, deadline_seconds: float = 30.0) -> None:
    """Wait until the port appears in LISTEN state without connecting to it.

    qemu-user's gdbstub handles the first connection specially, so the probe
    must not open a session of its own.
    """
    deadline = time.monotonic() + deadline_seconds
    while time.monotonic() < deadline:
        try:
            for path in ("/proc/net/tcp", "/proc/net/tcp6"):
                try:
                    with open(path) as handle:
                        for line in handle.readlines()[1:]:
                            fields = line.split()
                            if len(fields) < 4:
                                continue
                            local, state = fields[1], fields[3]
                            if state != "0A":  # TCP_LISTEN
                                continue
                            if int(local.split(":")[1], 16) == port:
                                return
                except FileNotFoundError:
                    continue
        except OSError:
            pass
        time.sleep(0.2)
    raise RuntimeError(f"qemu endpoint 127.0.0.1:{port} never became ready")


def main() -> int:
    arguments = sys.argv[1:]
    if len(arguments) < 2 or arguments[0] != "--mydbg":
        raise SystemExit(__doc__)
    mydbg = arguments[1]
    options = {"script": None, "target": None, "qemu": None, "ptr-regs": None,
               "ptr-slot": None, "timeout-seconds": None, "expect": None}
    index = 2
    while index < len(arguments):
        key = arguments[index].removeprefix("--")
        if key in ("script", "target", "qemu", "ptr-regs", "ptr-slot",
                   "timeout-seconds", "expect"):
            options[key] = arguments[index + 1]
            index += 2
        else:
            raise SystemExit(f"unknown argument {arguments[index]}")
    ensure_angr()

    qemu = None
    endpoint = None
    if options["qemu"]:
        port = 26_400 + (os.getpid() % 400)
        qemu = subprocess.Popen(
            [options["qemu"], "-g", str(port), options["target"],
             os.environ.get("MYDBG_SYMBOLIC_WRONG", "ABCD")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        endpoint = f"connect://127.0.0.1:{port}"
        wait_for_port(port)

    environment = os.environ.copy()
    environment["MYDBG_SYMBOLIC_TARGET"] = options["target"]
    if endpoint:
        environment["MYDBG_SYMBOLIC_ENDPOINT"] = endpoint
    if options["ptr-regs"]:
        environment["MYDBG_SYMBOLIC_PTR_REGS"] = options["ptr-regs"]
    if options["ptr-slot"]:
        environment["MYDBG_SYMBOLIC_PTR_SLOT"] = options["ptr-slot"]
    if options["timeout-seconds"]:
        environment["MYDBG_SYMBOLIC_TIMEOUT"] = options["timeout-seconds"]
    site = os.environ.get("MYDBG_SYMBOLIC_PYTHONPATH", "")
    if site:
        existing = environment.get("PYTHONPATH", "")
        environment["PYTHONPATH"] = f"{site}{os.pathsep}{existing}" if existing else site

    try:
        with tempfile.TemporaryDirectory(prefix="mydbg-symbolic-") as session_dir:
            completed = subprocess.run(
                [mydbg, "--headless-script", options["script"]],
                env={**environment, "MYDBG_SESSION_DIR": session_dir},
                capture_output=True, text=True, timeout=600, check=False,
            )
            sys.stdout.write(completed.stdout)
            sys.stderr.write(completed.stderr)
            if completed.returncode != 0:
                raise RuntimeError(
                    f"mydbg exited {completed.returncode}; output above"
                )
            if options["expect"] and options["expect"] not in completed.stdout:
                raise RuntimeError(
                    f"expected marker {options['expect']!r} missing from output"
                )
    finally:
        if qemu is not None:
            qemu.terminate()
            try:
                qemu.wait(timeout=10)
            except subprocess.TimeoutExpired:
                qemu.kill()
    print(f"symbolic-solver-ok target={options['target']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
