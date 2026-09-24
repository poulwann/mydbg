"""angrop integration for live mydbg sessions.

Covers the ROP-debug loop: scan gadgets once (content-keyed cache), build
chains, place payloads in the live session, and relaunch with the same input
until the chain lands where intended. The reverser scripts the loop; this
module and the GUI accelerate it.

Requires the optional angr backend (see ``requirements-symbolic.txt`` and
``scripts/bootstrap-symbolic.sh``); angrop rides on the same install.
"""

from __future__ import annotations

import os
import signal
import struct
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .symbolic import binary_digest, resolve_symbol

# NUL is deliberately absent: non-PIE gadget addresses contain 0x00 bytes, and
# targets that read from pipes carry them fine. Add 0x00 only when the input
# channel cannot transport it.
DEFAULT_BADBYTES = b"\x0a\x0d"
ROP_CACHE_ENV = "MYDBG_ROP_CACHE_DIR"
BOOTSTRAP_HINT = (
    "the angr backend is not installed for this interpreter; "
    "run scripts/bootstrap-symbolic.sh (see docs/manual/11-symbolic-execution.md)"
)


def _import_angr():
    try:
        import angr  # noqa: PLC0415
        import angrop  # noqa: PLC0415,F401  registers the ROP analysis
        from angrop import rop_utils  # noqa: PLC0415

        _disable_angr_alarms(signal, rop_utils)
        return angr
    except ImportError as error:
        raise ImportError(BOOTSTRAP_HINT) from error


class _ThreadSafeSignalStub:
    """Replaces angrop's alarm-based bail-outs inside mydbg's script thread.

    angrop's ``@timeout`` decorators call ``signal.signal``/``signal.alarm``,
    which the kernel only permits on the main thread; mydbg scripts always run
    on the embedded interpreter's worker thread, so every angrop entry point
    would raise ``ValueError``. The decorators resolve ``signal`` from
    ``angrop.rop_utils`` at call time, so stubbing that one reference disables
    the internal timeouts. Bound enforcement is mydbg's job instead: the GUI
    and headless runners wrap jobs in their own caps, and scripts get an
    explicit cancellation channel through the debugger bindings.
    """

    SIGALRM = signal.SIGALRM  # type: ignore[name-defined]

    def __init__(self, real_signal):
        self._real = real_signal

    def signal(self, sig, handler):
        return self._real.getsignal(sig)

    def alarm(self, seconds):
        return 0

    def getsignal(self, sig):
        return self._real.getsignal(sig)

    def __getattr__(self, name):
        return getattr(self._real, name)


def _disable_angr_alarms(real_signal, rop_utils):
    if getattr(rop_utils, "_mydbg_alarms_disabled", False):
        return
    rop_utils.signal = _ThreadSafeSignalStub(real_signal)
    rop_utils._mydbg_alarms_disabled = True


# --- Engine -------------------------------------------------------------------


class RopEngine:
    """Gadget finder and chain builder over one binary.

    Scans are single-threaded: angrop's multi-process finder does not survive
    Python 3.14's spawn-based multiprocessing, and single-threaded scans are
    deterministic. Results are cached on disk keyed by binary content, bad
    bytes, and angrop version, so relaunch loops never rescan.
    """

    def __init__(self, binary: str, *, badbytes: bytes = DEFAULT_BADBYTES,
                 fast_mode: bool | None = None):
        self.binary = binary
        self.badbytes = badbytes
        self._angr = _import_angr()
        self._project = self._angr.Project(binary, auto_load_libs=False)
        self._rop = self._project.analyses.ROP(fast_mode=fast_mode)
        self._rop.badbytes = list(badbytes)
        self._loaded = False

    # -- scanning ---------------------------------------------------------

    @staticmethod
    def cache_path(binary: str, badbytes: bytes) -> Path:
        root = os.environ.get(ROP_CACHE_ENV)
        base = Path(root) if root else Path.home() / ".cache" / "mydbg" / "rop"
        digest = binary_digest(binary)
        bad = badbytes.hex() or "none"
        return base / f"{digest}-{bad}.pkl"

    def has_cache(self) -> bool:
        return self.cache_path(self.binary, self.badbytes).is_file()

    def find_gadgets(self, *, use_cache: bool = True,
                     show_progress: bool = False) -> "RopEngine":
        """Populate gadgets, from the content-keyed cache when available."""
        path = self.cache_path(self.binary, self.badbytes)
        if use_cache and path.is_file():
            self._rop.load_gadgets(str(path))
            self._loaded = True
            return self
        self._rop.find_gadgets_single_threaded(show_progress=show_progress)
        self._loaded = True
        if use_cache:
            path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._rop.save_gadgets(str(path))
            except Exception:  # noqa: BLE001 - a failed cache write is benign
                pass
        return self

    def ensure_gadgets(self, **kwargs) -> "RopEngine":
        if not self._loaded:
            self.find_gadgets(**kwargs)
        return self

    # -- gadget inspection --------------------------------------------------

    def gadgets(self) -> list:
        self.ensure_gadgets()
        return list(self._rop.rop_gadgets)

    def find_gadgets_matching(self, text: str, *, exact: bool = False) -> list:
        """Gadgets whose disassembly text contains (or equals) ``text``.

        angrop gadgets carry basic-block addresses, not instruction lists, so
        matching runs against the gadget's ``dstr()`` asm string.
        """
        text = text.lower()
        matches = []
        for gadget in self.gadgets():
            rendered = self.gadget_text(gadget)
            if (rendered == text) if exact else (text in rendered):
                matches.append(gadget)
        return matches

    def gadget_text(self, gadget) -> str:
        """Lowercase instruction text for one gadget (``dstr`` minus addresses)."""
        return " ; ".join(part.split(":", 1)[-1].strip()
                          for part in gadget.dstr().split(";"))

    def gadget_summary(self, gadget) -> str:
        return f"{gadget.addr:#x}: {self.gadget_text(gadget)}"

    def summary(self, limit: int = 40) -> str:
        gadgets = self.gadgets()
        lines = [f"{len(gadgets)} gadgets in {self.binary} "
                 f"(badbytes={self.badbytes.hex() or 'none'})"]
        for gadget in gadgets[:limit]:
            lines.append(self.gadget_summary(gadget))
        if len(gadgets) > limit:
            lines.append(f"... {len(gadgets) - limit} more")
        return "\n".join(lines)

    # -- chain building -----------------------------------------------------

    def set_regs(self, **registers):
        """Chain that loads registers from the stack; returns an angrop ROP."""
        self.ensure_gadgets()
        return self._rop.set_regs(**registers)

    def func_call(self, function, arguments, **kwargs):
        """Chain that sets the argument registers and calls ``function``."""
        self.ensure_gadgets()
        return self._rop.func_call(function, arguments, **kwargs)

    def do_syscall(self, syscall_number: int, arguments: dict, **kwargs):
        self.ensure_gadgets()
        return self._rop.do_syscall(syscall_number, arguments, **kwargs)

    def execve(self, path: bytes, arguments: list[bytes] = (), env: dict = {},  # noqa: A002 - angrop API
               **kwargs):
        self.ensure_gadgets()
        return self._rop.execve(path=path, arguments=arguments, env=env, **kwargs)

    def chain_bytes(self, chain) -> bytes:
        return bytes(chain.payload_str())


# --- Placement and the relaunch loop -------------------------------------------


def p64(value: int, size: int = 8, *, little_endian: bool = True) -> bytes:
    return value.to_bytes(size, "little" if little_endian else "big")


def place(dbg, payload: bytes, address: int, *, timeout: float = 10.0) -> None:
    """Write a ROP payload into the live session."""
    dbg.write_memory(address, payload, timeout=timeout)


@dataclass
class RunConfig:
    """A persisted relaunch recipe: argv/env/cwd plus the stop point.

    Scripts build one, iterate the payload, and relaunch with identical setup
    so each iteration lands at the same stack depth.
    """

    argv: list[str]
    environment: dict[str, str] = field(default_factory=dict)
    cwd: str = ""
    stop_at: str = "main"
    stdin: bytes = b""


def relaunch(dbg, config: RunConfig, *, timeout: float = 15.0):
    """Terminate the session and start it again with identical arguments.

    Returns the fresh process handle; the session is stopped at ``stop_at``.
    """
    dbg.terminate(timeout=timeout)
    process = dbg.launch(config.argv, stop_at=config.stop_at,
                         environment=config.environment, cwd=config.cwd,
                         timeout=timeout)
    if config.stdin:
        process.send(config.stdin, timeout=timeout)
    return process


@dataclass
class LandingResult:
    """Outcome of ``test_landing``: did the chain land at the expected PC?"""

    landed: bool
    actual_pc: int
    expected_pc: int | None
    detail: str

    def summary(self) -> str:
        verdict = "landed" if self.landed else "MISSED"
        expected = (f"{self.expected_pc:#x}" if self.expected_pc is not None
                    else "unspecified")
        return f"rop-landing-{verdict} pc={self.actual_pc:#x} expected={expected} {self.detail}"


def test_landing(dbg, config: RunConfig, payload: bytes, payload_address: int,
                 *, expect_pc: int | None = None, expect_output: bytes | None = None,
                 expect_exit: int | None = None, timeout: float = 20.0,
                 line_mode: bool = True, send_stdin: bool = True) -> LandingResult:
    """One iteration of the ROP loop: relaunch, place, continue, verify.

    ``payload`` is written at ``payload_address`` when that address is
    non-zero (a live memory placement) and, with ``send_stdin``, also delivered
    on stdin. The chain lands wherever the overwritten return address points;
    the actual PC is reported so a missed landing is diagnosable.

    LLDB launches with a pty whose canonical line discipline corrupts binary
    stdin (EOF/erase/signal bytes are processed, not delivered), so byte-exact
    payloads belong in a file fed by argv; ``send_stdin`` is only for
    text-protocol targets. ``line_mode`` appends a newline so canonical-mode
    ``read()`` unblocks.
    """
    process = relaunch(dbg, config, timeout=timeout)
    if send_stdin:
        process.send(payload + (b"\n" if line_mode else b""), timeout=timeout)
    if payload_address:
        place(dbg, payload, payload_address, timeout=timeout)
    stop = dbg.continue_and_wait(timeout=timeout)
    if stop.state == "exited":
        actual_pc = 0
        detail = f"exit_status={stop.exit_status}"
        output = process.recv(4096, timeout=timeout)
        landed = ((expect_exit is None or stop.exit_status == expect_exit)
                  and (expect_output is None or expect_output in output)
                  and expect_pc is None)
        return LandingResult(landed, actual_pc, expect_pc,
                             detail + f" output={output[:120]!r}")
    snapshot = dbg.snapshot()
    actual_pc = snapshot.pc
    output = b""
    try:
        output = process.recv(4096, timeout=1.0)
    except Exception:  # noqa: BLE001 - output is optional
        pass
    landed = ((expect_pc is None or actual_pc == expect_pc)
              and (expect_output is None or expect_output in output))
    return LandingResult(landed, actual_pc, expect_pc,
                         f"stopped {snapshot.stop_reason} output={output[:120]!r}")
