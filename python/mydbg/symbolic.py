"""Symbolic execution helpers for live mydbg sessions, backed by angr.

The workflow this module supports: stop the target at any PC, snapshot the
concrete state into an angr ``SimState``, mark memory or registers symbolic,
explore guarded paths toward a target address under hard bounds, and apply the
solved model back into the live session.

The GUI bootstraps scripts that use this module; manual scripting is expected.
Everything here is plain Python over the existing ``dbg`` automation API, so it
works in GUI scripts, headless scripts, and the built-in script debugger.

Requires the optional angr backend (see ``requirements-symbolic.txt`` and
``scripts/bootstrap-symbolic.sh``).
"""

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass, field
from typing import Callable, Sequence

BOOTSTRAP_HINT = (
    "the angr backend is not installed for this interpreter; "
    "run scripts/bootstrap-symbolic.sh (see docs/manual/11-symbolic-execution.md)"
)

# Page size used when seeding live memory; skipped pages never fail the state.
_PAGE = 0x1000
# Default live-memory seeding limits. Explorations that need more should pass
# explicit regions rather than relying on larger automatic windows.
_DEFAULT_STACK_BYTES = 0x10000
_DEFAULT_MODULE_BYTES = 0x2000000
_MAX_KTEST_OBJECTS = 4096


def _import_angr():
    try:
        import angr  # noqa: PLC0415
        import claripy  # noqa: PLC0415

        return angr, claripy
    except ImportError as error:
        raise ImportError(BOOTSTRAP_HINT) from error


def requires_angr() -> bool:
    """True when the angr backend is importable in the embedded interpreter."""
    try:
        _import_angr()
        return True
    except ImportError:
        return False


# --- Snapshot -> SimState conversion ----------------------------------------


def _register_candidates(name: str) -> list[str]:
    """Candidate angr/archinfo register names for one LLDB register name."""
    lowered = name.lower().removeprefix("$")
    aliases = {
        "eip": "rip", "esp": "rsp", "ebp": "rbp",
    }
    primary = aliases.get(lowered, lowered)
    candidates = [primary]
    if primary.startswith("r") and primary[1:].isdigit():
        # LLDB ppc32 uses r0..r31; archinfo uses gpr0..gpr31.
        candidates.append(f"gpr{primary[1:]}")
    return candidates


@dataclass(frozen=True)
class ConversionNotes:
    """Diagnostics from building a SimState out of a live stop."""

    skipped_registers: tuple[str, ...] = ()
    unreadable_pages: int = 0
    seeded_bytes: int = 0
    hooked_plt: int = 0


def state_from_debugger(
    dbg,
    snapshot=None,
    *,
    stack_bytes: int = _DEFAULT_STACK_BYTES,
    module_bytes: int = _DEFAULT_MODULE_BYTES,
    extra_regions: Sequence[tuple[int, int]] = (),
    zero_fill: bool = True,
) -> tuple[object, object, ConversionNotes]:
    """Build ``(project, state, notes)`` from the current stopped session.

    ``state`` starts at the live PC with live register values, and its memory
    is seeded from the live main-module mapping (which honors applied patches),
    the stack window around SP, and any ``extra_regions``. Everything angr
    executes is lifted from live bytes, not from the on-disk image, so PIE
    rebasing and instruction patching compose automatically.
    """
    angr, _ = _import_angr()
    if snapshot is None:
        snapshot = dbg.snapshot()
    if snapshot.state != "stopped":
        raise RuntimeError(f"symbolic state needs a stopped session, got {snapshot.state}")
    if not snapshot.modules:
        raise RuntimeError("snapshot has no modules; cannot locate the main image")

    main_module = next(
        (m for m in snapshot.modules if m.base <= snapshot.pc < m.end),
        snapshot.modules[0],
    )
    project = angr.Project(main_module.path, auto_load_libs=False)
    # angr maps the image at its own base and installs SimProcedure hooks for
    # PLT stubs there. The explored state runs at the live runtime base, so
    # every hook is re-registered at the runtime PLT address; otherwise calls
    # like printf@plt execute real stubs and jump through the live GOT into
    # the dynamic loader.
    runtime_delta = main_module.base - project.loader.main_object.mapped_base
    hooks_by_name: dict[str, object] = {}
    for hook_addr, procedure in project._sim_procedures.items():
        name = getattr(procedure, "display_name", "") or type(procedure).__name__
        hooks_by_name.setdefault(name, procedure)
    hooked_plt = 0
    for name, plt_address in project.loader.main_object.plt.items():
        procedure = hooks_by_name.get(name)
        if procedure is not None:
            project.hook(plt_address + runtime_delta, procedure)
            hooked_plt += 1
    options = set()
    if zero_fill:
        options |= {angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS}
    state = project.factory.blank_state(addr=snapshot.pc, add_options=options)

    seeded = 0
    unreadable = 0

    def seed(address: int, size: int) -> None:
        nonlocal seeded, unreadable
        read, holes = _read_pages(dbg, address, size)
        if read is None:
            unreadable += holes
            return
        if read:
            state.memory.store(address, read)
            seeded += len(read)
        unreadable += holes

    # Main-module live image. Read in bounded chunks so huge mappings stay safe.
    module_start = main_module.base
    module_size = min(main_module.end - main_module.base, module_bytes)
    chunk = 0x10000
    for offset in range(0, module_size, chunk):
        seed(module_start + offset, min(chunk, module_size - offset))

    # Stack window around SP, honoring the snapshot's live stack pointer.
    if snapshot.sp:
        for direction in (-1, 1):
            start = snapshot.sp - stack_bytes if direction < 0 else snapshot.sp
            seed(start, stack_bytes)

    for address, size in extra_regions:
        seed(address, size)

    # Applied instruction patches are already live in the process, but overlay
    # them explicitly so a stale read can never regress a patched byte.
    for patch in snapshot.patches:
        state.memory.store(patch.address, bytes(patch.replacement))

    skipped_registers: list[str] = []
    seeded_ranges: list[tuple[int, int]] = []
    # Seed widest-first and skip aliases (r8d/bp/ebx...) that are subranges of
    # already-stored registers; otherwise narrow alias values clobber the wide
    # register seeded earlier from the same live values.
    storable: list[tuple[int, int, str, int]] = []
    for register in snapshot.registers:
        for alias in _register_candidates(register.name):
            entry = state.arch.registers.get(alias)
            if entry is None:
                continue
            offset, width = entry[0], entry[1]
            try:
                value = dbg.read_register(register.name.lower().removeprefix("$"))
            except Exception:  # noqa: BLE001 - non-numeric registers are expected
                skipped_registers.append(register.name)
                break
            storable.append((width, offset, alias, value))
            break
        else:
            skipped_registers.append(register.name)
    storable.sort(key=lambda item: (-item[0], item[1]))
    for width, offset, alias, value in storable:
        if any(start <= offset and offset + width <= start + span
               for start, span in seeded_ranges):
            continue  # narrow alias of an already-seeded wider register
        try:
            state.registers.store(alias, value & ((1 << (width * 8)) - 1))
        except (KeyError, AttributeError, ValueError):
            skipped_registers.append(alias)
            continue
        seeded_ranges.append((offset, width))

    notes = ConversionNotes(
        skipped_registers=tuple(skipped_registers),
        unreadable_pages=unreadable,
        seeded_bytes=seeded,
        hooked_plt=hooked_plt,
    )
    return project, state, notes


def _read_pages(dbg, address: int, size: int) -> tuple[bytes | None, int]:
    """Read live memory; returns ``(bytes, hole pages)``.

    One bulk read is tried first; on failure the region is probed page-wise so
    sparse holes never fail the whole seed. ``None`` means nothing was readable.
    """
    try:
        return bytes(dbg.read_memory(address, size)), 0
    except Exception:  # noqa: BLE001 - fall through to page-wise probing
        pass
    parts: list[bytes] = []
    holes = 0
    for offset in range(0, size, _PAGE):
        try:
            parts.append(bytes(dbg.read_memory(address + offset, _PAGE)))
        except Exception:  # noqa: BLE001 - holes between mappings are normal
            parts.append(b"")
            holes += 1
    if not any(parts):
        return None, holes
    filled = b"".join(part if len(part) == _PAGE else part.ljust(_PAGE, b"\0")
                      for part in parts)
    return filled, holes


# --- Symbolizing inputs ------------------------------------------------------


def symbolize_memory(state, address: int, size: int, name: str = "input"):
    """Replace ``size`` live bytes at ``address`` with one symbolic variable."""
    angr, claripy = _import_angr()
    variable = claripy.BVS(name, size * 8)
    state.memory.store(address, variable)
    return variable


def symbolize_register(state, register: str, name: str | None = None):
    """Make one register symbolic; returns the claripy variable."""
    angr, claripy = _import_angr()
    for alias in _register_candidates(register):
        if alias in state.arch.registers:
            break
    else:
        raise ValueError(f"unknown register {register!r} for {state.arch.name}")
    width = state.arch.registers[alias][1]
    variable = claripy.BVS(name or alias, width * 8)
    state.registers.store(alias, variable)
    return variable


def model_bytes(state, variable) -> bytes:
    """Concretize one symbolic variable under the state's path constraints."""
    return state.solver.eval(variable, cast_to=bytes)


def model_int(state, variable) -> int:
    """Concretize one symbolic variable as an integer."""
    return state.solver.eval(variable)


# --- Bounded exploration ------------------------------------------------------


@dataclass
class ExplorationResult:
    """Outcome of a bounded exploration. ``found`` states satisfy the target."""

    found: list = field(default_factory=list)
    active: list = field(default_factory=list)
    deadended: int = 0
    avoided: int = 0
    errored: int = 0
    error_sample: str = ""
    steps: int = 0
    timed_out: bool = False
    cancelled: bool = False

    @property
    def status(self) -> str:
        if self.found:
            return "found"
        if self.cancelled:
            return "cancelled"
        if self.timed_out:
            return "timeout"
        if self.active:
            return "unresolved"
        return "exhausted"


def _bounded_technique(angr, deadline: float, max_steps: int, max_states: int,
                       cancel: Callable[[], bool] | None):
    """Build an angr ExplorationTechnique enforcing wall-clock/step/state bounds.

    Everything that survives past a bound is moved to the ``cut`` stash, so a
    bounded run always terminates with a fully inspectable manager.
    """
    class Bounded(angr.exploration_techniques.ExplorationTechnique):
        def __init__(self):
            super().__init__()
            self.steps = 0

        def step(self, simgr, stash="active", **kwargs):  # noqa: ARG002 - angr API
            self.steps += 1
            exceeded = (
                time.time() >= deadline
                or self.steps >= max_steps
                or len(simgr.stashes.get(stash, ())) >= max_states
            )
            cancelled = cancel is not None and cancel()
            if exceeded or cancelled:
                simgr.move(stash, "cut", lambda state: True)  # noqa: ARG005
                return simgr
            return simgr.step(stash=stash, **kwargs)

    return Bounded()


def explore(project, state, find, avoid: Sequence[int] = (), *, timeout: float = 60.0,
            max_steps: int = 20000, max_states: int = 4000,
            cancel: Callable[[], bool] | None = None) -> tuple[object, ExplorationResult]:
    """Explore from ``state`` toward ``find`` under hard bounds.

    ``find`` is an address, a sequence of addresses, or a state predicate.
    Returns the final ``SimulationManager`` plus a summary result; the manager
    keeps every stash, so partial work is never thrown away.
    """
    simgr = project.factory.simgr(state)
    deadline = time.time() + timeout
    technique = _bounded_technique(_import_angr()[0], deadline,
                                   max_steps, max_states, cancel)
    simgr.use_technique(technique)
    simgr.explore(find=find, avoid=list(avoid))
    result = ExplorationResult(
        found=list(simgr.found),
        active=list(simgr.active),
        deadended=len(simgr.deadended),
        avoided=len(simgr.avoid),
        errored=len(simgr.errored),
        error_sample=(f"pc={simgr.errored[0].state.addr:#x} {simgr.errored[0].error} blocks="
                      + "->".join(hex(a) for a in simgr.errored[0].state.history.bbl_addrs.hardcopy[-12:])
                      if simgr.errored else ""),
        steps=technique.steps,
        timed_out=time.time() >= deadline and bool(simgr.active),
        cancelled=bool(cancel and cancel()),
    )
    return simgr, result


# --- High-level solve-from-PC workflow ----------------------------------------


@dataclass
class Symbol:
    """One symbolized input region produced by a solve request."""

    kind: str  # "memory" or "register"
    name: str
    variable: object
    address: int = 0
    size: int = 0
    register: str = ""


@dataclass
class Solution:
    """Result of ``find_way``: model bytes ready to apply to the live session."""

    status: str
    symbols: list[Symbol] = field(default_factory=list)
    states: list = field(default_factory=list)
    result: ExplorationResult | None = None
    notes: ConversionNotes | None = None
    models: dict[str, bytes] = field(default_factory=dict)
    manager: object = None

    def summary(self) -> str:
        lines = [f"status: {self.status}"]
        if self.notes is not None:
            lines.append(
                f"seeded {self.notes.seeded_bytes} bytes, "
                f"{self.notes.unreadable_pages} unreadable pages, "
                f"skipped registers: {', '.join(self.notes.skipped_registers) or 'none'}"
            )
        for symbol in self.symbols:
            model = self.models.get(symbol.name)
            if model is None:
                lines.append(f"{symbol.name}: no model")
            elif symbol.kind == "memory":
                lines.append(f"{symbol.name} @ {symbol.address:#x} = {model.hex()}")
            else:
                width = symbol.size * 8
                value = int.from_bytes(model, "little") if model else 0
                lines.append(f"{symbol.name} ({symbol.register}) = {value:#0{width // 4 + 2}x}")
        if self.result is not None:
            lines.append(
                f"steps={self.result.steps} deadended={self.result.deadended} "
                f"avoided={self.result.avoided} errored={self.result.errored}"
            )
            if self.result.error_sample:
                lines.append(f"error sample: {self.result.error_sample}")
        return "\n".join(lines)

    def apply(self, dbg, *, timeout: float = 10.0) -> None:
        """Write every solved model back into the live session."""
        if self.status != "found":
            raise RuntimeError(f"cannot apply an unresolved solution ({self.status})")
        for symbol in self.symbols:
            model = self.models.get(symbol.name)
            if model is None:
                continue
            if symbol.kind == "memory":
                dbg.write_memory(symbol.address, model, timeout=timeout)
            else:
                value = int.from_bytes(model, "little")
                dbg.write_register(symbol.register, value, timeout=timeout)


def _parse_symbol_spec(spec, state) -> Symbol:
    """Parse one symbolize specification: ``reg:NAME``, ``hexaddr:size``, or address-only."""
    lowered = spec.strip().lower()
    if lowered.startswith("reg:"):
        register = lowered[4:]
        variable = symbolize_register(state, register)
        alias = next(alias for alias in _register_candidates(register)
                     if alias in state.arch.registers)
        width = state.arch.registers[alias][1]
        return Symbol("register", alias, variable, register=register, size=width)
    parts = lowered.split(":")
    if len(parts) == 2:
        address = int(parts[0], 16)
        size = int(parts[1], 16)
    elif len(parts) == 1 and parts[0]:
        address = int(parts[0], 16)
        size = 8
    else:
        raise ValueError(f"cannot parse symbol spec {spec!r}")
    variable = symbolize_memory(state, address, size)
    return Symbol("memory", f"mem_{address:x}", variable, address=address, size=size)


def find_way(
    dbg,
    target: int,
    *,
    symbolize: Sequence[str] = (),
    avoid: Sequence[int] = (),
    timeout: float = 60.0,
    max_steps: int = 20000,
    max_states: int = 4000,
    snapshot=None,
    extra_regions: Sequence[tuple[int, int]] = (),
) -> Solution:
    """From the current stopped PC, explore to ``target`` and solve the inputs.

    ``symbolize`` entries are ``reg:rdi`` (symbolic register), ``deadbeef:20``
    (symbolic 20 bytes at that hex address), or ``deadbeef`` (symbolic pointer
    slot, 8 bytes). With no entries the run is a reachability check.
    """
    project, state, notes = state_from_debugger(dbg, snapshot, extra_regions=extra_regions)
    symbols = [_parse_symbol_spec(spec, state) for spec in symbolize]
    simgr, result = explore(
        project, state, target, avoid=avoid, timeout=timeout,
        max_steps=max_steps, max_states=max_states,
    )
    solution = Solution(
        status=result.status, symbols=symbols, states=list(simgr.found),
        result=result, notes=notes, manager=simgr,
    )
    if simgr.found:
        solution.models = {symbol.name: model_bytes(simgr.found[0], symbol.variable)
                           for symbol in symbols}
    return solution


def resolve_symbol(dbg, name: str) -> int:
    """Resolve a symbol or expression to a runtime address via the engine."""
    for expression in (f"&{name}", name):
        try:
            result = dbg.evaluate(expression)
        except Exception:  # noqa: BLE001 - fall through to the next spelling
            continue
        if result.numeric_value is not None:
            return result.numeric_value
    raise RuntimeError(f"cannot resolve {name!r} to an address")


# --- KLEE artifact interop ----------------------------------------------------


def import_ktest(path: str) -> dict[str, bytes]:
    """Parse a KLEE ``.ktest`` file into ``{object name: concrete bytes}``.

    The returned objects can be applied with ``dbg.write_memory``/registers or
    fed to a relaunch loop; KLEE solves at build time, mydbg replays at runtime.
    """
    with open(path, "rb") as handle:
        data = handle.read()
    if data[:4] not in (b"KTEST", b"BOUT"):
        raise ValueError(f"{path} is not a KTEST file")
    offset = 4
    (version,) = struct.unpack_from(">I", data, offset)
    offset += 4
    if version not in (2, 3, 4):
        raise ValueError(f"unsupported KTEST version {version} in {path}")
    (argument_count,) = struct.unpack_from(">I", data, offset)
    offset += 4
    for _ in range(argument_count):
        (length,) = struct.unpack_from(">I", data, offset)
        offset += 4 + length
    (object_count,) = struct.unpack_from(">I", data, offset)
    offset += 4
    if object_count > _MAX_KTEST_OBJECTS:
        raise ValueError(f"implausible object count {object_count} in {path}")
    objects: dict[str, bytes] = {}
    for _ in range(object_count):
        (size,) = struct.unpack_from(">I", data, offset)
        offset += 4
        (name_length,) = struct.unpack_from(">I", data, offset)
        offset += 4
        name = data[offset:offset + name_length].decode("utf-8", "replace")
        offset += name_length
        objects[name] = data[offset:offset + size]
        offset += size
    return objects


# --- Script generation --------------------------------------------------------


def generate_script(
    target: int | str,
    symbolize: Sequence[str],
    *,
    avoid: Sequence[int | str] = (),
    timeout: float = 60.0,
) -> str:
    """Return an editable bootstrap script for one find-a-way exploration.

    The GUI's "find a way to here" flow emits this text into the script editor;
    the reverser then owns and iterates on it.
    """
    def literal(value: int | str) -> str:
        return f"{value!r}" if isinstance(value, str) else f"0x{value:x}"

    symbol_items = ", ".join(repr(item) for item in symbolize)
    avoid_items = ", ".join(literal(item) for item in avoid)
    return f'''"""Generated by mydbg: symbolic find-a-way bootstrap. Edit freely."""
from mydbg import symbolic


def run(dbg):
    target = symbolic.resolve_symbol(dbg, {target!r})
    solution = symbolic.find_way(
        dbg,
        target,
        symbolize=[{symbol_items}],
        avoid=[{avoid_items}],
        timeout={timeout},
    )
    print(solution.summary())
    if solution.status == "found":
        solution.apply(dbg)
    return solution
'''


def binary_digest(path: str) -> str:
    """SHA256 of a file, used for content-keyed caches."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(0x100000), b""):
            digest.update(block)
    return digest.hexdigest()
