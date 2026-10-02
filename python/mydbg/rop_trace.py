"""Read-only, concrete stack-entry tracing using optional Unicorn and Capstone.

Only the initial return is synthesized. Every displayed instruction executes in
Unicorn against lazily captured live bytes; faults and unavailable machine state
end the trace rather than introducing symbolic or zero-filled values.
"""

from __future__ import annotations

import math
import time

_PAGE = 4096
_MAX_BYTES = 8 * 1024 * 1024
_MAX_ACCESS = 65536
_MAX_EVENTS = 65536
_BOOTSTRAP_HINT = (
    "ROP tracing requires Unicorn and Capstone in the optional symbolic Python "
    "environment; run scripts/bootstrap-symbolic.sh and configure that environment."
)


class _Boundary(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def _identity(snapshot):
    return (
        snapshot.state, snapshot.generation, snapshot.stop_revision,
        snapshot.thread_id, snapshot.pc, snapshot.sp,
        tuple((r.name, r.value) for r in snapshot.registers),
        tuple((p.address, bytes(p.replacement)) for p in snapshot.patches),
        tuple((t.id, f.index) for t in snapshot.threads for f in t.frames
              if f.selected),
    )


class _Capture:
    def __init__(self, dbg, snapshot, deadline, cancelled):
        self.dbg = dbg
        self.snapshot = snapshot
        self.identity = _identity(snapshot)
        self.deadline = deadline
        self.cancelled = cancelled
        self.copied = 0
        self.notes = []

    def check(self, live=False):
        if self.cancelled is not None and self.cancelled():
            raise _Boundary("cancelled", "Analysis cancelled; the live target was not changed.")
        if time.monotonic() >= self.deadline:
            raise _Boundary("timeout", "Analysis reached its wall-clock limit.")
        if live and _identity(self.dbg.snapshot()) != self.identity:
            raise _Boundary("stale", "The selected live stop, registers, or patches changed during capture.")

    def remaining(self):
        self.check()
        return max(0.001, min(0.25, self.deadline - time.monotonic()))

    def read(self, address, size):
        self.check(live=True)
        if self.copied + size > _MAX_BYTES:
            raise _Boundary("memory_limit", "Live memory capture reached its 8 MiB limit.")
        self.copied += size
        try:
            data = bytes(self.dbg.read_memory(address, size, timeout=self.remaining()))
        except Exception as error:
            self.check(live=True)
            raise _Boundary("invalid_read", f"Live bytes at {address:#x} are unavailable: {error}") from error
        self.check(live=True)
        if len(data) != size:
            raise _Boundary("invalid_read", f"Short live read at {address:#x}: {len(data)} of {size} bytes.")
        return data

    def register(self, names):
        values = {r.name.lower(): r.value for r in self.snapshot.registers}
        for name in names:
            if name in values:
                try:
                    return int(values[name].strip(), 0)
                except (TypeError, ValueError):
                    pass
        errors = []
        for name in names:
            self.check(live=True)
            try:
                value = int(self.dbg.read_register(name, timeout=self.remaining()))
            except Exception as error:
                self.check(live=True)
                errors.append(str(error))
                continue
            self.check(live=True)
            return value
        raise _Boundary("unavailable_state", f"Required register {names[0]} is unavailable: {'; '.join(errors)}")


class _Memory:
    def __init__(self, capture, uc, unicorn, pointer_size, trace):
        self.capture = capture
        self.uc = uc
        self.unicorn = unicorn
        self.width = pointer_size
        self.limit = 1 << (pointer_size * 8)
        self.trace = trace
        self.regions = sorted(capture.snapshot.memory_regions, key=lambda r: r.start)
        # A mapped Unicorn page is not evidence that its bytes are known. Masks
        # protect partial pages, and original bytes never receive simulated writes.
        self.pages = {}
        self.slots = {}
        self.stack_windows = []

    def region(self, address, kind):
        status = {"read": "invalid_read", "write": "invalid_write", "execute": "invalid_target"}[kind]
        for region in self.regions:
            if region.start <= address < region.end:
                allowed = getattr(region, {"read": "readable", "write": "writable", "execute": "executable"}[kind])
                if not allowed:
                    raise _Boundary(status, f"{kind.capitalize()} permission denied at {address:#x}.")
                return region
        raise _Boundary(status, f"No captured live mapping permits {kind} at {address:#x}.")

    def ensure(self, address, size, kind="read"):
        self.capture.check()
        if size < 0 or size > _MAX_ACCESS or address < 0 or address + size > self.limit:
            raise _Boundary("memory_limit", f"Out-of-range or oversized {kind} at {address:#x} ({size} bytes).")
        cursor = address
        while cursor < address + size:
            region = self.region(cursor, kind)
            base = cursor & -_PAGE
            end = min(address + size, base + _PAGE, region.end)
            if base not in self.pages:
                if len(self.pages) * _PAGE >= _MAX_BYTES:
                    raise _Boundary("memory_limit", "Simulated mappings reached their 8 MiB limit.")
                permissions = 0
                for mapped in self.regions:
                    if mapped.start < base + _PAGE and base < mapped.end:
                        permissions |= (self.unicorn.UC_PROT_READ if mapped.readable else 0)
                        permissions |= (self.unicorn.UC_PROT_WRITE if mapped.writable else 0)
                        permissions |= (self.unicorn.UC_PROT_EXEC if mapped.executable else 0)
                self.uc.mem_map(base, _PAGE, permissions)
                self.pages[base] = (bytearray(_PAGE), bytearray(_PAGE))
                start = max(base, region.start)
                stop = min(base + _PAGE, region.end)
                try:
                    data = self.capture.read(start, stop - start)
                except _Boundary as error:
                    if error.status != "invalid_read":
                        raise
                    # Some remote backends expose mappings containing unreadable
                    # holes. Retry only the requested bytes; never pad the page.
                else:
                    original, known = self.pages[base]
                    original[start - base:stop - base] = data
                    known[start - base:stop - base] = b"\x01" * len(data)
                    self.uc.mem_write(start, data)
            original, known = self.pages[base]
            offset = cursor - base
            stop = end - base
            while offset < stop:
                if known[offset]:
                    offset += 1
                    continue
                missing_end = offset + 1
                while missing_end < stop and not known[missing_end]:
                    missing_end += 1
                data = self.capture.read(base + offset, missing_end - offset)
                original[offset:missing_end] = data
                known[offset:missing_end] = b"\x01" * len(data)
                self.uc.mem_write(base + offset, data)
                offset = missing_end
            cursor = end

    def read(self, address, size, kind="read"):
        self.ensure(address, size, kind)
        return bytes(self.uc.mem_read(address, size))

    def original(self, address, size):
        self.ensure(address, size)
        result = bytearray()
        while len(result) < size:
            cursor = address + len(result)
            base = cursor & -_PAGE
            count = min(size - len(result), _PAGE - (cursor - base))
            result.extend(self.pages[base][0][cursor - base:cursor - base + count])
        return bytes(result)

    def slot(self, address):
        if address in self.slots:
            return self.slots[address]
        if len(self.slots) >= _MAX_EVENTS:
            raise _Boundary("memory_limit", "Captured stack slots reached their limit.")
        slot = {"address": address, "value": 0, "readable": False}
        self.slots[address] = slot
        self.trace["stack_slots"].append(slot)
        try:
            slot["value"] = int.from_bytes(self.original(address, self.width), "little")
            slot["readable"] = True
        except _Boundary as error:
            if error.status not in {"invalid_read", "invalid_target"}:
                raise
        return slot

    def stack_access(self, address, size, sp):
        if max(0, sp - 128) <= address < min(self.limit, sp + 4096):
            return True
        return any(start <= address < end or address <= start < address + size
                   for start, end in self.stack_windows)


class _Machine:
    def __init__(self, capture, trace, unicorn, x86, capstone, csx):
        self.capture, self.trace = capture, trace
        self.unicorn, self.x86, self.capstone, self.csx = unicorn, x86, capstone, csx
        self.width = trace["pointer_size"]
        self.bits = self.width * 8
        self.mask = (1 << self.bits) - 1
        mode = unicorn.UC_MODE_64 if self.width == 8 else unicorn.UC_MODE_32
        self.uc = unicorn.Uc(unicorn.UC_ARCH_X86, mode)
        self.cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if self.width == 8 else capstone.CS_MODE_32)
        self.cs.detail = True
        self.pc_name, self.sp_name = ("rip", "rsp") if self.width == 8 else ("eip", "esp")
        self.registers = {}
        self.aliases = {}
        self.segment_bases = {}
        self.undefined_flags = set()
        self.memory = _Memory(capture, self.uc, unicorn, self.width, trace)
        self.events = []
        self.event_bytes = 0
        self.event_count = 0
        self.failure = None
        self.instruction = None
        self.uc.hook_add(unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, self._access)
        self.uc.hook_add(unicorn.UC_HOOK_MEM_INVALID, self._invalid)
        self.uc.hook_add(unicorn.UC_HOOK_INTR, self._interrupt)
        self.uc.hook_add(unicorn.UC_HOOK_CODE, self._code)

    def seed(self):
        families = (
            ("rax", "eax", "ax", "al", "ah"), ("rbx", "ebx", "bx", "bl", "bh"),
            ("rcx", "ecx", "cx", "cl", "ch"), ("rdx", "edx", "dx", "dl", "dh"),
            ("rsi", "esi", "si", "sil"), ("rdi", "edi", "di", "dil"),
            ("rbp", "ebp", "bp", "bpl"), ("rsp", "esp", "sp", "spl"),
            ("rip", "eip", "ip"),
        )
        if self.width == 8:
            families += tuple((f"r{i}", f"r{i}d", f"r{i}w", f"r{i}b") for i in range(8, 16))
        for family in families:
            name = family[0 if self.width == 8 else 1]
            value = self.capture.register((name,)) & self.mask
            self.registers[name] = getattr(self.x86, "UC_X86_REG_" + name.upper())
            self.uc.reg_write(self.registers[name], value)
            self.aliases.update((alias, name) for alias in family)
        flags_name = "rflags" if self.width == 8 else "eflags"
        value = self.capture.register((flags_name, "eflags", "rflags")) & 0xFFFFFFFF
        if value & (1 << 17):
            raise _Boundary("unavailable_state", "Virtual-8086 execution needs segment descriptors that are not captured.")
        self.registers[flags_name] = self.x86.UC_X86_REG_EFLAGS
        self.uc.reg_write(self.x86.UC_X86_REG_EFLAGS, value)
        self.aliases.update((name, flags_name) for name in ("eflags", "rflags", "flags"))
        if self.width == 4:
            # Do not silently assume protected-mode selector bases are zero.
            self.segment("cs")
            self.segment("ss")

    def linux_flat_segment(self, name):
        if name not in {"cs", "ss", "ds", "es"} or "linux" not in self.capture.snapshot.target_triple.lower():
            raise _Boundary("unavailable_state", f"The {name} segment base is unavailable.")
        cs = self.capture.register(("cs",))
        ss = self.capture.register(("ss",))
        if (cs, ss) not in {(0x23, 0x2B), (0x73, 0x7B)}:
            raise _Boundary("unavailable_state", f"Custom/LDT selectors CS={cs:#x}, SS={ss:#x} need captured descriptor state.")
        if name in {"ds", "es"} and self.capture.register((name,)) != ss:
            raise _Boundary("unavailable_state", f"The {name} selector is not the captured Linux flat-user data selector.")
        note = f"Using Linux flat-user ABI for captured CS={cs:#x}, SS={ss:#x}; custom and TLS selectors are not inferred."
        if note not in self.capture.notes:
            self.capture.notes.append(note)
        return 0

    def segment(self, name):
        if self.width == 8 and name in {"cs", "ds", "es", "ss"}:
            return  # Long mode architecturally ignores these bases.
        if name in self.segment_bases:
            return
        try:
            value = self.capture.register((name + "_base", name + "base")) & self.mask
        except _Boundary as error:
            if self.width != 4 or error.status != "unavailable_state":
                raise
            value = self.linux_flat_segment(name)
        if self.width == 4:
            if value != 0 or name in {"fs", "gs"}:
                raise _Boundary("unavailable_state", f"32-bit {name} requires an uncaptured segment descriptor.")
        else:
            register = getattr(self.x86, "UC_X86_REG_" + name.upper() + "_BASE")
            self.uc.reg_write(register, value)
            self.registers[name + "_base"] = register
            self.trace["initial_registers"].append({"name": name + "_base", "value": value})
        self.segment_bases[name] = value

    def values(self):
        return {name: int(self.uc.reg_read(register)) & ((1 << 64) - 1)
                for name, register in self.registers.items()}

    def pc(self):
        return int(self.uc.reg_read(self.registers[self.pc_name]))

    def sp(self):
        return int(self.uc.reg_read(self.registers[self.sp_name]))

    def decode(self):
        address = self.pc()
        raw = bytearray()
        for offset in range(15):
            raw.extend(self.memory.read(address + offset, 1, "execute"))
            instruction = next(self.cs.disasm(bytes(raw), address, count=1), None)
            if instruction is not None:
                return instruction
        raise _Boundary("unsupported_instruction", f"Capstone could not decode the instruction at {address:#x}.")

    def flow(self, instruction):
        mnemonic = instruction.mnemonic.split()[-1]
        if mnemonic in {"syscall", "sysenter", "sysret", "sysexit", "int", "int1", "int3", "into"}:
            return "syscall"
        if mnemonic in {"hlt", "ud0", "ud1", "ud2", "iret", "iretd", "iretq", "retf", "retfq", "lcall", "ljmp"}:
            return "stop"
        if instruction.group(self.capstone.CS_GRP_RET):
            return "return"
        if instruction.group(self.capstone.CS_GRP_CALL):
            return "call"
        if instruction.group(self.capstone.CS_GRP_JUMP):
            return "jump" if mnemonic == "jmp" else "branch"
        return "normal"

    def required_state(self, instruction):
        mnemonic = instruction.mnemonic.split()[-1]
        if instruction.group(self.capstone.CS_GRP_PRIVILEGE) or mnemonic in {
            # Restoring IF/IOPL depends on privilege state, not just EFLAGS.
            "popf", "popfd", "popfq",
            "cpuid", "rdtsc", "rdtscp", "rdpmc", "rdrand", "rdseed", "xgetbv", "xsetbv",
            "xbegin", "xend", "xabort", "xtest", "monitor", "mwait", "rdpid",
            "rdfsbase", "rdgsbase", "wrfsbase", "wrgsbase", "swapgs",
            "rdpkru", "wrpkru", "xsave", "xsave64", "xsavec", "xsaveopt", "xsaves",
            "xrstor", "xrstor64", "xrstors", "fxsave", "fxsave64", "fxrstor", "fxrstor64",
            "bsf", "bsr",
        }:
            raise _Boundary("unsupported_instruction", f"{instruction.mnemonic} needs machine state outside the captured thread.")
        for group in instruction.groups:
            if instruction.group_name(group).lower().startswith(("fpu", "mmx", "sse", "avx", "3dnow")):
                raise _Boundary("unavailable_state", f"{instruction.mnemonic} requires uncaptured floating-point/vector state.")
        reads, writes = instruction.regs_access()
        for register in set(reads) | set(writes):
            name = instruction.reg_name(register)
            if name in self.aliases:
                continue
            if name in {"cs", "ds", "es", "ss", "fs", "gs"} and register not in writes:
                self.segment(name)
                continue
            raise _Boundary("unavailable_state", f"{instruction.mnemonic} requires uncaptured register {name}.")
        # A selector used as an integer is not its base. Even in long mode the
        # ignored DS/SS base does not make an unread selector safe to expose.
        for operand in instruction.operands:
            if (operand.type == self.csx.X86_OP_REG
                    and instruction.reg_name(operand.reg) in {"cs", "ds", "es", "ss", "fs", "gs"}):
                raise _Boundary("unavailable_state", "Explicit segment-selector operands require captured descriptor state.")
        for operand in instruction.operands:
            if operand.type == self.csx.X86_OP_MEM:
                name = instruction.reg_name(operand.mem.segment)
                if name:
                    self.segment(name)
                elif self.width == 4:
                    base = instruction.reg_name(operand.mem.base)
                    self.segment("ss" if base in {"ebp", "esp", "bp", "sp"} else "ds")
        for flag in self.undefined_flags:
            dependencies = (getattr(self.csx, "X86_EFLAGS_TEST_" + flag, 0)
                            | getattr(self.csx, "X86_EFLAGS_PRIOR_" + flag, 0))
            if instruction.eflags & dependencies:
                raise _Boundary("unavailable_state", f"{instruction.mnemonic} reads {flag}, undefined by an earlier instruction.")
        if self.undefined_flags and mnemonic in {"pushf", "pushfd", "pushfq", "lahf"}:
            raise _Boundary("unavailable_state", "The instruction exposes flags left undefined by an earlier instruction.")

    def _fail(self, error):
        if self.failure is None:
            self.failure = error
        self.uc.emu_stop()

    def _code(self, uc, address, size, _):
        try:
            self.capture.check()
            if address != self.instruction.address or size != self.instruction.size:
                raise _Boundary("unsupported_instruction", "Unicorn and Capstone disagree on the next instruction boundary.")
            self.memory.ensure(address, size, "execute")
        except _Boundary as error:
            self._fail(error)

    def _interrupt(self, uc, number, _):
        self._fail(_Boundary("stop", f"CPU exception/interrupt {number} stopped simulated execution."))

    def _invalid(self, uc, access, address, size, value, _):
        u = self.unicorn
        kind = "execute" if access in {u.UC_MEM_FETCH_UNMAPPED, u.UC_MEM_FETCH_PROT} else (
            "write" if access in {u.UC_MEM_WRITE_UNMAPPED, u.UC_MEM_WRITE_PROT} else "read")
        if kind == "execute" and self.pc() != self.instruction.address:
            # Some Unicorn versions fetch a branch destination before honoring
            # count=1. The branch already retired: validate its destination on
            # the next trace iteration, not by rolling back the consumed return.
            self.deferred_fetch = True
            uc.emu_stop()
            return False
        try:
            self.memory.ensure(address, size, kind)
            return True
        except _Boundary as error:
            self._fail(error)
            return False

    def _access(self, uc, access, address, size, value, _):
        try:
            write = access == self.unicorn.UC_MEM_WRITE
            self.memory.ensure(address, size, "write" if write else "read")
            before = bytes(uc.mem_read(address, size))
            self.event_bytes += len(before) * 2
            self.event_count += 1
            if self.event_bytes > _MAX_BYTES or self.event_count > _MAX_EVENTS:
                raise _Boundary("memory_limit", "Instruction memory effects reached their bounded trace limit.")
            stack = self.memory.stack_access(address, size, self.sp())
            # Unicorn's write-hook value is truncated for wide stores. Read the
            # actual result after execution instead of fabricating its bytes.
            self.events.append({"address": address, "before": before, "after": before,
                                "write": write, "stack": stack})
            if stack:
                for offset in range(0, size, self.width):
                    self.memory.slot(address + offset)
        except _Boundary as error:
            self._fail(error)

    def step(self, instruction, flow):
        self.instruction = instruction
        self.required_state(instruction)
        before = self.values()
        context = self.uc.context_save()
        self.events = []
        self.failure = None
        self.deferred_fetch = False
        repeat = any(prefix in {0xF2, 0xF3} for prefix in instruction.prefix) and (
            instruction.mnemonic.startswith(("rep ", "repe ", "repne ")))
        try:
            execution_deadline = min(self.capture.deadline, time.monotonic() + 0.05)
            iterations = 0
            while True:
                self.capture.check()
                iterations += 1
                if iterations > _MAX_EVENTS:
                    raise _Boundary("memory_limit", "Repeated instruction reached its iteration limit.")
                if time.monotonic() >= execution_deadline:
                    raise _Boundary("timeout", "A single instruction reached its 50 ms execution limit.")
                micros = max(1, int((execution_deadline - time.monotonic()) * 1000000))
                event_start = len(self.events)
                try:
                    self.uc.emu_start(instruction.address, 0, timeout=micros, count=1)
                except self.unicorn.UcError:
                    if not self.deferred_fetch:
                        raise
                if self.failure is not None:
                    raise self.failure
                if self.uc.query(self.unicorn.UC_QUERY_TIMEOUT):
                    raise _Boundary("timeout", "A single instruction reached its 50 ms execution limit.")
                # Finalize each REP iteration before another can overwrite the
                # same byte. This preserves reversible, ordered memory effects.
                for index in range(event_start, len(self.events)):
                    event = self.events[index]
                    if event["write"]:
                        event["after"] = bytes(self.uc.mem_read(event["address"], len(event["before"])))
                if not repeat or self.pc() != instruction.address:
                    break
            self.capture.check(live=True)
        except Exception as error:
            for event in reversed(self.events):
                if event["write"]:
                    self.uc.mem_write(event["address"], event["before"])
            self.uc.context_restore(context)
            if isinstance(error, _Boundary):
                raise
            if self.failure is not None:
                raise self.failure from error
            raise _Boundary("unsupported_instruction", f"Unicorn could not execute {instruction.mnemonic}: {error}") from error
        after = self.values()
        for flag in ("CF", "PF", "AF", "ZF", "SF", "OF", "DF", "IF", "TF", "NT", "RF", "AC"):
            if instruction.eflags & getattr(self.csx, "X86_EFLAGS_UNDEFINED_" + flag, 0):
                self.undefined_flags.add(flag)
            elif any(instruction.eflags & getattr(self.csx, "X86_EFLAGS_" + effect + "_" + flag, 0)
                     for effect in ("MODIFY", "RESET", "SET")):
                self.undefined_flags.discard(flag)
        return {
            "address": instruction.address, "next_address": self.pc(),
            "sp_before": before[self.sp_name], "sp_after": after[self.sp_name],
            "bytes": bytes(instruction.bytes),
            "text": f"{instruction.mnemonic} {instruction.op_str}".rstrip(),
            "flow": flow, "completed": True,
            "register_changes": [{"name": name, "before": value, "after": after[name]}
                                 for name, value in before.items() if value != after[name]],
            "memory_accesses": self.events,
        }


def trace_stack(dbg, stack_address, *, stack_bytes=512, max_instructions=256,
                max_nodes=64, timeout=5.0, cancelled=None):
    """Trace a synthetic initial return without writing or resuming the target.

    A returned status describes the boundary encountered, never exploit success.
    ``initial_registers`` is the state after the synthetic return. Incomplete
    instructions have no committed effects, so all completed effects are exactly
    reversible. Unavailable dependencies raise ImportError; malformed requests
    raise ValueError. Capture/execution boundaries return useful partial traces.
    """
    for name, value, maximum in (("stack_bytes", stack_bytes, 65536),
                                 ("max_instructions", max_instructions, 10000),
                                 ("max_nodes", max_nodes, 4096)):
        if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
            raise ValueError(f"{name} must be an integer in [1, {maximum}]")
    if not isinstance(stack_address, int) or isinstance(stack_address, bool) or not 0 <= stack_address < 1 << 64:
        raise ValueError("stack_address must be an unsigned 64-bit integer")
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 60:
        raise ValueError("timeout must be finite and in (0, 60] seconds")
    started = time.monotonic()
    snapshot = dbg.snapshot()
    trace = {
        "generation": snapshot.generation, "stop_revision": snapshot.stop_revision,
        "thread_id": snapshot.thread_id, "source_pc": snapshot.pc, "source_sp": snapshot.sp,
        "stack_address": stack_address, "pointer_size": snapshot.address_byte_size,
        "architecture": snapshot.architecture, "initial_registers": [],
        "stack_slots": [], "nodes": [], "status": "unavailable_state", "message": "",
    }
    capture = _Capture(dbg, snapshot, started + timeout, cancelled)
    try:
        capture.check(live=True)
        if snapshot.state != "stopped":
            raise _Boundary("unavailable_state", "ROP capture requires a stopped target.")
        architecture = snapshot.architecture.lower().split("-")[0]
        expected = 8 if architecture in {"x86_64", "amd64", "x86_64h"} else (
            4 if architecture in {"x86", "i386", "i486", "i586", "i686"} else 0)
        if not expected or snapshot.address_byte_size != expected or snapshot.byte_order != "little":
            raise _Boundary("unsupported_architecture", "Stack-return entry is supported only for little-endian x86/x86-64 targets.")
        for thread in snapshot.threads:
            for frame in thread.frames:
                if frame.selected and frame.index != 0:
                    raise _Boundary("unavailable_state", "Select the innermost stopped frame before capturing live machine state.")
        if stack_address + max(expected, stack_bytes) > 1 << (expected * 8):
            raise ValueError("The requested stack window exceeds the target address space")
        try:
            import unicorn
            from unicorn import x86_const
            import capstone
            from capstone import x86_const as csx
        except ImportError as error:
            raise ImportError(_BOOTSTRAP_HINT) from error
        capture.check()
        if not hasattr(snapshot, "memory_regions"):
            raise _Boundary("unavailable_state", "The debugger snapshot does not expose live memory permissions.")
        machine = _Machine(capture, trace, unicorn, x86_const, capstone, csx)
        machine.seed()
        memory = machine.memory
        memory.stack_windows.append((stack_address, stack_address + max(expected, stack_bytes)))
        first = memory.slot(stack_address)
        if not first["readable"]:
            raise _Boundary("invalid_read", f"Initial return slot at {stack_address:#x} is unreadable.")
        machine.uc.reg_write(machine.registers[machine.pc_name], first["value"])
        machine.uc.reg_write(machine.registers[machine.sp_name], (stack_address + expected) & machine.mask)
        trace["initial_registers"] = [{"name": name, "value": value} for name, value in machine.values().items()]
        for offset in range(expected, stack_bytes - expected + 1, expected):
            memory.slot(stack_address + offset)
        next_slot = stack_address
        new_node = True
        count = 0
        while True:
            capture.check(live=True)
            if count >= max_instructions:
                raise _Boundary("instruction_limit", f"Stopped after {count} instructions (instruction limit).")
            if new_node:
                if len(trace["nodes"]) >= max_nodes:
                    raise _Boundary("node_limit", f"Stopped after {len(trace['nodes'])} gadget/control-flow occurrences (node limit).")
                node = {"entry_address": machine.pc(), "entry_sp": machine.sp(),
                        "stack_slot": next_slot, "instructions": []}
                trace["nodes"].append(node)
                new_node = False
            instruction = machine.decode()
            flow = machine.flow(instruction)
            row = {
                "address": instruction.address, "next_address": instruction.address,
                "sp_before": machine.sp(), "sp_after": machine.sp(),
                "bytes": bytes(instruction.bytes),
                "text": f"{instruction.mnemonic} {instruction.op_str}".rstrip(),
                "flow": flow, "completed": False, "register_changes": [], "memory_accesses": [],
            }
            node["instructions"].append(row)
            if flow == "syscall":
                raise _Boundary("syscall", f"Stopped before {row['text']} at {instruction.address:#x}; no system call was executed.")
            if flow == "stop":
                raise _Boundary("stop", f"Stopped before {row['text']} at {instruction.address:#x}; architectural boundary needs uncaptured state.")
            before_sp = machine.sp()
            if flow == "return":
                memory.slot(before_sp)
            row.update(machine.step(instruction, flow))
            count += 1
            if flow in {"return", "call", "jump", "branch"}:
                new_node = True
                next_slot = before_sp if flow == "return" else None
    except _Boundary as error:
        trace["status"] = error.status
        trace["message"] = " ".join((str(error), *capture.notes))
    return trace
