"""Concrete ROP regression, run by the native symbolic test wrapper.

MYDBG_SYMBOLIC_TARGET names the tests/debuggees/rop_trace.c executable. The
fixture constructs chains before rop_trace_ready; the script never executes them
in the live process. Optional Unicorn and Capstone must be importable.
"""

from __future__ import annotations

import os


class _SnapshotView:
    def __init__(self, snapshot, excluded):
        self._snapshot = snapshot
        self.registers = [r for r in snapshot.registers if r.name.lower() not in excluded]

    def __getattr__(self, name):
        return getattr(self._snapshot, name)


class _ReadOnly:
    """A real debugger capture surface with no mutation methods at all."""

    def __init__(self, dbg, excluded=()):
        self._dbg = dbg
        self.excluded = set(excluded)
        self.reads = 0
        self.snapshots = 0

    def snapshot(self):
        self.snapshots += 1
        return _SnapshotView(self._dbg.snapshot(), self.excluded)

    def read_memory(self, address, size, timeout=10.0):
        self.reads += 1
        return self._dbg.read_memory(address, size, timeout=timeout)

    def read_register(self, name, timeout=10.0):
        if name in self.excluded:
            raise RuntimeError(f"register {name} intentionally unavailable")
        return self._dbg.read_register(name, timeout=timeout)


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _address(dbg, symbol):
    result = dbg.evaluate("&" + symbol)
    if result.numeric_value is None:
        raise RuntimeError(f"could not resolve fixture symbol {symbol}: {result.value}")
    return result.numeric_value


def _rows(trace):
    return [instruction for node in trace["nodes"] for instruction in node["instructions"]]


def _replay(trace):
    """Exercise the consumer contract: apply every delta, then reverse it."""
    registers = {r["name"]: r["value"] for r in trace["initial_registers"]}
    initial_registers = dict(registers)
    memory = {}
    initial_memory = {}
    for row in _rows(trace):
        _require(isinstance(row["bytes"], bytes), "instruction bytes lost their byte representation")
        _require(row["flow"] in {"normal", "return", "call", "jump", "branch", "syscall", "stop"},
                 "unknown instruction flow")
        if not row["completed"]:
            _require(not row["register_changes"] and not row["memory_accesses"],
                     "incomplete instruction committed effects")
            continue
        _require(registers["rip"] == row["address"] and registers["rsp"] == row["sp_before"],
                 "instruction does not begin at the simulated cursor")
        for change in row["register_changes"]:
            _require(registers[change["name"]] == change["before"], "register delta has an incorrect before value")
            registers[change["name"]] = change["after"]
        _require(registers["rip"] == row["next_address"] and registers["rsp"] == row["sp_after"],
                 "instruction does not end at the simulated cursor")
        for access in row["memory_accesses"]:
            _require(isinstance(access["before"], bytes) and isinstance(access["after"], bytes),
                     "memory effects are not byte arrays")
            _require(len(access["before"]) == len(access["after"]), "memory effect changed its extent")
            for offset, value in enumerate(access["before"]):
                address = access["address"] + offset
                if address not in memory:
                    memory[address] = value
                    initial_memory[address] = value
                _require(memory[address] == value, "memory access did not observe previous simulated writes")
            if access["write"]:
                for offset, value in enumerate(access["after"]):
                    memory[access["address"] + offset] = value
            else:
                _require(access["before"] == access["after"], "read-only access changed bytes")
    final_registers = dict(registers)
    final_memory = dict(memory)
    for row in reversed(_rows(trace)):
        for access in reversed(row["memory_accesses"]):
            if access["write"]:
                for offset, value in enumerate(access["after"]):
                    _require(memory[access["address"] + offset] == value, "reverse write saw wrong after bytes")
                for offset, value in enumerate(access["before"]):
                    memory[access["address"] + offset] = value
        for change in reversed(row["register_changes"]):
            _require(registers[change["name"]] == change["after"], "reverse register saw wrong after value")
            registers[change["name"]] = change["before"]
    _require(registers == initial_registers, "reverse stepping did not restore initial registers")
    _require(memory == initial_memory, "reverse stepping did not restore initial memory")
    return final_registers, final_memory


def run(dbg):
    from mydbg.rop_trace import trace_stack

    process = dbg.launch([os.environ["MYDBG_SYMBOLIC_TARGET"]], stop_at="main", timeout=30)
    dbg.set_breakpoint("rop_trace_ready")
    stop = dbg.continue_and_wait(timeout=30)
    _require(stop.state == "stopped", "fixture did not stop after chain initialization")
    symbols = (
        "rop_trace_chain", "rop_trace_value", "rop_trace_pivot_stack", "rop_trace_add7",
        "rop_trace_pivot", "rop_trace_syscall", "rop_trace_pop_rax", "rop_trace_invalid_target",
        "rop_trace_invalid_read", "rop_trace_invalid_write", "rop_trace_nx", "rop_trace_loop_stack",
        "rop_trace_control_stack", "rop_trace_tls_stack", "rop_trace_undefined_stack",
        "rop_trace_partial_stack", "rop_trace_rep_stack", "rop_trace_rep_source",
        "rop_trace_rep_destination", "rop_trace_loop", "rop_trace_flags_stack",
    )
    addresses = {name: _address(dbg, name) for name in symbols}
    chain = addresses["rop_trace_chain"]
    pivot_stack = addresses["rop_trace_pivot_stack"]
    value = addresses["rop_trace_value"]
    original = {
        (chain, 19 * 8): bytes(dbg.read_memory(chain, 19 * 8)),
        (pivot_stack, 16): bytes(dbg.read_memory(pivot_stack, 16)),
        (value, 8): bytes(dbg.read_memory(value, 8)),
        (addresses["rop_trace_rep_destination"], 8): bytes(dbg.read_memory(addresses["rop_trace_rep_destination"], 8)),
        (addresses["rop_trace_add7"], 5): bytes(dbg.read_memory(addresses["rop_trace_add7"], 5)),
    }
    baseline = dbg.snapshot()
    baseline_registers = [(r.name, r.value) for r in baseline.registers]
    reader = _ReadOnly(dbg)
    trace = trace_stack(reader, chain, stack_bytes=19 * 8, timeout=30)
    _require(trace["status"] == "syscall", f"main chain stopped early: {trace['status']}: {trace['message']}")
    _require(trace["generation"] == baseline.generation and trace["stop_revision"] == baseline.stop_revision
             and trace["thread_id"] == baseline.thread_id, "trace has incorrect stop provenance")
    _require(trace["source_pc"] == baseline.pc and trace["source_sp"] == baseline.sp, "source registers changed")
    initial = {r["name"]: r["value"] for r in trace["initial_registers"]}
    _require(initial["rip"] == addresses["rop_trace_pop_rax"] and initial["rsp"] == chain + 8,
             "initial return was not applied exactly once")
    _require(trace["nodes"][0]["stack_slot"] == chain, "initial return lost its stack-slot provenance")
    final, memory = _replay(trace)
    _require(final["rax"] == 26, "register arithmetic or simulated write/read propagation is incorrect")
    _require(final["rip"] == addresses["rop_trace_syscall"] and final["rsp"] == pivot_stack + 16,
             "pivoted chain did not stop before its system call")
    _require(bytes(memory[value + i] for i in range(8)) == (12).to_bytes(8, "little"),
             "the simulated data write was lost")
    occurrences = [n for n in trace["nodes"] if n["entry_address"] == addresses["rop_trace_add7"]]
    _require([n["stack_slot"] for n in occurrences] == [chain + 2 * 8, chain + 9 * 8, pivot_stack],
             "repeated gadgets collapsed or pivot return provenance is incorrect")
    slots = {s["address"]: s for s in trace["stack_slots"]}
    _require(slots[chain + 17 * 8]["value"] == 1, "initial stack view was overwritten with simulated future bytes")
    pivot_nodes = [n for n in trace["nodes"] if n["entry_address"] == addresses["rop_trace_pivot"]]
    _require(len(pivot_nodes) == 1 and pivot_nodes[0]["stack_slot"] == chain + 17 * 8,
             "future return did not use the simulated stack write")
    targets = {n["stack_slot"] for n in trace["nodes"]}
    _require(chain + 8 not in targets and chain + 13 * 8 not in targets,
             "pop data, including a gadget address, was misclassified as a return target")
    _require(any(a["address"] == chain + 13 * 8 and a["stack"] and not a["write"]
                 for row in _rows(trace) for a in row["memory_accesses"]),
             "data consumption is not visible in the instruction effects")
    _require(not _rows(trace)[-1]["completed"], "syscall boundary executed in the simulator")

    for symbol, status in (("rop_trace_invalid_target", "invalid_target"),
                           ("rop_trace_nx", "invalid_target"),
                           ("rop_trace_invalid_read", "invalid_read"),
                           ("rop_trace_partial_stack", "invalid_read"),
                           ("rop_trace_invalid_write", "invalid_write")):
        boundary = trace_stack(reader, addresses[symbol], stack_bytes=8, timeout=30)
        _require(boundary["status"] == status,
                 f"{symbol}: expected {status}, got {boundary['status']}: {boundary['message']}")
        _replay(boundary)
        if status in {"invalid_read", "invalid_write"}:
            _require(any(row["completed"] for row in _rows(boundary)), "fault discarded the useful partial trace")
            _require(not _rows(boundary)[-1]["completed"], "faulting instruction committed partial effects")

    control = trace_stack(reader, addresses["rop_trace_control_stack"], stack_bytes=8, timeout=30)
    _require(control["status"] == "syscall", f"control-flow chain failed: {control['message']}")
    final, _ = _replay(control)
    _require(final["rax"] == 7, "call/return execution produced the wrong register state")
    _require({"branch", "call", "return", "jump"} <= {row["flow"] for row in _rows(control)},
             "control-flow boundaries were not represented")
    _require(any(n["entry_address"] == addresses["rop_trace_add7"] and n["stack_slot"] is None
                 for n in control["nodes"]), "call target was mislabeled as a stack-return target")

    repeated = trace_stack(reader, addresses["rop_trace_rep_stack"], stack_bytes=48, timeout=30)
    _require(repeated["status"] == "syscall", f"REP chain failed: {repeated['message']}")
    final, memory = _replay(repeated)
    destination = addresses["rop_trace_rep_destination"]
    _require(final["rcx"] == 0 and bytes(memory[destination + i] for i in range(8)) == b"\x81\x02\x03\x04\x05\x06\x07\xfe",
             "REP was reported complete before its concrete memory effects finished")

    for excluded in (("rax",), ("rflags", "eflags")):
        unavailable = trace_stack(_ReadOnly(dbg, excluded), chain, stack_bytes=8, timeout=30)
        _require(unavailable["status"] == "unavailable_state" and not unavailable["nodes"],
                 "missing GPR/flags silently inherited Unicorn defaults")
    tls = trace_stack(_ReadOnly(dbg, ("fs_base", "fsbase")), addresses["rop_trace_tls_stack"], stack_bytes=8, timeout=30)
    _require(tls["status"] == "unavailable_state" and not _rows(tls)[-1]["completed"],
             "FS memory read silently used an unknown segment base")
    undefined = trace_stack(reader, addresses["rop_trace_undefined_stack"], stack_bytes=8, timeout=30)
    _require(undefined["status"] == "unavailable_state", "branch silently used an architecturally undefined flag")
    flags = trace_stack(reader, addresses["rop_trace_flags_stack"], stack_bytes=24, timeout=30)
    _require(flags["status"] == "unsupported_instruction" and not _rows(flags)[-1]["completed"],
             "privilege-sensitive flags restoration used uncaptured CPL/IOPL state")

    instruction_bound = trace_stack(reader, chain, stack_bytes=8, max_instructions=3, timeout=30)
    _require(instruction_bound["status"] == "instruction_limit"
             and sum(row["completed"] for row in _rows(instruction_bound)) == 3,
             "instruction limit is not exact")
    node_bound = trace_stack(reader, addresses["rop_trace_loop_stack"], stack_bytes=8, max_nodes=2, timeout=30)
    _require(node_bound["status"] == "node_limit" and len(node_bound["nodes"]) == 2
             and all(n["entry_address"] == addresses["rop_trace_loop"] for n in node_bound["nodes"]),
             "loop occurrence/node bound is not exact")
    cancelled = trace_stack(reader, chain, stack_bytes=8, timeout=30, cancelled=lambda: True)
    _require(cancelled["status"] == "cancelled", "cancellation was ignored")
    expired = trace_stack(reader, chain, stack_bytes=8, timeout=1e-9)
    _require(expired["status"] == "timeout", "wall-clock bound was ignored")
    cancellation_reader = _ReadOnly(dbg)
    interrupted = trace_stack(cancellation_reader, addresses["rop_trace_loop_stack"], stack_bytes=8,
                              max_nodes=4096, max_instructions=10000, timeout=30,
                              cancelled=lambda: cancellation_reader.snapshots > 40)
    _require(interrupted["status"] == "cancelled" and any(row["completed"] for row in _rows(interrupted)),
             "bounded mid-trace cancellation did not preserve completed instructions")
    _replay(interrupted)

    for (address, size), data in original.items():
        _require(bytes(dbg.read_memory(address, size)) == data, "analysis mutated live memory")
    after = dbg.snapshot()
    _require(after.state == "stopped" and after.generation == baseline.generation
             and after.stop_revision == baseline.stop_revision and after.thread_id == baseline.thread_id
             and after.pc == baseline.pc and after.sp == baseline.sp,
             "analysis stepped/resumed or changed the live stop")
    _require([(r.name, r.value) for r in after.registers] == baseline_registers, "analysis mutated live registers")
    dbg.terminate(timeout=30)
    del process
    print("rop-trace-ok")
