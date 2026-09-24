import os
import sys


def _script_debug_probe():
    token = 0x43544621
    return token


def run(dbg):
    probe = _script_debug_probe()
    if probe != 0x43544621:
        raise RuntimeError("Python script stepping corrupted the probe value")

    mode = os.environ["MYDBG_CROSS_MODE"]
    arch_name = os.environ["MYDBG_CROSS_ARCH"]
    executable = os.environ["MYDBG_CROSS_EXECUTABLE"]
    definition = _architecture_definition(arch_name)
    deficiencies = []

    print(f"python-cross-arch-stdout={arch_name}")
    print(f"python-cross-arch-stderr={arch_name}", file=sys.stderr)

    if mode == "native":
        loaded = dbg.load(executable, timeout=15)
        _require(loaded.state == "target loaded", "load did not publish target-loaded state")
        _require(
            os.path.realpath(loaded.target_path) == os.path.realpath(executable),
            "loaded snapshot lost the executable path",
        )
        process = dbg.launch(
            [executable, os.environ["MYDBG_CROSS_SEED"]],
            stop_at="entry",
            cwd=os.path.dirname(executable),
            timeout=15,
        )
        _require(process is not None, "native launch did not return a process handle")
    elif mode == "connected":
        _binding(
            dbg,
            "connect_remote",
            deficiencies,
            "Debugger.connect_remote(executable, endpoint, mode='qemu-user', timeout=...) -> Process",
        )
        if dbg.snapshot().state != "stopped":
            process = dbg.connect_remote(
                executable,
                os.environ["MYDBG_CROSS_ENDPOINT"],
                mode="qemu-user",
                timeout=20,
            )
            _require(process is not None, "remote connect did not return a process handle")
    else:
        raise RuntimeError(f"unknown cross-architecture mode: {mode}")

    initial = dbg.snapshot()
    _require(initial.state == "stopped", f"debugger was not stopped: {initial.state}")
    _require(initial.generation > 0, "debug session generation was not published")
    _require(initial.stop_revision > 0, "initial stop revision was not published")
    _require(initial.process_id > 0, "process id was not published")
    _require(initial.thread_id > 0, "selected thread id was not published")
    _require(initial.pc > 0 and initial.sp > 0, "PC or SP was not published")
    _check_snapshot_metadata(initial, definition, mode, executable, deficiencies)
    if mode == "connected":
        before_restart = dbg.snapshot()
        try:
            dbg.restart(timeout=5)
        except RuntimeError as error:
            _require(
                str(error)
                == "restart is unavailable for QEMU-user sessions; "
                "the active remote session is unchanged",
                f"remote restart returned an imprecise diagnostic: {error}",
            )
        else:
            raise RuntimeError("remote restart unexpectedly succeeded")
        after_restart = dbg.snapshot()
        _require(after_restart.state == "stopped", "remote restart destroyed the stopped session")
        _require(
            (
                after_restart.generation,
                after_restart.stop_revision,
                after_restart.process_id,
                after_restart.thread_id,
                after_restart.target_path,
                after_restart.pc,
                after_restart.sp,
            )
            == (
                before_restart.generation,
                before_restart.stop_revision,
                before_restart.process_id,
                before_restart.thread_id,
                before_restart.target_path,
                before_restart.pc,
                before_restart.sp,
            ),
            "remote restart mutated the active session",
        )
    _check_threads(initial)

    lifecycle_failure_id = dbg.set_breakpoint("crackme_failure", timeout=10)
    lifecycle_failure = _find_breakpoint(
        dbg.list_breakpoints(), lifecycle_failure_id
    )
    _require(lifecycle_failure.enabled, "new failure breakpoint was disabled")
    _require(lifecycle_failure.addresses, "failure breakpoint did not resolve")
    dbg.enable_breakpoint(lifecycle_failure_id, False, timeout=10)
    _require(
        not _find_breakpoint(
            dbg.list_breakpoints(), lifecycle_failure_id
        ).enabled,
        "breakpoint disable was not reflected",
    )
    dbg.enable_breakpoint(lifecycle_failure_id, True, timeout=10)
    _require(
        _find_breakpoint(
            dbg.list_breakpoints(), lifecycle_failure_id
        ).enabled,
        "breakpoint enable was not reflected",
    )
    dbg.remove_breakpoint(lifecycle_failure_id, timeout=10)
    _require(
        all(item.id != lifecycle_failure_id for item in dbg.list_breakpoints()),
        "removed breakpoint remained visible",
    )

    success_path = definition["success_path"]
    entry_symbol, verify_symbol, mix_symbol, checkpoint_symbol, success_symbol = (
        success_path
    )
    challenge_breakpoints = {}
    for symbol in success_path + ("crackme_failure",):
        breakpoint_id = dbg.set_breakpoint(symbol, timeout=10)
        breakpoint = _find_breakpoint(dbg.list_breakpoints(), breakpoint_id)
        _require(breakpoint.enabled, f"{symbol} breakpoint was disabled")
        _require(breakpoint.addresses, f"{symbol} breakpoint did not resolve")
        challenge_breakpoints[symbol] = {
            "id": breakpoint_id,
            "addresses": tuple(breakpoint.addresses),
        }

    verify_address = challenge_breakpoints[verify_symbol]["addresses"][0]
    before_entry = dbg.snapshot()
    entry = dbg.continue_and_wait(timeout=20)
    _require_new_stopped_snapshot(before_entry, entry, f"continue to {entry_symbol}")
    _require_breakpoint_stop(
        entry, entry_symbol, challenge_breakpoints[entry_symbol]
    )
    _require_breakpoint_not_hit(
        entry,
        "crackme_failure",
        challenge_breakpoints["crackme_failure"],
        f"while reaching {entry_symbol}",
    )

    reached_prologues = [entry_symbol]
    challenge_state = entry
    instruction_steps = 0
    for expected_symbol in (verify_symbol, mix_symbol, checkpoint_symbol):
        challenge_state, instruction_steps = _step_to_breakpoint(
            dbg,
            challenge_state,
            expected_symbol,
            challenge_breakpoints,
            definition,
            instruction_steps,
        )
        reached_prologues.append(expected_symbol)

    checkpoint = challenge_state
    _check_threads(checkpoint)
    _check_snapshot_metadata(checkpoint, definition, mode, executable, deficiencies)

    dbg.select_thread(checkpoint.thread_id, timeout=10)
    dbg.select_frame(checkpoint.thread_id, 0, timeout=10)
    checkpoint = dbg.snapshot()

    pc_value = dbg.read_register(definition["pc_register"], timeout=10)
    sp_value = dbg.read_register(definition["sp_register"], timeout=10)
    _require(pc_value == checkpoint.pc, "native PC register disagreed with the snapshot")
    _require(sp_value == checkpoint.sp, "native SP register disagreed with the snapshot")
    general_value = dbg.read_register(definition["general_register"], timeout=10)
    dbg.write_register(definition["general_register"], general_value, timeout=10)
    _require(
        dbg.read_register(definition["general_register"], timeout=10) == general_value,
        "native general register did not round trip",
    )
    dbg.write_register(definition["pc_register"], pc_value, timeout=10)
    _require(
        dbg.read_register(definition["pc_register"], timeout=10) == pc_value,
        "native PC register did not round trip",
    )

    evaluated_pc = dbg.evaluate(f"${definition['pc_register']}", timeout=10)
    _require(evaluated_pc.numeric_value == pc_value, "register expression was not numeric")

    stack_bytes = dbg.read_memory(sp_value, definition["pointer_size"] * 2, timeout=10)
    _require(
        len(stack_bytes) == definition["pointer_size"] * 2,
        "stack memory read returned the wrong byte count",
    )
    replacement = bytes([stack_bytes[0] ^ 0x5A]) + stack_bytes[1:]
    dbg.write_memory(sp_value, replacement, timeout=10)
    _require(
        dbg.read_memory(sp_value, len(replacement), timeout=10) == replacement,
        "stack memory write did not round trip",
    )
    patched = dbg.snapshot()
    _require(
        any(
            patch.address == sp_value and patch.replacement == replacement
            for patch in patched.patches
        ),
        "Python memory write bypassed tracked patches",
    )
    dbg.write_memory(sp_value, stack_bytes, timeout=10)
    _require(
        dbg.read_memory(sp_value, len(stack_bytes), timeout=10) == stack_bytes,
        "restoring stack memory did not round trip",
    )
    _require(
        all(patch.address != sp_value for patch in dbg.snapshot().patches),
        "restored stack patch remained tracked",
    )

    try:
        dbg.read_register("__mydbg_missing_register__", timeout=10)
    except RuntimeError:
        pass
    else:
        raise RuntimeError("missing register unexpectedly produced a value")

    help_result = dbg.execute("help", timeout=10)
    _require(help_result.success, "help command reported failure")
    try:
        dbg.execute("__mydbg_unknown_command__", timeout=10)
    except RuntimeError as error:
        _require(str(error).strip(), "command failure lost its diagnostic")
    else:
        raise RuntimeError("unknown debugger command unexpectedly succeeded")
    disassembly = dbg.execute(f"disasm 0x{verify_address:x}", timeout=10)
    _require(disassembly.success, "disassembly command reported failure")
    _require(disassembly.message.strip(), "disassembly command returned no instructions")
    modules = dbg.execute("modules", timeout=10)
    _require(modules.success and modules.message.strip(), "module command returned no modules")
    backtrace = dbg.execute("backtrace", timeout=10)
    _require(backtrace.success and backtrace.message.strip(), "backtrace command returned no frames")

    _check_disassembly_syntax(dbg, definition, deficiencies)

    dbg.remove_breakpoint(
        challenge_breakpoints[checkpoint_symbol]["id"], timeout=10
    )
    before_step = dbg.snapshot()
    _require(
        instruction_steps < definition["instruction_step_limit"],
        _instruction_bound_message(
            definition, instruction_steps, success_symbol, before_step
        ),
    )
    checkpoint_instruction = _instruction_at_pc(
        before_step, f"leaving {checkpoint_symbol}"
    )
    stepped = _step_once(
        dbg,
        before_step,
        checkpoint_instruction,
        False,
        instruction_steps + 1,
        definition["instruction_step_limit"],
        success_symbol,
    )
    instruction_steps += 1
    _require_breakpoint_not_hit(
        stepped,
        "crackme_failure",
        challenge_breakpoints["crackme_failure"],
        f"while stepping from {checkpoint_symbol} to {success_symbol}",
    )
    _require_no_out_of_order_prologue(
        stepped, success_symbol, challenge_breakpoints
    )

    success, instruction_steps = _step_to_breakpoint(
        dbg,
        stepped,
        success_symbol,
        challenge_breakpoints,
        definition,
        instruction_steps,
    )
    reached_prologues.append(success_symbol)
    _require(
        tuple(reached_prologues) == success_path,
        f"challenge prologues were reached out of order: {reached_prologues}",
    )
    after_success, instruction_steps = _step_through_function(
        dbg,
        success,
        success_symbol,
        challenge_breakpoints,
        definition,
        instruction_steps,
    )
    _require_breakpoint_not_hit(
        after_success,
        "crackme_failure",
        challenge_breakpoints["crackme_failure"],
        f"after stepping through {success_symbol}",
    )
    dbg.remove_breakpoint(
        challenge_breakpoints[success_symbol]["id"], timeout=10
    )

    before_exit = dbg.snapshot()
    exited = dbg.continue_and_wait(timeout=20)
    _require(
        exited.generation == before_exit.generation,
        "final continue changed the debug session generation",
    )
    _require(
        exited.revision > before_exit.revision,
        "final continue did not publish a newer snapshot",
    )
    _require(exited.state == "exited", f"continue did not report exit: {exited.state}")
    _require(
        exited.exit_status == definition["success_exit_status"],
        f"crackme exited with status {exited.exit_status}",
    )
    dbg.terminate(timeout=10)

    if mode == "native":
        restarted_process = dbg.restart(timeout=15)
        _require(restarted_process is not None, "restart did not return a process handle")
        restarted = dbg.snapshot()
        _require(restarted.state == "stopped", "restart did not restore the launch stop policy")
        _require(restarted.generation > exited.generation, "restart did not advance generation")
        dbg.terminate(timeout=15)
        _require(dbg.snapshot().state == "exited", "terminate did not publish process exit")

    if deficiencies:
        raise RuntimeError(
            "missing Python binding contract(s):\n- " + "\n- ".join(deficiencies)
        )
    print(f"python-cross-arch-ok={arch_name}")


def _require_new_stopped_snapshot(previous, current, action):
    _require(
        current.generation == previous.generation,
        f"{action} changed generation from {previous.generation} "
        f"to {current.generation}",
    )
    _require(
        current.revision > previous.revision,
        f"{action} did not publish a newer snapshot revision "
        f"({previous.revision} -> {current.revision})",
    )
    _require(
        current.state == "stopped",
        f"{action} produced {current.state} instead of a stopped snapshot "
        f"(pc=0x{current.pc:x}, error={current.error!r})",
    )
    _require(
        current.stop_revision > previous.stop_revision,
        f"{action} did not publish a newer stopped snapshot "
        f"({previous.stop_revision} -> {current.stop_revision})",
    )


def _require_breakpoint_stop(snapshot, symbol, breakpoint):
    addresses = breakpoint["addresses"]
    _require(
        snapshot.pc in addresses,
        f"{symbol} stopped at 0x{snapshot.pc:x}, outside its breakpoint "
        f"addresses {[hex(address) for address in addresses]}",
    )
    observed = _find_breakpoint(snapshot.breakpoints, breakpoint["id"])
    _require(observed.enabled, f"{symbol} breakpoint was disabled at its prologue")
    _require(
        observed.hit_count > 0,
        f"{symbol} prologue at 0x{snapshot.pc:x} did not record a breakpoint hit",
    )
    _require(
        _snapshot_has_function(snapshot, symbol),
        f"{symbol} prologue stop did not expose a {symbol} stack frame",
    )


def _require_breakpoint_not_hit(
    snapshot, symbol, breakpoint, context
):
    observed = _find_breakpoint(snapshot.breakpoints, breakpoint["id"])
    _require(
        observed.hit_count == 0,
        f"{symbol} breakpoint was hit {context} "
        f"(hits={observed.hit_count}, pc=0x{snapshot.pc:x})",
    )


def _require_no_out_of_order_prologue(
    snapshot, expected_symbol, breakpoints
):
    for symbol, breakpoint in breakpoints.items():
        if symbol == expected_symbol:
            continue
        if snapshot.pc in breakpoint["addresses"]:
            raise RuntimeError(
                f"reached {symbol} prologue at 0x{snapshot.pc:x} while "
                f"instruction-stepping toward {expected_symbol}"
            )


def _instruction_calls_breakpoint(instruction, symbol, breakpoint):
    mnemonic = instruction.mnemonic.lower()
    if mnemonic not in {
        "call",
        "callq",
        "bl",
        "blx",
        "bal",
        "jal",
        "jalr",
    }:
        return False
    rendered = f"{instruction.operands} {instruction.comment}".lower()
    if symbol.lower() in rendered:
        return True
    return any(
        f"0x{address:x}" in rendered or str(address) in rendered
        for address in breakpoint["addresses"]
    )


def _step_to_breakpoint(
    dbg,
    current,
    expected_symbol,
    breakpoints,
    definition,
    instruction_steps,
):
    expected_breakpoint = breakpoints[expected_symbol]
    if current.pc in expected_breakpoint["addresses"]:
        _require_breakpoint_stop(current, expected_symbol, expected_breakpoint)
        return current, instruction_steps

    observed = _find_breakpoint(
        current.breakpoints, expected_breakpoint["id"]
    )
    _require(
        observed.hit_count == 0,
        f"{expected_symbol} breakpoint already had {observed.hit_count} hit(s) "
        f"before its prologue was reached",
    )

    limit = definition["instruction_step_limit"]
    while instruction_steps < limit:
        instruction = _instruction_at_pc(
            current, f"stepping toward {expected_symbol}"
        )
        if _instruction_calls_breakpoint(
            instruction, expected_symbol, expected_breakpoint
        ):
            stepped = dbg.continue_and_wait(timeout=20)
            instruction_steps += 1
            _require_new_stopped_snapshot(
                current,
                stepped,
                f"continue over call at 0x{instruction.address:x} "
                f"to catch {expected_symbol}",
            )
        else:
            stepped = _step_once(
                dbg,
                current,
                instruction,
                False,
                instruction_steps + 1,
                limit,
                expected_symbol,
            )
            instruction_steps += 1
        _require_breakpoint_not_hit(
            stepped,
            "crackme_failure",
            breakpoints["crackme_failure"],
            f"while stepping toward {expected_symbol}",
        )
        _require_no_out_of_order_prologue(
            stepped, expected_symbol, breakpoints
        )
        if stepped.pc in expected_breakpoint["addresses"]:
            _require_breakpoint_stop(
                stepped, expected_symbol, expected_breakpoint
            )
            return stepped, instruction_steps

        observed = _find_breakpoint(
            stepped.breakpoints, expected_breakpoint["id"]
        )
        _require(
            observed.hit_count == 0,
            f"{expected_symbol} breakpoint recorded {observed.hit_count} hit(s) "
            f"without stopping at a resolved prologue address; "
            f"pc=0x{stepped.pc:x}",
        )
        current = stepped

    raise RuntimeError(
        _instruction_bound_message(
            definition, instruction_steps, expected_symbol, current
        )
    )


def _step_through_function(
    dbg,
    current,
    symbol,
    breakpoints,
    definition,
    instruction_steps,
):
    _require(
        _snapshot_has_function(current, symbol),
        f"cannot step through {symbol}: its frame is absent at "
        f"pc=0x{current.pc:x}",
    )
    limit = definition["instruction_step_limit"]
    while _snapshot_has_function(current, symbol):
        if instruction_steps >= limit:
            raise RuntimeError(
                _instruction_bound_message(
                    definition,
                    instruction_steps,
                    f"return from {symbol}",
                    current,
                )
            )
        instruction = _instruction_at_pc(current, f"stepping through {symbol}")
        step_over = instruction.mnemonic.lower().startswith(
            definition["final_step_over_mnemonics"]
        )
        stepped = _step_once(
            dbg,
            current,
            instruction,
            step_over,
            instruction_steps + 1,
            limit,
            f"return from {symbol}",
        )
        instruction_steps += 1
        _require_breakpoint_not_hit(
            stepped,
            "crackme_failure",
            breakpoints["crackme_failure"],
            f"while stepping through {symbol}",
        )
        current = stepped
    return current, instruction_steps


def _step_once(
    dbg,
    current,
    instruction,
    step_over,
    step_number,
    limit,
    destination,
):
    operation = "step-over" if step_over else "step-into"
    description = (
        f"instruction {operation} {step_number}/{limit} at "
        f"0x{instruction.address:x} ({instruction.mnemonic} "
        f"{instruction.operands}) toward {destination}"
    )
    stepped = dbg.step_instruction(step_over=step_over, timeout=15)
    _require_new_stopped_snapshot(current, stepped, description)
    _require(
        stepped.pc != current.pc,
        f"{description} left the PC unchanged at 0x{stepped.pc:x}",
    )
    return stepped


def _instruction_at_pc(snapshot, context):
    for instruction in snapshot.instructions:
        if instruction.address == snapshot.pc:
            return instruction
    available = ", ".join(
        f"0x{instruction.address:x}" for instruction in snapshot.instructions
    )
    raise RuntimeError(
        f"{context} has no instruction metadata at pc=0x{snapshot.pc:x}; "
        f"published addresses: [{available}]"
    )


def _snapshot_has_function(snapshot, symbol):
    for thread in snapshot.threads:
        if thread.id != snapshot.thread_id:
            continue
        return any(symbol in frame.function for frame in thread.frames)
    return False


def _instruction_bound_message(
    definition, instruction_steps, destination, snapshot
):
    return (
        f"exhausted the {definition['instruction_step_limit']}-instruction "
        f"bound after {instruction_steps} step(s) while seeking {destination}; "
        f"last state={snapshot.state}, pc=0x{snapshot.pc:x}, "
        f"generation={snapshot.generation}, revision={snapshot.revision}, "
        f"stop_revision={snapshot.stop_revision}"
    )


def _architecture_definition(name):
    success_path = (
        "crackme_entry",
        "crackme_verify",
        "crackme_mix",
        "crackme_checkpoint",
        "crackme_success",
    )
    definitions = {
        "x86_64": {
            "aliases": ("x86_64", "amd64"),
            "byte_order": "little",
            "pointer_size": 8,
            "pc_register": "rip",
            "sp_register": "rsp",
            "general_register": "rax",
            "mnemonics": ("mov", "push", "pop", "call", "ret", "cmp", "lea", "xor", "sub", "add"),
            "success_path": success_path,
            "success_exit_status": 0,
            "instruction_step_limit": 384,
            "final_step_over_mnemonics": ("call", "callq"),
        },
        "arm": {
            "aliases": ("arm", "armv7"),
            "byte_order": "little",
            "pointer_size": 4,
            "pc_register": "pc",
            "sp_register": "sp",
            "general_register": "r0",
            "mnemonics": ("mov", "push", "pop", "bl", "bx", "ldr", "str", "cmp", "add", "sub"),
            "success_path": success_path,
            "success_exit_status": 0,
            "instruction_step_limit": 256,
            "final_step_over_mnemonics": (),
        },
        "mips": {
            "aliases": ("mips", "mipsel", "mips32"),
            "byte_order": "little",
            "pointer_size": 4,
            "pc_register": "pc",
            "sp_register": "sp",
            "general_register": "a0",
            "mnemonics": ("add", "addiu", "sw", "lw", "jal", "jr", "move", "lui", "ori", "xor", "beq", "bne"),
            "success_path": success_path,
            "success_exit_status": 0,
            "instruction_step_limit": 384,
            "final_step_over_mnemonics": (),
        },
        "ppc": {
            "aliases": ("ppc", "powerpc"),
            "byte_order": "big",
            "pointer_size": 4,
            "pc_register": "pc",
            "sp_register": "r1",
            "general_register": "r3",
            "mnemonics": ("stw", "stwu", "lwz", "mflr", "mtlr", "bl", "blr", "cmp", "li", "mr", "addi", "xor"),
            "success_path": success_path,
            "success_exit_status": 0,
            "instruction_step_limit": 320,
            "final_step_over_mnemonics": (),
        },
    }
    try:
        return definitions[name]
    except KeyError as error:
        raise RuntimeError(f"unsupported cross-architecture scenario: {name}") from error


def _binding(owner, name, deficiencies, contract):
    if not hasattr(owner, name):
        if contract not in deficiencies:
            deficiencies.append(contract)
        return None
    return getattr(owner, name)


def _check_snapshot_metadata(snapshot, definition, mode, executable, deficiencies):
    architecture = _binding(snapshot, "architecture", deficiencies, "Snapshot.architecture: str")
    target_triple = _binding(snapshot, "target_triple", deficiencies, "Snapshot.target_triple: str")
    byte_order = _binding(snapshot, "byte_order", deficiencies, "Snapshot.byte_order: str")
    address_size = _binding(snapshot, "address_byte_size", deficiencies, "Snapshot.address_byte_size: int")
    session_mode = _binding(snapshot, "mode", deficiencies, "Snapshot.mode: str")
    instructions = _binding(snapshot, "instructions", deficiencies, "Snapshot.instructions: list[Instruction]")
    modules = _binding(snapshot, "modules", deficiencies, "Snapshot.modules: list[Module]")
    supports_intel = _binding(
        snapshot,
        "supports_intel_syntax",
        deficiencies,
        "Snapshot.supports_intel_syntax: bool",
    )
    _binding(snapshot, "intel_syntax", deficiencies, "Snapshot.intel_syntax: bool")

    _require(
        os.path.realpath(snapshot.target_path) == os.path.realpath(executable),
        "snapshot lost the local ELF path",
    )
    register_names = {register.name.lower() for register in snapshot.registers}
    for register_name in (
        definition["pc_register"],
        definition["sp_register"],
        definition["general_register"],
    ):
        _require(
            register_name in register_names,
            f"snapshot omitted native register {register_name}",
        )

    if architecture is not None:
        normalized = architecture.lower()
        _require(
            any(alias in normalized for alias in definition["aliases"]),
            f"snapshot reported the wrong architecture: {architecture}",
        )
    if target_triple is not None:
        _require(target_triple, "snapshot target triple was empty")
    if byte_order is not None:
        _require(byte_order == definition["byte_order"], f"wrong byte order: {byte_order}")
    if address_size is not None:
        _require(address_size == definition["pointer_size"], f"wrong address size: {address_size}")
    if session_mode is not None:
        expected_mode = "local" if mode == "native" else "QEMU user"
        _require(session_mode == expected_mode, f"wrong session mode: {session_mode}")
    if supports_intel is not None:
        _require(
            supports_intel == (definition["pc_register"] == "rip"),
            "snapshot exposed the x86 syntax toggle for the wrong architecture",
        )
    if instructions is not None:
        _require(instructions, "snapshot contained no instructions")
        mnemonics = tuple(item.mnemonic.lower() for item in instructions)
        _require(
            any(value.startswith(definition["mnemonics"]) for value in mnemonics),
            f"snapshot instructions were not native to the target: {mnemonics}",
        )
    if modules is not None:
        _require(modules, "snapshot contained no modules")
        expected = os.path.basename(executable)
        _require(
            any(os.path.basename(module.path) == expected for module in modules),
            "local ELF was absent from the module snapshot",
        )


def _check_threads(snapshot):
    _require(snapshot.threads, "snapshot contained no threads")
    selected = [thread for thread in snapshot.threads if thread.selected]
    _require(len(selected) == 1, "snapshot did not identify exactly one selected thread")
    _require(selected[0].id == snapshot.thread_id, "selected thread id disagreed with snapshot")
    _require(selected[0].frames, "selected thread contained no stack frames")
    _require(selected[0].frames[0].selected, "top stack frame was not selected")


def _check_disassembly_syntax(dbg, definition, deficiencies):
    is_x86 = definition["pc_register"] == "rip"
    if is_x86:
        dbg.execute("syntax att", timeout=10)
        snapshot = dbg.snapshot()
        intel_syntax = _binding(snapshot, "intel_syntax", deficiencies, "Snapshot.intel_syntax: bool")
        instructions = _binding(snapshot, "instructions", deficiencies, "Snapshot.instructions: list[Instruction]")
        if intel_syntax is not None:
            _require(not intel_syntax, "AT&T syntax state was not published")
        if instructions is not None:
            _require(
                any("%" in instruction.operands for instruction in instructions),
                "AT&T disassembly omitted register prefixes",
            )
        dbg.execute("syntax intel", timeout=10)
        _require(dbg.snapshot().intel_syntax, "Intel syntax state was not restored")
    else:
        try:
            dbg.execute("syntax intel", timeout=10)
        except RuntimeError:
            pass
        else:
            raise RuntimeError("non-x86 target accepted the x86 syntax toggle")
        snapshot = dbg.snapshot()
        instructions = _binding(snapshot, "instructions", deficiencies, "Snapshot.instructions: list[Instruction]")
        if instructions is not None:
            _require(
                all("%" not in instruction.operands for instruction in instructions),
                "non-x86 disassembly used AT&T register prefixes",
            )


def _find_breakpoint(breakpoints, breakpoint_id):
    for breakpoint in breakpoints:
        if breakpoint.id == breakpoint_id:
            return breakpoint
    raise RuntimeError(f"breakpoint {breakpoint_id} was absent from the snapshot")


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)
