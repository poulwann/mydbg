# Symbolic Execution and ROP

mydbg integrates symbolic execution (angr), script-driven ROP chain tooling
(angrop), and a graphical stack-driven ROP simulator (Unicorn/Capstone).
These optional backends run inside mydbg's embedded Python. The visualizer
captures a stopped target but executes only in an isolated emulator.

## Installing the backend

The backend needs the interpreter LLDB itself uses:

```console
./scripts/bootstrap-symbolic.sh
export MYDBG_SYMBOLIC_PYTHONPATH=$PWD/.venv-symbolic/lib/python3.14/site-packages
export PYTHONPATH="$MYDBG_SYMBOLIC_PYTHONPATH${PYTHONPATH:+:$PYTHONPATH}"
```

The script queries `lldb --print-script-interpreter-info`, creates
`.venv-symbolic` with that interpreter, and installs the pinned ecosystem
(`requirements-symbolic.txt`: angr 9.2.223, angrop 9.2.12.post3,
Unicorn 2.1.4, Capstone 5.0.6). Use the site-packages directory matching that
interpreter; the example above uses Python 3.14. `PYTHONPATH` exposes the
backends to the GUI and embedded scripts; `MYDBG_SYMBOLIC_PYTHONPATH` also
configures the test wrappers. Missing dependencies produce a diagnostic.

## Symbolic execution from a stopped PC

The core workflow — stop anywhere, snapshot the live state into an angr
`SimState`, mark inputs symbolic, explore to a target, apply the solved model
back to the live session:

```python
from mydbg import symbolic

def run(dbg):
    dbg.launch(["./crackme", "wrong"], stop_at="main")
    dbg.set_breakpoint("crackme_entry")
    dbg.continue_execution()
    dbg.wait_for_stop(timeout=5)

    seed_slot = dbg.read_register("rbp") - 0x44  # read the disassembly first
    solution = symbolic.find_way(
        dbg,
        symbolic.resolve_symbol(dbg, "crackme_success"),
        symbolize=[f"{seed_slot:x}:4"],
        timeout=120,
    )
    print(solution.summary())
    if solution.status == "found":
        solution.apply(dbg)      # writes the model into the live session
    dbg.continue_execution()
```

- `symbolize` entries: `reg:rdi` (a symbolic register), `deadbeef:20`
  (symbolic bytes at a hex address), or `deadbeef` (8 bytes).
- `find_way` seeds the state from the live process: the main module image
  (applied instruction patches included), a stack window around SP, and all
  live registers. Exploration is bounded by `timeout`, `max_steps`, and
  `max_states`; everything past a bound lands in the manager's `cut` stash
  instead of running away.
- The state executes **live bytes at runtime addresses**: PIE bases come from
  the session, and PLT stubs are re-hooked at the runtime base so angr's
  SimProcedures (printf and friends) fire instead of jumping through the live
  GOT into the dynamic loader.
- Registers are seeded widest-first, so LLDB's alias register list (`r8d`,
  `bp`, ...) never clobbers the wide registers.
- `solution.summary()` prints the model, and `solution.states`/`manager`
  expose the raw angr objects for custom work.

LLDB function breakpoints land **after the prologue**; if the function has
already spilled its argument, symbolize the stack slot (as above), not the
argument register.

See `examples/solve_symbolic.py` for the complete x86_64 crackme solve, and
`tests/scripts/symbolic_solve.py` for the cross-architecture variant (QEMU
user sessions, big- and little-endian).

## KLEE artifact interop

KLEE solves at build time (LLVM bitcode, `klee` runtime); mydbg replays the
results on the live process:

```python
from mydbg import symbolic

objects = symbolic.import_ktest("test000001.ktest")
for name, data in objects.items():
    dbg.write_memory(target_address, data)
```

## Input-space solves: symbolic stdin and keygens

Two patterns from angr's CTF-solving workflows where the answer is input
bytes, not memory. The solved input verifies against the live target through
a relaunch (`mydbg.rop.test_landing`), not a memory write.

### Symbolic stdin flag finder

Explore from the target's entry with symbolic stdin; constrain the bytes up
front; find the success branch. `find`/`avoid` take addresses or state
predicates:

```python
from mydbg import symbolic

project = symbolic._entry_project(dbg, binary="./challenge")
find = symbolic.resolve_project_symbol(project, "stdin_success")
avoid = [symbolic.resolve_project_symbol(project, "stdin_fail")]

solution = symbolic.solve_entry_stdin(
    dbg, find, avoid=avoid, size=24, printable=True, timeout=300,
    binary="./challenge",
)
print(solution.summary())          # input: mydbg_symb0lic_stdin_win
```

Name the success/failure paths as `noinline` functions in your target so the
symbol table yields clean find/avoid addresses. See
`examples/solve_stdin.py`, which relaunches the target with the solved 24
bytes in an input file and requires `stdin_flag_ok`.

### Keygen via call state

Call a validation function with a symbolic NUL-terminated printable argument
and accept any state where a nonzero return value is satisfiable:

```python
dbg.launch(["./keygenme", "wrong"], stop_at="main")
function = symbolic.resolve_symbol(dbg, "keygen_valid")
solution = symbolic.call_way(dbg, function, size=17, printable=True)
print(solution.input_bytes)        # a 16-char serial
```

The argument lives in symbolized memory below SP, clear of the callee frame;
the return sentinel is on the stack (amd64) or in the link register
(arm/mips/ppc). 32-bit x86 (stack arguments) is unsupported. See
`examples/solve_keygen.py`, which relaunches with the serial on argv and
requires `keygen_ok`.

### Exploration knobs

`explore()` and both input-space solves take `technique="bfs"|"dfs"` (DFS
keeps the frontier small on branchy targets) plus the same hard caps. For
input-format constraints beyond `printable`/`prefix`, apply them directly:
`state.solver.add(variable.get_bytes(0, 5) == b"flag{")`.

### Unicorn fast path

`unicorn=True` on `solve_entry_stdin` (and any state you build yourself, via
`angr.options.unicorn`) runs concrete stretches on the Unicorn engine —
roughly 10-100x faster on compute-heavy targets with symbolic boundaries. It
needs the `unicorn` package from `requirements-symbolic.txt`; angr does not
declare that dependency and silently disables the engine without it.

## Trace-guided solving

Record the concrete run and replay it symbolically, then solve the input from
the point the concrete run already reached — the fastest route into far-away
decision points:

```python
dbg.launch(["./crackme", "wrong"], stop_at="main")
dbg.set_breakpoint("crackme_entry")
dbg.continue_execution()
dbg.wait_for_stop(timeout=5)

verify = symbolic.resolve_symbol(dbg, "crackme_verify")
dbg.set_breakpoint("crackme_verify")
success = symbolic.resolve_symbol(dbg, "crackme_success")

solution = symbolic.trace_way(
    dbg,
    symbolize=["reg:edi"],   # the argument at the traced point
    find=success,
    stop_at=verify,          # the recording stops here
    max_trace_steps=2000,
)
print(solution.summary())
solution.apply(dbg)          # the live session sits at the traced point
```

- `record_trace` single-steps the live session (LLDB round-trips make this
  seconds-scale — trace the interesting span, not whole programs).
- `reduce_trace_blocks` converts the instruction trace to basic-block heads
  by lifting block boundaries from the image; instruction-patched regions
  should not be traced (the lifted sizes come from the on-disk bytes).
- The replay is an explicit block-following loop: every step must land on the
  next recorded block, and strays land in the manager's `desync` stash with a
  diagnostic instead of silently derailing.
- Symbolize **at the traced point**, not before: values the concrete run
  already consumed (spilled arguments, read buffers) are dead by the time the
  trace ends. Symbolize the register or memory the remaining code reads.
- `Solution.model_int(name)` evaluates a register model endianness-free;
  `eval(cast_to=bytes)` follows bit order, not target byte order.

See `examples/solve_trace.py`.

## Engine-owned qemu-user sessions

`connect_remote` can spawn and own the qemu-user stub itself — the debugger
starts `qemu -g port [-L sysroot] target args`, holds the target's stdin, and
tears the stub down with the session:

```python
process = dbg.connect_remote(
    binary, "", mode="qemu-user", timeout=60,
    qemu="qemu-arm", sysroot="/tmp/sysroots/armel",
    cwd="/path/to/challenge", stdin_file="/tmp/payload.bin",
)
dbg.send_stdin(b"more input\r\n")   # reaches the target through the owned pipe
```

- `stdin_file` redirects the target's stdin to a file; `send_stdin` writes
  through the owned pipe. Both deliver raw bytes — the pty corruption that
  affects local launches does not apply.
- Target output flows back through the session's output capture
  (`process.recv`), drained continuously and once more at exit.
- Symbol breakpoints work: when LLDB cannot resolve a main-image symbol
  (qemu-user stops dynamic binaries at the dynamic loader, where LLDB also
  cannot bind pending breakpoints), the engine resolves it from the image's
  own ELF symbol table. Non-PIE values are runtime addresses; PIE images
  resolve once mapped.
- Local launches accept `stdin_path=` for the same raw-stdin delivery via
  LLDB's `target.input-path`.
- Session teardown kills the owned stub after the LLDB connection ends — do
  not kill it from a script while the session is live (mydbg's exit hangs on
  a dead stub).

## ROP Emporium workflow (examples/rop_emporium/)

The ROP Emporium challenge set ships under `examples/rop_emporium/`; the
solve scripts drive it entirely through the debugger: gadget scan (angrop),
chain assembly, engine-owned qemu sessions, breakpoint stops, and output
verification — ret2win (x64/i386/ARM), split, callme (three csu-style calls),
and write4 (library-base discovery through the guest's own `link_map`, since
qemu's stub does not report guest libraries).

Sysroots are environment provisioning: download the target glibc package for
each architecture and unpack it into `/tmp/sysroots/<arch>` (override with
`MYDBG_ROP_SYSROOTS`):

```console
# Debian pool: libc6_<version>_<arch>.deb -> unpack ./lib and ./usr/lib
# x64 needs the loader + libc reachable under sysroot/lib64,
# plus a guest /bin/sh (dash) for challenges that call system().
qemu-arm -L /tmp/sysroots/armel ./ret2win_armv5   # smoke test
```

Findings worth knowing before you script your own:

- Use `continue_and_wait` for breakpoint legs: `wait_for_stop` can return the
  stop you were already sitting on.
- qemu-mipsel + LLDB 21 misbehaves on dynamically linked guests (registers
  read stale, entry trap repeats); the static-fixture tests pass, so prefer
  static targets on MIPS until LLDB's mips gdb-remote register context
  improves.
- angrop's `func_call` bails on some gadget mixes ("overlapped moves"); when
  it does, assemble the chain from its gadget database by hand
  (`find_gadgets_matching`) — callme's solve does exactly that.
- Modern glibc `system()` uses posix_spawn/clone; clone under qemu-user or
  under a traced process crashes in this environment regardless of the
  debugger. split's solve verifies the chain with `puts` and documents the
  payload for `system`.

## Stack-driven ROP visualizer

![A captured ROP chain with repeated gadgets, a stack pivot, and simulated state](screenshots/rop-visualizer.png)

1. Stop an x86-64 or supported Linux i386 target with the proposed chain in
   readable memory.
2. Open **View > ROP visualizer**. Enter the **address of the first stack
   slot**, in hexadecimal, or use `$sp` / **Use SP**.
   Alternatively, right-click a Memory dump selection or a Stack telescope
   **slot address**, then choose **Visualize ROP from here**. This opens the
   panel at the slot's address, not the gadget pointer stored there.
3. Click **Analyze**. The simulator consumes the first pointer as an initial
   return: PC becomes that pointer and SP advances by the target pointer
   width. Other captured general registers and flags seed the emulator.
   This does not execute an overflow or redirect the live thread.
4. Use **Next instruction**, **Prev instruction**, **Next gadget**, **Reset**,
   or the timeline. Left/Right also move the simulated cursor while this
   panel is focused. **Sync live views** keeps Disassembly or Memory dump on
   the selected simulated address without executing the target. Native
   execution shortcuts are suppressed in the panel.

The graph records execution **occurrences**, not one deduplicated node per
code address. Reusing a gadget creates another node. Return edges name the
consumed stack slot; pop/data operands remain data even when their value
looks like a gadget address. Calls, jumps, and conditional branches split
occurrences too, but do not invent return slots. A pivot follows the actual
simulated SP into the new stack segment. This is one concrete path, not a
graph of every possible branch.

Each instruction row shows the address, SP transition, and short effect chips
(`Δ` for register writes, `R`/`W` for memory). Long rows are clipped with an
ellipsis; hover or open the inspector for full text. **Fit** shows the full
trace; **Selection** centers the selected occurrence; **100%** restores
readable text size. Drag the background or middle-drag to pan, and use the
wheel to zoom around the pointer.

The inspector reconstructs state at the cursor:

- **Registers** shows simulated values and the selected instruction's deltas.
- **Stack** distinguishes observed return targets, data, and unconsumed
  slots. `*` marks a simulated write. Roles describe use across the trace;
  they are not guesses based on whether a value points to executable memory.
- **Memory effects** lists each recorded read/write, with before/after bytes
  for the selected access. Writes are visible to later simulated
  instructions, including writes that change a future return target.

No simulation action writes memory/registers, resumes, or single-steps the
live process. **Sync live views** and explicit **Follow** buttons only
navigate the live debugger views.
**Trace recorded** means a trace is available, not that the chain succeeds.
Read the terminal boundary: system calls and interrupts stop before
execution, and invalid code, permissions, uncaptured state, or limits stop
the trace with a diagnostic. Incomplete instructions have no committed
effects; even a partially executed repeated instruction is rolled back.

Analysis uses the existing Python worker and native-control lease. Defaults
are 512 stack-preview bytes, 256 instructions, 64 occurrences, and five
seconds. Expand **Analysis limits** to adjust them; capture size, memory
effects, and individual instruction execution are also bounded. **Cancel**
stops analysis without changing the target. A previous trace can remain
visible while a new request is pending or cancelled.

The panel marks a trace **OFFLINE / STALE** after a detected process, stop,
thread, register, or tracked-patch change. Offline simulated stepping still
works, but live Follow actions are disabled. Re-analyze after raw LLDB or
external memory writes: writes outside the tracked patch API are not all
detectable by the source fingerprint.

### Execution boundaries

The simulator supports x86-64 and flat-user Linux i386. For i386, missing
segment bases are accepted only with a Linux target triple and captured
standard Linux CS/SS selector pairs; the diagnostic names that ABI model.
Custom/TLS descriptors are not inferred. x86-64 FS/GS accesses require their
actual captured bases. Missing GPRs, undefined flags used by a later
instruction, uncaptured SIMD/FPU state, privileged operations, and
privilege-dependent flag restoration stop explicitly.

Memory is lazily captured from readable live mappings with their reported
permissions. Unknown bytes are not supplied as zero-filled memory.
This is a bounded CPU simulation, not an OS, syscall, CET/shadow-stack, or
exploit-success validator. Other architectures still have the separate
script-driven angrop workflows below.

Scripts can consume the same read-only trace:

```python
from mydbg.rop_trace import trace_stack

def run(dbg):
    trace = trace_stack(dbg, dbg.snapshot().sp, stack_bytes=512,
                        max_instructions=256, max_nodes=64, timeout=5.0)
    print(trace["status"], trace["message"])
    for node in trace["nodes"]:
        print(node["stack_slot"], hex(node["entry_address"]))
        for instruction in node["instructions"]:
            print(instruction["text"], instruction["completed"],
                  instruction["register_changes"], instruction["memory_accesses"])
```

`initial_registers` represents the state after the synthetic initial return;
`stack_slots` retains the original captured bytes as pointer-width values.
Instruction effects are ordered and reversible. `cancelled=` optionally
accepts a cancellation callback. This API needs Unicorn and Capstone,
not an angrop gadget scan.

## ROP with angrop

`mydbg.rop` wraps angrop's ROP analysis for the ret2win/exploit iteration
loop:

```python
from mydbg import rop

dbg.launch([target, payload_path], stop_at="main")
win = rop.resolve_symbol(dbg, "rop_win")      # true entry address

engine = rop.RopEngine(target)
engine.find_gadgets()                          # cached by binary digest
print(engine.summary())
gadget = engine.find_gadgets_matching("pop rdi ; ret", exact=True)[0]

payload = b"A" * 56 + rop.p64(gadget.addr) + rop.p64(token) + rop.p64(win)
config = rop.RunConfig(argv=[target, payload_path], stop_at="main")
landing = rop.test_landing(dbg, config, payload, 0,
                           send_stdin=False, expect_output=b"rop_win_ok",
                           expect_exit=0)
print(landing.summary())                       # rop-landing-landed/MISSED pc=...
```

- Gadget scans are single-threaded and cached under `~/.cache/mydbg/rop/`
  keyed by binary content, bad bytes, and angrop version; relaunch loops never
  rescan. Set `MYDBG_ROP_CACHE_DIR` to relocate the cache.
- `RunConfig` + `relaunch` restarts the target with identical arguments so
  each iteration lands at the same stack depth; `test_landing` reports the
  actual PC on a miss (a misaligned chain faults at its shifted address,
  which tells you the offset is wrong).
- angrop's internal alarm-based timeouts are disabled because they cannot run
  on mydbg's script thread; enforce your own bounds.
- Default bad bytes are `\x0a\x0d`. NUL is deliberately absent — non-PIE
  gadget addresses contain it, and file/pipe inputs carry it fine.
- Deliver byte-exact payloads through a **file named in argv**. mydbg launches
  with a pty whose canonical line discipline corrupts binary stdin (EOF,
  erase, and signal bytes are processed rather than delivered); `place()`
  writing directly into live memory is the alternative for targets that are
  already past their input read.

See `examples/rop_crackme.py` for the full loop, including the deliberately
misaligned chain being rejected with its fault PC.

## Symbolic execution limits and good practice

- The state snapshot covers the main module mapping, a ±64 KiB stack window,
  and any `extra_regions` you pass. Anything outside is zero-filled
  (`ZERO_FILL_UNCONSTRAINED_*`), so reads of unrelated pages do not poison
  the path.
- One exploration at a time per session; long jobs block the script that
  started them (the interpreter holds the GIL), and the GUI lease keeps the
  console actions honest. Cancel via the script debugger's stop button.
- The segment bases (`fs`/`gs`) are zero in the symbolic state, which keeps
  stack-canary checks self-consistent; canary-failing paths are simply paths
  the solver prunes.
