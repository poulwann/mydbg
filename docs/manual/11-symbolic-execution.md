# Symbolic Execution and ROP

mydbg integrates symbolic execution (angr) and ROP chain tooling (angrop) as
optional, script-first backends. The GUI and console bootstrap scripts; the
reverser owns and iterates on them. Every helper here runs inside mydbg's
embedded Python, on live debugger state.

## Installing the backend

The backend needs the interpreter LLDB itself uses:

```console
./scripts/bootstrap-symbolic.sh
export MYDBG_SYMBOLIC_PYTHONPATH=$PWD/.venv-symbolic/lib/python3.14/site-packages
```

The script queries `lldb --print-script-interpreter-info`, creates
`.venv-symbolic` with that interpreter, and installs the pinned ecosystem
(`requirements-symbolic.txt`: angr 9.2.223, angrop 9.2.12.post3). Without it,
`mydbg.symbolic.requires_angr()` returns False and the symbolic features
report a diagnostic instead of failing mysteriously.

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

## Limits and good practice

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
