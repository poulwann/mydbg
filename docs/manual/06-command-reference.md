# Command reference

![Native context and address inspection, a registered plugin command, and Python job status](screenshots/console.png)

Enter a command in **Command > Debugger console**, then press Enter or **Run**. The other tab, **Debuggee output**, shows program output; it is not a terminal input box. Use Python Process I/O for interactive binary-safe communication.

The GUI command field is a single-line buffer, not a full LLDB terminal, shell, Python REPL, or readline editor. It does not implement command-history recall or completion. Output is captured separately from input.

## Dispatch and notation

mydbg handles its built-ins first, then registered native plugin commands, then forwards unrecognized input to LLDB. `help`/`h` prints mydbg help; `pwndbg` prints compatibility help, not an embedded pwndbg installation. Use LLDB's `command ...` facilities for LLDB-specific discovery.

In this chapter:

- `ADDRESS` means an unsigned numeric address, stopped-frame register (optionally `$`-prefixed), or an LLDB expression resolving to an address.
- `ID`, `COUNT`, and most native numeric options accept unsigned decimal or `0x` hexadecimal. Negative values and shell arithmetic are not generic native number syntax.
- Uppercase names and bracketed optional arguments are notation, not literal input.
- `a | b` denotes aliases, not a shell pipeline.
- Native tokenized arguments support single/double quotes and backslash escapes outside single quotes. This is not a shell: no expansion/substitution/pipelines. Empty quoted arguments are lost; use Python for exact argv.
- Quote an address expression containing spaces when a command tokenizes multiple arguments. Raw-tail commands can consume the remaining text directly.

LLDB expression evaluation and raw commands can execute code or mutate the target. The console is **not sandboxed**. State-changing LLDB commands are reconciled into mydbg afterward, not intercepted in the middle of an opaque LLDB script. A Python job's control lease refuses ordinary GUI native console input until it finishes; `py status` and `py stop` remain available.

Important compatibility differences: **`r` reads registers, not run; `p` steps over, not print; `x ADDRESS` changes the GUI dump; `hbreak` is not guaranteed hardware; heap bin names are heuristic filters.**

## Help, display, context, and watches

- `help`, `h`: built-in command help.
- `pwndbg`: compatibility-help summary.
- `tip [--all]`: basic tips, or extended tips with exactly `--all`.
- `config`: architecture/mode/syntax/theme, configured launch arguments, context sections/watch count, and selected analysis bounds. This is a report, not a general setter.
- `theme [dark|light]`: query or select the theme.
- `syntax intel|att`: switch supported x86 disassembly syntax and refresh stopped capture. Non-x86 targets reject the switch; no-argument syntax is not a query.
- `context [SECTION]`, `ctx [SECTION]`: show the default context or one selected section. Requires stopped state. Sections: `regs`, `disasm`, `insight`/`operands`/`args`, `stack`, `backtrace`, `threads`, `expressions`/`watches`, `history`, `crash`, `ghidra`. The ghidra section points to the GUI decompiler; it is not a text decompile command.
- `set context-sections SECTION...`: replace the default list. Use lowercase names; this setter does not validate arbitrary names. Default sections are regs, disasm, insight, stack, backtrace, threads, crash.
- `ctx-watch`: list zero-based watch indices and definitions.
- `ctx-watch eval EXPR`: append an LLDB expression watch.
- `ctx-watch execute LLDB-COMMAND`: append an execute-mode watch. This runs through LLDB, not recursively through mydbg aliases.
- `ctx-watch delete INDEX`: remove one watch and reindex survivors.
- `ctx-watch clear`: remove all watches.
- `display EXPR`: add an eval watch to the same list.
- `undisplay INDEX`: delete from that same list.

Watches refresh during context display and watch-list edits; even `ctx regs` can refresh the watches. LLDB evaluation/execute watches can have side effects. Expression definitions can persist, but execute watches are intentionally not replayed from saved sessions.

```text
ctx regs
ctx insight
set context-sections regs disasm stack expressions
ctx-watch eval payload->total
ctx expressions
ctx-watch delete 0
```

Stop history and register deltas are observations, not reverse execution or process checkpoints.

## Load, launch, attach, and process control

- `file PATH`: load exactly one ELF path without running it. Quote spaces. Refuses replacement of a live target until it is terminated/exited/detached.
- `set args [ARG...]`: replace launch arguments; no tail clears them.
- `argv`: list configured launch arguments, not the inferior argv array.
- `run [ARG...]`: launch using configured intent. A nonempty tail replaces arguments; empty preserves them.
- `start [ARG...]`: launch with a one-shot main breakpoint.
- `sstart [ARG...]`: launch with a one-shot `__libc_start_main` breakpoint, if resolvable.
- `starti [ARG...]`, `entry [ARG...]`: launch stopped at entry. The launch tail is passed to LLDB after `--`.
- `attachp PID`: attach to a numeric PID using the selected target.
- `process connect ENDPOINT`: specialized remote connection helper. Requires target and endpoint; adds `connect://` when no URL scheme is given. It is not the full LLDB process-connect options parser.
- `g`, `go`, `c`, `continue`: continue a valid stopped process. No native destination/count syntax; additional text does not implement one.
- `pause`, `breakin`: request a stop of a running process.
- `finish`: LLDB `thread step-out`.
- `jump ADDRESS-TEXT`: LLDB `thread jump --address ...`; changes execution, not the browsing cursor.
- `signal SIGNAL-TEXT`: LLDB `process signal ...`; can terminate or otherwise affect the target.

Use raw `process detach` to detach and raw `process kill` or GUI Terminate to terminate. There is no separate native `restart`/`quit` implementation in this command catalog; unrecognized commands depend on LLDB/plugin support. See [execution](03-execution.md) for GUI restart and remote lifecycle.

## Stepping and run-until

- `t`, `step`: selected-thread source step into.
- `p`, `next`: source step over.
- `ti`, `si`, `stepi`: instruction step into.
- `pi`, `ni`, `nexti`: instruction step over.
- `nextcall`: run to the next linearly discovered call-like mnemonic.
- `nextbranch`, `nextjmp`: next branch-like mnemonic.
- `nextret`, `stepret`: next return-like mnemonic.
- `nextsyscall`, `stepsyscall`: next syscall-like mnemonic.
- `nextproginstr`: next linearly decoded instruction, not a library-skipping policy.
- `xuntil MNEMONIC [MAX]`, `stepuntilasm MNEMONIC [MAX]`: next case-insensitive mnemonic substring match. Default lookahead 256; MAX clamped to 1-4096.

Native step aliases do not implement a count argument. Run-until skips the current instruction, scans a bounded linear list, then asks the selected thread to run to the first match. It is not dynamic tracing and MAX is not an execution timeout. Other stops can intervene; a statically discovered destination might never execute. The fixed run-until aliases use 256 instructions.

## Breakpoints and watchpoints

- `bp SPEC`, `b SPEC`, `break SPEC`, `brk SPEC`, `bnew SPEC`: ordinary breakpoint helper. SPEC is numeric address, `*ADDRESS-EXPRESSION`, stopped register name, or symbol name. Zero locations can mean a successfully created pending symbol breakpoint.
- `hbreak SPEC`, `thbreak SPEC`: the same ordinary helper; do not infer hardware/one-shot behavior from these aliases.
- `bl`: list ID, enabled state, hits, and description.
- `bc ID`, `delete ID`: delete one numeric breakpoint; no wildcard/all syntax.
- `be ID`, `bd ID`: enable/disable one breakpoint.
- `breakrva OFFSET`, `pie breakpoint OFFSET`: set at a numeric offset from the first module's loaded object-header base. Requires a loaded base.
- `tbreak NAME`, `tb NAME`: LLDB one-shot symbol breakpoint.
- `rbreak REGEX`: LLDB function-regex breakpoint.
- `condition ID CONDITION-TEXT`: LLDB native condition. Text is inserted into `breakpoint modify --condition ...`; preserve LLDB quoting.
- `ignore ID COUNT`: LLDB ignore-count modification.
- `script-condition ID EXPRESSION`: compile/set the bounded side-effect-free language. Use the GUI Clear condition action to remove it; the console form requires an expression.
- `watch EXPR`: LLDB write watchpoint.
- `rwatch EXPR`: LLDB read watchpoint.
- `awatch EXPR`: LLDB read/write watchpoint.

The simple SPEC helper is not a source-file/line parser. Use explicit LLDB commands for that:

```text
breakpoint set --file dwarf.cpp --line 13
breakpoint modify --condition 'bias == 3' 2
script-condition 2 if (rdi != 0 && rsi == 3)
```

Replace the example ID with the real one. Hardware resources, exception resolvers, persistence, and the complete bounded-language grammar are covered in [breakpoints](04-breakpoints.md).

## Registers, frames, expressions, and symbols

- `r`, `reg`, `regs`, `registers`: list captured register values while stopped.
- `r NAME`: read a selected-frame register; an initial `$` is accepted.
- `r NAME=VALUE` or `r NAME VALUE`: write using LLDB register-value syntax, then refresh. Do not assume arbitrary C arithmetic is accepted as a register value.
- `print EXPR`: LLDB `expression -- ...`.
- `? EXPR`: selected-frame expression evaluation and value output.
- `argc`: find/evaluate argc where available; not universal entry-register decoding.
- `dumpargs`: LLDB `frame variable --show-types --scope`, which can include more than just arguments.
- `bt`: selected-thread backtrace.
- `k`, `kp`, `backtrace`: all-thread backtrace.
- `threads`: LLDB thread list.
- `up`, `down`: relative frame selection by one; supplied counts are not implemented.
- `info breakpoints`, `info threads`, `info regs`, `info registers`: the corresponding LLDB listing. Other info topics are not native compatibility implementations.
- `u ADDRESS-TEXT`, `disasm ADDRESS-TEXT`: textual LLDB disassembly of 32 instructions. Does not move the GUI cursor. Supply an address; this alias has no implemented default-PC argument.
- `ln ADDRESS-TEXT`, `symbol ADDRESS-TEXT`: LLDB image address lookup.
- `x MODULE!REGEX`: LLDB regex name lookup of the suffix after `!`. The prefix is discarded, **not a module filter**.
- `x/FMT ...`: forwarded intact to LLDB's memory-examine syntax.
- `cstruct TYPE ADDRESS`, `dt TYPE ADDRESS`: evaluate/dereference `*(TYPE*)ADDRESS`. Quote multiword types or address expressions. This is LLDB expression evaluation, not the decompiler's type editor.
- `cymbol`, `cymbol -l`: list custom address annotations.
- `cymbol NAME`: query a custom annotation.
- `cymbol NAME ADDRESS`: add/update one.
- `cymbol -d NAME`: delete one.

Custom cymbol names are not registered as general LLDB expression identifiers. File-backed custom addresses can persist; runtime-only addresses can produce an unsafe-address notice instead.

```text
r pc
print payload->total
hexdump $sp 64
ln $pc
u $pc
```

## Memory reads and pointer traversal

- `dump ADDRESS`, `x ADDRESS` without `!`: select the GUI's up-to-256-byte dump. Requires stopped process; partial reads are possible. Returns a status, not a console hex dump.
- `hexdump ADDRESS [COUNT]`: console hex+ASCII. Default 128 bytes; COUNT clamped to 1-4096. Requires the requested full read.
- `db ADDRESS-TEXT`, `dc ADDRESS-TEXT`: LLDB hex memory read, 32 one-byte units.
- `dw ADDRESS-TEXT`, `du ADDRESS-TEXT`: 32 two-byte hex units. `du` is not a Unicode decoder.
- `dd ADDRESS-TEXT`: 32 four-byte hex units.
- `dq ADDRESS-TEXT`: 32 **target-pointer-sized** hex units, not invariably eight bytes.
- `da ADDRESS-TEXT`: LLDB byte-sized C-string format.
- `dds ADDRESS-TEXT`: four-byte address-format entries.
- `dps`, `dqs`, `dpa`, `dpc`, `dpp`, `dsu`, each followed by ADDRESS-TEXT: target-pointer-sized address-format entries. Their names do not imply full WinDbg semantics.
- `telescope [ADDRESS [COUNT]]`, `teles`, `tel`: default SP and 8 pointer slots; count bounded to 1-64. Reports target-width/endian values and available symbol/string previews.
- `p2p ADDRESS [DEPTH]`: dereference a pointer chain, default 5 and bounded to 1-32. Stops on cycles/read errors; not a rich symbol/object inspector.
- `plist HEAD [NEXT-OFFSET [MAX-NODES]]`: follow pointers at node+offset, default offset 0 and max 32, capped at 256. Ends on null, cycle, read failure, or bound.
- `distance ADDRESS ADDRESS`: second minus first in bytes, pointer slots, and hexadecimal representation.

```text
tel $sp 4
p2p $sp 3
vmmap $sp
xinfo $pc
```

## Byte-pattern searching

```text
search STRING [MAPPING-SUBSTRING]
search -x HEXBYTES [MAPPING-SUBSTRING]
search -t TYPE VALUE [MAPPING-SUBSTRING]
```

Types: `string`/`str`, `byte`/`u8`, `short`/`u16`, `int`/`u32`, `long`/`u64` (eight bytes), and `pointer` (target width).

Quote a string containing spaces or spaced hex bytes. Hex input consists of complete byte pairs, optionally 0x-prefixed per token; no wildcard pattern is implemented here. Numeric patterns use target endianness. Narrow numeric widths discard high bits, so range-check your input yourself.

The search checks every byte in readable captured mappings, optionally restricted by a case-sensitive mapping-name substring. It carries overlap across 64 KiB reads, supports overlapping matches, and stops at 256 results or a 256 MiB read budget. Read failures can abandon a mapping. It does not retain a candidate set for refinement; use [Value scanner](05-memory-and-analysis.md) for first/next scans.

```text
search "token> "
search -x "41 42 43"
search -t u32 0x13572468
```

## Writes, assembly, and revert

These commands mutate live target memory. Confirm the address/range and target state before issuing them.

- `patch ADDRESS HEXBYTES...`: tracked raw patch. Complete pairs, optional 0x prefixes; spaces/commas accepted by the hex parser. Reads original bytes and requires a stopped target.
- `assemble ADDRESS INTEL-ASSEMBLY`, `asm ADDRESS INTEL-ASSEMBLY`: assemble and track a write on supported x86 32-/64-bit targets. Address is split at the first whitespace; the rest is assembly text. There is no automatic instruction-length matching or NOP padding.
- `nop ADDRESS [COUNT]`: write repeated NOP encodings, default 1, bounded to 1-256 repetitions.
- `syscall ADDRESS [COUNT]`: write repeated syscall-like encodings, same repetition bound; it does not execute a syscall. Fixed encodings cover a limited x86/AArch64/RISC-V set, not arbitrary target ISA/endian combinations.
- `patch_list`: list tracked IDs, addresses, originals, and replacements.
- `patch_revert ID-OR-ADDRESS`: restore one tracked entry by numeric ID/address, report write failure if it cannot be restored.
- `eb ADDRESS VALUES...`, `ew`, `ed`, `eq`: raw LLDB memory writes of 1-, 2-, 4-, or 8-byte units respectively. These are **not tracked** by patch_list.

Tracked overlapping patches preserve the earliest originals. Restart/new generation clears the ledger; none of these operations writes the on-disk ELF. See [memory editing](05-memory-and-analysis.md) for UI behavior and partial-write cautions.

## Maps, modules, ELF sections, and relocations

- `lm`, `modules`, `linkmap`: captured module ranges and paths. `linkmap` is not a native link_map structure walk.
- `vmmap [ADDRESS-OR-NAME]`, `mmap`, `memmap`, `!address`: list mappings; resolve an address and show its containing mapping, or fall back to case-sensitive name-substring filtering if resolution fails.
- `xinfo ADDRESS`, `examine ADDRESS`: containing mapping/permissions/name/offset, module/section/file address, and available symbol.
- `piebase [MODULE-SUBSTRING]`: loaded object-header base. Without a filter use the first module; with one report matching module paths that have a loaded base.
- `got [MODULE-SUBSTRING]`: `.got` and `.got.plt` sections and available target-width slots.
- `gotplt [MODULE-SUBSTRING]`: `.got.plt` only.
- `plt [MODULE-SUBSTRING]`: `.plt` and `.plt.sec` ranges and disassembly.
- `elfsections [LLDB-ARGS]`: LLDB `image dump sections` with the supplied tail.
- `checksec`: captured local ELF PIE/NX/RELRO/canary/symbol metadata.
- `kbase`, `kchecksec`: explicitly unsupported kernel-session helpers.
- `aslr [on|off]`: query/change LLDB target.disable-aslr. `on` sets disable-aslr false, `off` true. A launch preference, not retroactive relocation of an existing process.

GOT/PLT require actual matching sections and readable relocated data. Slot enumeration is bounded to 256 per GOT section, and PLT disassembly reads a fixed instruction count. Missing sections or the known GOT/PLT limitation are not proof that imports do not exist. checksec is file metadata, not a comprehensive runtime security audit.

## Process, ABI, and operating-system helpers

- `pid`: captured process ID.
- `procinfo`: local-process `/proc/PID/status` fields and command line. Remote/QEMU sessions reject host `/proc` lookup rather than pretending it describes the guest.
- `auxv`: local `/proc/PID/auxv`, decoded using target word size/byte order with names for common AT_* entries. Requires a compatible live local process.
- `tls`: available fs_base, tpidr_el0, tp, and/or gs_base register values.
- `retaddr`: caller-frame PCs/functions from the selected thread's backtrace, not a raw-stack search.
- `canary`: inspect fs_base+0x28 when available, otherwise try `__stack_chk_guard`. ABI-dependent heuristic, not universal TLS layout knowledge.
- `errno`: evaluate target errno and label it with the host strerror description. Cross-system descriptions can differ.
- `syscalls [EXACT-NAME-OR-DECIMAL-NUMBER]`: lookup in a small built-in table, not syscall tracing or a complete ABI catalog. x86-64 has its own table; all other targets use one generic table, which must not be assumed correct for every architecture.
- `sigreturn`: display current SP/registers and an assumed syscall number. Inspection only; no signal-return frame is written.
- `valist ADDRESS`: read 24 bytes; decode the common x86-64 va_list fields there, or show raw bytes for other architectures. Not a general ABI-aware argument iterator.

## Cyclic patterns and stack inspection

- `cyclic [LENGTH]`: lowercase de Bruijn pattern, order 4, default 100 bytes, maximum 26^4 = 456,976.
- `cyclic -l VALUE`, `cyclic --lookup VALUE`: search a text or numeric value. Numeric input is converted low-byte-first irrespective of target endianness, up to eight bytes/stopping at NUL. If a longer query misses, lookup also tries its first four bytes.
- `stack_explore`: executable-mapping pointers in the captured stack window. Not a scan of every stack mapping or a complete return-address recovery pass.

```text
cyclic 64
cyclic -l 0x61616162
stack_explore
```

Crash triage can report cyclic matches, but an offset is a diagnostic clue, not proof of control-flow exploitability.

## glibc heap compatibility helpers

All commands here inspect the bounded heuristic capture described in [heap inspection](05-memory-and-analysis.md). They do not implement arbitrary glibc-version arena introspection or allocator mutations.

- `heap_config`: glibc assumption, target pointer width/order, safe-linking heuristic, 256-chunk bound, detected libc path, and walk status.
- `heap [ADDRESS]`, `malloc_chunk [ADDRESS]`, `bins [ADDRESS]`: captured chunks, optionally the chunk containing ADDRESS. malloc_chunk without an address also lists the capture.
- `vis_heap_chunks`: same captured chunks with computed next-chunk addresses.
- `fastbins [ADDRESS]`: free-looking chunks no larger than F.
- `tcachebins [ADDRESS]`: free-looking chunks no larger than T.
- `unsortedbin [ADDRESS]`: free-looking chunks larger than F.
- `smallbins [ADDRESS]`: free-looking chunks with F < size <= T.
- `largebins [ADDRESS]`: free-looking chunks larger than T.
- `arena`, `arenas`, `mp`: captured-chunk counts/bytes and heap mapping/status, not full malloc_state/malloc_par structures.
- `find_fake_fast ADDRESS`: search the preceding 0x100 bytes for aligned plausible fastbin-sized headers covering ADDRESS; read-only.
- `try_free USER-POINTER`: check whether a known discovered chunk is aligned and plausibly allocated; read-only, **does not call free**.

F is 0x50 for four-byte pointers and 0x90 otherwise; T is 0x200 for four-byte pointers and 0x400 otherwise. These ranges intentionally overlap and are size filters, not actual bin membership. Free-looking output may include raw fd/bk and a safe-linked fd candidate. Treat ambiguous or missing captures as unavailable data, not an empty allocator.

## Python console commands and LLDB forwarding

The GUI intercepts only:

```text
py run /absolute/path/to/script.py
py status
py stop
```

`py run` treats the remainder as a literal filename, not shell-quoted argv. There is no `py eval` or persistent Python REPL. The editor's traced Run/Debug differs from this untraced file job. See [Python automation](08-python-automation.md).

Unknown native commands are forwarded to LLDB with their original text. Examples include explicit `breakpoint set`, `settings set`, `process detach`, `frame variable`, and `image lookup` options. LLDB's own `script ...` is a different Python environment/API from mydbg's injected `run(dbg)` automation contract. Neither arbitrary LLDB scripting nor plugin callbacks are restricted by the bounded breakpoint-condition language.
