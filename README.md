# mydbg

Debugger for reversing ELF files on Linux.

LLDB for control. Rizin/rz-ghidra for analysis. ImGui for the workspace. Python, heap tools, patches, scans, symbolic execution, and ROP review live beside the debugger instead of in five separate terminals.

## Video

<video src="rop-review-demo.mp4" controls width="100%"></video>

[Open video](rop-review-demo.mp4)

[![mydbg workspace](docs/manual/screenshots/overview.png)](docs/manual/screenshots/overview.png)

## Why

Normal debuggers give you registers and a prompt. Reversing needs the rest of the loop:

- disassemble
- decompile
- follow memory
- patch code
- inspect heap state
- script the target
- run remote/QEMU stubs
- review ROP chains before trying them

mydbg keeps that loop in one UI.

## Run it

```console
./scripts/build.sh
./build/dev/mydbg ./path/to/elf
```

New launches stop at `main`.

```text
F9       continue
F2       breakpoint
F7/F8    instruction step
F11/F10  source step
F1       manual
```

## Code view

| Graph | Decompiler |
| --- | --- |
| [![Disassembly graph](docs/manual/screenshots/graph.png)](docs/manual/screenshots/graph.png) | [![Decompiler](docs/manual/screenshots/decompiler.png)](docs/manual/screenshots/decompiler.png) |

- linear + graph disassembly
- rz-ghidra decompiler
- DWARF names, prototypes, records, source context
- clickable calls, jumps, pointers
- navigation history
- saved comments, symbols, watches, breakpoints, decompiler edits

## Exploit view

| ROP | Heap |
| --- | --- |
| [![ROP visualizer](docs/manual/screenshots/rop-visualizer.png)](docs/manual/screenshots/rop-visualizer.png) | [![Heap view](docs/manual/screenshots/heap.png)](docs/manual/screenshots/heap.png) |

| Memory | Inspect |
| --- | --- |
| [![Memory dump](docs/manual/screenshots/memory.png)](docs/manual/screenshots/memory.png) | [![Inspection view](docs/manual/screenshots/inspection.png)](docs/manual/screenshots/inspection.png) |

Tools:

- hex/ASCII memory dump
- memory edits
- instruction patching
- Intel syntax assembly
- string scans
- typed value scans
- pointer chains
- telescope
- cyclic patterns
- ELF security
- glibc heap view

ROP viewer:

- start from a stack slot or `$sp`
- step by instruction or gadget
- see return edges and stack pivots
- see register and memory effects in graph rows
- sync Disassembly / Memory to the simulated cursor
- clipped rows stay readable; hover shows full text

The ROP simulation uses captured state. It does not run the target.

## Python

[![Python debugger](docs/manual/screenshots/python-debug.png)](docs/manual/screenshots/python-debug.png)

```console
./build/dev/mydbg --script ./script.py
./build/dev/mydbg --headless-script ./script.py
```

Examples:

```console
./build/dev/mydbg --headless-script examples/rop_crackme.py
./build/dev/mydbg --headless-script examples/solve_symbolic.py
./build/dev/mydbg --headless-script examples/rop_emporium/solve_ret2win_x64.py
```

## Targets

- local launch
- PID attach
- `lldb-server`
- `gdbserver`
- QEMU user stubs
- QEMU system stubs

Open **Session**, pick the profile, enter the stub endpoint, add the local ELF or symbols.

## Stack

| Task | Backend |
| --- | --- |
| process control | LLDB |
| binary analysis | Rizin |
| decompile | rz-ghidra |
| graph / UI | Dear ImGui |
| automation | embedded Python |
| symbolic execution | angr, optional |
| ROP chains | angrop, optional |
| emulation | Unicorn + Capstone, optional |
| remote targets | GDB protocol / QEMU |
| saved state | executable SHA256 |

## Build

Linux only.

```console
./scripts/build.sh
ctest --preset dev
```

Binary:

```text
build/dev/mydbg
```

NixOS:

```console
nix-shell
./scripts/build.sh
```

System Rizin/rz-ghidra instead of bootstrapped deps:

```console
./scripts/build.sh --skip-deps
ctest --preset system-dev
```

Release:

```console
./scripts/bootstrap-analysis-deps.sh
cmake --preset release
cmake --build --preset release
```

## Requirements

- Linux
- C++20 compiler
- CMake 3.28+
- Ninja or Make
- pkg-config
- Python 3.12+ with embedding headers
- LLDB executable, headers, and library from the same install
- SDL3, OpenGL, libpng, bzip2
- Rizin `rz_core` 0.8.2 and matching rz-ghidra assets

Packages:

```console
# Arch
sudo pacman -S --needed base-devel cmake ninja git pkgconf python lldb sdl3 mesa libpng bzip2

# Debian/Ubuntu with SDL3
sudo apt install build-essential cmake ninja-build git pkg-config \
  python3 python3-dev python3-venv lldb liblldb-dev libsdl3-dev libgl-dev libpng-dev libbz2-dev
```

Full tests also need `lldb-server`, Clang, LLD, and QEMU user emulators.

Python must match LLDB:

```console
lldb --print-script-interpreter-info
```

Override:

```console
cmake -S . -B build -DPython_EXECUTABLE=/path/to/lldb-compatible-python
```

## Optional symbolic / ROP deps

```console
scripts/bootstrap-symbolic.sh
```

Installs angr, angrop, Unicorn, and Capstone into `.venv-symbolic`.

## Tests

```console
ctest --preset dev
```

Native-only loop:

```console
cmake --preset native-dev
cmake --build --preset native-dev
ctest --preset native-dev
```

Labels:

```console
ctest --preset dev -L unit
ctest --preset dev -L native
ctest --preset dev -L python
ctest --preset dev -L symbolic
```

## Tree

```text
src/app/           GUI and panels
src/backend/lldb/  LLDB engine, commands, QEMU sessions
src/scripting/     embedded Python and bindings
src/plugins/       native plugin API
locales/en/        English UI strings
python/mydbg/      Python package
docs/manual/       manual and screenshots
tests/             tests, debuggees, scenarios
examples/          targets and scripts
```

## Manual

- [Getting started](docs/manual/01-getting-started.md)
- [Workspace and code analysis](docs/manual/02-workspace.md)
- [Execution and remote sessions](docs/manual/03-execution.md)
- [Breakpoints](docs/manual/04-breakpoints.md)
- [Memory and analysis](docs/manual/05-memory-and-analysis.md)
- [Command reference](docs/manual/06-command-reference.md)
- [Troubleshooting](docs/manual/07-troubleshooting.md)
- [Python automation](docs/manual/08-python-automation.md)
- [Settings and help](docs/manual/09-settings.md)
- [Plugins](docs/manual/10-plugins.md)
- [Symbolic execution and ROP](docs/manual/11-symbolic-execution.md)

Press `F1` in the GUI for the same manual.