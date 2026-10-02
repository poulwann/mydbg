# mydbg

Native Linux debugger for ELF targets. LLDB runs the process. Rizin and rz-ghidra handle analysis and decompilation. Dear ImGui provides the dockable UI.

Built for reverse engineering, CTFs, exploit development, and native debugging.

## Demo

<video src="rop-review-demo.mp4" controls width="900"></video>

If your Markdown viewer does not play embedded video: [ROP review demo](rop-review-demo.mp4).

[![mydbg workspace overview](docs/manual/screenshots/overview.png)](docs/manual/screenshots/overview.png)

## Screenshots

| ROP review | Decompiler |
| --- | --- |
| [![ROP visualizer](docs/manual/screenshots/rop-visualizer.png)](docs/manual/screenshots/rop-visualizer.png) | [![Decompiler](docs/manual/screenshots/decompiler.png)](docs/manual/screenshots/decompiler.png) |

| Graph | Memory |
| --- | --- |
| [![Disassembly graph](docs/manual/screenshots/graph.png)](docs/manual/screenshots/graph.png) | [![Memory dump](docs/manual/screenshots/memory.png)](docs/manual/screenshots/memory.png) |

| Python debugger | Heap |
| --- | --- |
| [![Python debugger](docs/manual/screenshots/python-debug.png)](docs/manual/screenshots/python-debug.png) | [![Heap view](docs/manual/screenshots/heap.png)](docs/manual/screenshots/heap.png) |

## Features

- Local launch, PID attach, and remote GDB-protocol sessions.
- QEMU user/system remote debugging for cross-architecture targets.
- Disassembly, graph view, registers, stack, memory, modules, maps, threads, and backtrace.
- rz-ghidra decompiler with DWARF names, prototypes, types, and saved edits.
- Clickable call/jump/pointer navigation with history.
- Conditional breakpoints.
- Saved sessions keyed by executable SHA256.
- Memory dump, edits, patching, assembly, string scans, value scans, pointer chains, telescope, cyclic patterns.
- ELF security view and glibc heap view.
- Embedded Python automation plus source-level Python script debugging.
- Optional angr symbolic execution and angrop ROP tooling.
- Stack-driven ROP visualizer with instruction stepping, effect summaries, pivots, and live-view sync.
- Native plugin API.
- Built-in manual, themes, keybindings, scaling, persistent layout, localization catalogs.

## Build

Linux only. Use the bootstrap path unless you already have compatible Rizin/rz-ghidra builds.

```console
./scripts/build.sh
ctest --preset dev
```

Output:

```text
build/dev/mydbg
```

NixOS:

```console
nix-shell
./scripts/build.sh
```

Use system Rizin/rz-ghidra instead of bootstrapping:

```console
./scripts/build.sh --skip-deps
ctest --preset system-dev
```

Release build:

```console
./scripts/bootstrap-analysis-deps.sh
cmake --preset release
cmake --build --preset release
```

## Runtime requirements

- Linux
- C++20 compiler
- CMake 3.28+
- Ninja or Make
- pkg-config
- Python 3.12+ with embedding headers
- LLDB executable, headers, and library from the same install
- SDL3, OpenGL, libpng, bzip2
- Rizin `rz_core` 0.8.2 and matching rz-ghidra assets

Typical packages:

```console
# Arch
sudo pacman -S --needed base-devel cmake ninja git pkgconf python lldb sdl3 mesa libpng bzip2

# Debian/Ubuntu with SDL3
sudo apt install build-essential cmake ninja-build git pkg-config \
  python3 python3-dev python3-venv lldb liblldb-dev libsdl3-dev libgl-dev libpng-dev libbz2-dev
```

For full dev tests also install `lldb-server`, Clang, LLD, and QEMU user emulators.

Python must match LLDB:

```console
lldb --print-script-interpreter-info
```

If needed:

```console
cmake -S . -B build -DPython_EXECUTABLE=/path/to/lldb-compatible-python
```

## Run

```console
./build/dev/mydbg
./build/dev/mydbg ./path/to/program
./build/dev/mydbg --script ./script.py
./build/dev/mydbg --headless-script ./script.py
```

The GUI stops new launches at `main`.

Useful keys:

- `F9` continue
- `F2` breakpoint
- `F7` / `F8` instruction step
- `F11` / `F10` source step
- `F1` manual

Remote debugging:

- Start `lldb-server`, `gdbserver`, QEMU user, or QEMU system with a GDB stub.
- Pick the matching profile in **Session**.
- Enter the stub endpoint and local ELF/symbol file.

## Optional symbolic / ROP backends

```console
scripts/bootstrap-symbolic.sh
```

Provides angr, angrop, Unicorn, and Capstone for symbolic execution and ROP tracing.

Examples:

```console
./build/dev/mydbg --headless-script examples/rop_crackme.py
./build/dev/mydbg --headless-script examples/rop_emporium/solve_ret2win_x64.py
```

## Tests

```console
ctest --preset dev
```

Smaller native-only loop:

```console
cmake --preset native-dev
cmake --build --preset native-dev
ctest --preset native-dev
```

Useful labels:

```console
ctest --preset dev -L unit
ctest --preset dev -L native
ctest --preset dev -L python
ctest --preset dev -L symbolic
```

## Repo map

```text
src/app/          GUI and panels
src/backend/lldb/ LLDB engine, commands, QEMU sessions
src/scripting/    Embedded Python and bindings
src/plugins/      Native plugin API
locales/en/       English UI strings
python/mydbg/     Python support package
docs/manual/      Built-in manual and screenshots
tests/            Tests, debuggees, scenarios
examples/         Example targets and scripts
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