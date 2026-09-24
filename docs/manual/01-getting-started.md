# Getting started

mydbg is a native Linux debugger for ELF programs. LLDB controls execution and live process state; Rizin and rz-ghidra provide binary analysis and decompilation. The graphical interface is SDL3/OpenGL with dockable Dear ImGui panels. Embedded Python can drive the same debugger without opening a window.

This manual describes implemented controls and APIs, not proposed integrations. Opening a program in the GUI **launches it and stops at main**; it is not a read-only file viewer. Only run targets and scripts you trust, or use an isolated debugging environment.

![A real stopped debuggee with synchronized code, registers, frames, and session state](screenshots/workspace.png)

## Find the right chapter

- [Workspace and code analysis](02-workspace.md): disassembly, graph navigation, decompilation, DWARF, registers, threads, and frames.
- [Execution and remote sessions](03-execution.md): start/stop, stepping, run-until, attach, QEMU, and native shortcuts.
- [Breakpoints, conditions, and saved sessions](04-breakpoints.md): conditional stops, SHA256 identity, durable edits, comments, and clearing.
- [Memory, scans, and inspection](05-memory-and-analysis.md): byte editing, selections and exports, patches, maps, heap, and value scanning.
- [Command reference](06-command-reference.md): mydbg commands, compatibility aliases, and LLDB forwarding.
- [Troubleshooting and safety](07-troubleshooting.md): unavailable data, errors, platform limits, and recovery.
- [Python automation](08-python-automation.md): script editor/debugger, headless workflows, and complete public API.
- [Settings and help](09-settings.md): layouts, themes, fonts, scaling, keybindings, translations, and the manual reader.
- [Native plugins](10-plugins.md): loading, ABI, commands, UI extensions, and events.

## Build requirements

Use Linux with a C++20 compiler, CMake 3.28+, Ninja or Make, Git, and pkg-config. Development headers and libraries are required for OpenGL, SDL3, libpng 1.6+, Python 3.12+, and LLDB. Python must include embedding development support and `venv`.

The `lldb` executable, headers, shared library, and embedded Python must be compatible. Check the interpreter LLDB was built against:

```sh
lldb --print-script-interpreter-info
```

CMake verifies that interpreter choice. Do not fix a mismatch by substituting an arbitrary liblldb or setting unrelated Python paths. Select the compatible interpreter at configuration time if necessary:

```sh
cmake --preset dev -DPython_EXECUTABLE=/path/to/compatible/python
```

Typical system packages, subject to distribution naming and SDL3 availability:

```sh
# Arch Linux
sudo pacman -S --needed base-devel cmake ninja git pkgconf python lldb sdl3 mesa libpng

# Debian/Ubuntu releases with SDL3 development packages
sudo apt install build-essential cmake ninja-build git pkg-config \
  python3 python3-dev python3-venv lldb liblldb-dev libsdl3-dev libgl-dev libpng-dev
```

On Nix, enter the repository development shell with `nix-shell` before building. Cross-architecture tests additionally use QEMU and LLVM tools supplied by that shell.

### Analysis dependencies

Use the repository bootstrap rather than unpatched distribution Rizin plugins. It installs the pinned Rizin 0.8.2 and rz-ghidra sources into `.deps/`, applying the tracked DWARF/type integration patches and the standalone SHA256 export used for sessions.

The first build also fetches pinned pybind11, Dear ImGui docking, ImGuiColorTextEdit, and imgui_markdown sources. Initial configuration therefore needs network access unless the dependencies are already cached.

```sh
./scripts/build.sh
```

This bootstraps analysis dependencies, configures the **dev** preset, and builds the application and fixtures in `build/dev/`. If Meson is unavailable, the bootstrap prepares its pinned local Python environment. Later builds reuse the dependency stamp; rerun the bootstrap after provider patches or pins change.

After the first bootstrap, the ordinary incremental commands are:

```sh
cmake --preset dev
cmake --build --preset dev
```

To use an existing, equivalently patched installation:

```sh
./scripts/build.sh --skip-deps
```

That selects **system-dev** in `build/system-dev/`, isolated from the bootstrapped build cache. Rizin must expose `rz_core` version 0.8.2 through pkg-config. For custom locations use `PKG_CONFIG_PATH`, `RZ_GHIDRA_INCLUDE_DIR`, and `RZ_GHIDRA_LIBRARY` at configuration time. `core_ghidra.so` needs its adjacent `rz_ghidra_sleigh/` specification directory.

For an optimized application build without tests:

```sh
./scripts/bootstrap-analysis-deps.sh
cmake --preset release
cmake --build --preset release
```

The executable is then `build/release/mydbg`. To choose a different bootstrap prefix, set `MYDBG_DEPS_PREFIX` consistently during bootstrap and initial configuration, for example `MYDBG_DEPS_PREFIX="$HOME/.cache/mydbg-deps" ./scripts/build.sh`.

There is no separate install workflow in this build. If relocating a build, keep its runtime libraries/provider assets available and retain the executable-adjacent `manual/` directory for screenshots. The chapter text itself is embedded.

## Command-line entry points

Run from the repository root in these examples:

```sh
# GUI, no target loaded
./build/dev/mydbg

# GUI: launch an ELF and stop at main
./build/dev/mydbg ./build/dev/debuggee_dwarf5_embedded

# GUI: immediately run an automation file, also loading it into the editor
./build/dev/mydbg --script ./examples/solve_ctf.py

# No GUI: immediately run an automation file
./build/dev/mydbg --headless-script ./examples/solve_ctf.py
```

`--script` is **not** an open-without-running switch. To inspect an untrusted script without executing it, start the empty GUI and use the Python editor's **Load** or **Browse** control instead.

The command line accepts one ELF path or one of those script forms; it does not accept trailing target arguments, a general command string, or a `--help` switch. Set target arguments and working directory through [launch commands or Python](03-execution.md). The `--headless` family listed below is for built-in smoke scenarios, not an interactive command-line debugger.

### First native session

1. Start `./build/dev/mydbg ./build/dev/debuggee_dwarf5_embedded` after a dev build. It should stop at main.
2. In **Breakpoints**, enter `dwarf_compute` and press Enter or **Add**.
3. Click the Disassembly panel, then press **F9** or Session's **Continue**. The program stops in dwarf_compute. The Breakpoints hit count increments.
4. Inspect the highlighted instruction, Registers, Backtrace, and Decompiler. In this fixture the decompiler can recover DwarfPayload and DwarfMode from DWARF.
5. Press **F7** for one instruction, **F8** to step over a call, or **F10/F11** for source-oriented stepping. The selected thread/frame determines the inspected state.
6. Right-click an instruction or decompiler address to add an address comment. Name/type edits and comments are automatically saved with the executable's SHA256 session.
7. Use **Launch / Restart** for another run. Quit and reopen the same bytes to recover supported authored state. Use **Clear saved session** when you want a clean analysis baseline.

The Session panel exposes launch, attach, remote connection, stepping, termination, target identity, stop reason, and persistence status. [Execution](03-execution.md) explains exactly when controls are enabled and how local and remote sessions differ.

For your own source, compile with debug information and retain the executable and its separate debug files. `-g -O0 -fno-omit-frame-pointer` is a useful initial debugging configuration; optimized code can still be inspected but source variables may be unavailable or move between locations.

## First headless automation run

The bundled CTF example is a complete workflow, not a canned transcript: it launches the challenge, waits for a prompt, sets a breakpoint, reads the per-process expected bytes, patches the candidate in live memory, and verifies the flag and exit status.

```sh
./build/dev/mydbg --headless-script ./examples/solve_ctf.py
```

The build provides the default challenge path. Override it with `MYDBG_CTF_CHALLENGE=/absolute/path/to/ctf_challenge` if needed. Scripts run with your user permissions. A failing script returns a nonzero command exit status; inspect its traceback rather than assuming a partial run succeeded.

To keep a one-off script run from changing your normal saved sessions:

```sh
session_dir=$(mktemp -d)
MYDBG_SESSION_DIR="$session_dir" ./build/dev/mydbg --headless-script ./examples/solve_ctf.py
# Remove only this newly created directory when you no longer need its session.
```

[Python automation](08-python-automation.md) gives the `run(dbg)` contract, memory/process APIs, cancellation rules, and a small starter script.

## Developer headless scenarios

These built-in entry points execute fixed scenarios and exit. Their arguments must be the corresponding fixture, not an arbitrary application with different symbols or behavior:

```sh
./build/dev/mydbg --headless-keybindings
./build/dev/mydbg --headless-condition ./build/dev/debuggee_condition
./build/dev/mydbg --headless-heap ./build/dev/debuggee_heap
./build/dev/mydbg --headless-scans ./build/dev/debuggee_scans
./build/dev/mydbg --headless-intelligence ./build/dev/debuggee_intelligence
```

`--headless EXECUTABLE [ATTACH_FIXTURE]` runs the native vertical-slice smoke scenario. It is not a replacement for `--headless-script`. Use CTest to supply the correct fixture paths:

```sh
ctest --test-dir build/dev --output-on-failure
```

Tests requiring remote stubs or cross-architecture tools need those tools installed. A passing native scenario does not prove every QEMU architecture or remote feature works; see the [current limitations](07-troubleshooting.md).

## About the screenshots

The images in this manual are captures of the actual application on an isolated off-screen X11 display, not mockups. Native debugging examples use repository fixtures; Python examples use the bundled CTF script. Crops emphasize the control being explained. Addresses, PIDs, hashes, fonts, and exact layout may differ on your machine.

Headless script mode exercises real debugger behavior without SDL. Screenshots require the graphical renderer, so capture it under Xvfb with a private executable-adjacent mydbg.ini and `MYDBG_SESSION_DIR`, rather than changing a user's desktop or saved sessions. Use PNG assets for both normal Markdown readers and the built-in manual.
