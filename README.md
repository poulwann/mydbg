# mydbg

mydbg is a native Linux debugger for ELF executables. LLDB owns process control, Rizin and rz-ghidra provide analysis and decompilation, and Dear ImGui provides a dockable graphical workspace.

The project is aimed at native debugging, reverse engineering, CTF challenges, and exploit-development workflows. It is currently Linux-only.

## Features

- LLDB-backed local launching/PID attach and remote GDB-protocol sessions for `lldb-server`, `gdbserver`, QEMU user, and QEMU system
- Synchronized disassembly, registers, backtrace, stack, memory, modules, and memory-map views
- Optional disassembly control-flow graphs with basic blocks, branch/loop edges, pan/zoom, and debugger actions
- Shared disassembly syntax colors, DWARF source/scope/type information, and inline symbol/string-pointer annotations in linear and graph views
- Rizin/rz-ghidra decompilation with automatically applied DWARF prototypes, local/global names, and record layouts
- Clickable call, jump, and pointer targets with IDA-style keyboard navigation and mouse back/forward history in disassembly and decompiler views
- Conditional breakpoints with a bounded, side-effect-free condition language
- Automatic SHA256-keyed sessions for breakpoints, expression watches, custom symbols, decompiler edits, and address comments, with one-click clearing
- Stop history, register deltas, operand resolution, branch prediction, ABI argument display, and crash triage
- Hex memory editing, instruction patching, Intel-syntax assembly, and reversible patches
- Hex/ASCII memory selection, pointer following, and C/Python/JavaScript/Rust clipboard exports with explicit endian conversion
- Binary string extraction and typed first/next value scans
- ELF security, process, glibc heap, pointer-chain, telescope, search, and cyclic-pattern tools
- Embedded Python automation and a source-level script debugger with Python-aware indentation and themed syntax highlighting
- Versioned native plugin API for commands, panels, menu items, and lifecycle callbacks
- Built-in searchable manual, configurable keybindings, themes, scaling, fonts, and persistent layouts
- Checked INI localization catalogs for first-party GUI text, console output, and diagnostics

See [`docs/manual/`](docs/manual/) for usage details and the complete command reference.

## Requirements

The build requires the following tools and development files:

| Dependency | Requirement | Purpose |
| --- | --- | --- |
| Linux | Required | Supported host and target platform |
| C++ compiler | C++20 support | Builds the application and tests |
| CMake | 3.28 or newer | Configures the project |
| Ninja or Make | Either | Executes the generated build |
| Git | Required for initial configuration | Fetches pinned third-party UI dependencies |
| pkg-config | Required | Locates Rizin |
| OpenGL development files | Required | GUI renderer |
| SDL3 development files | SDL3 CMake package | Windowing and input |
| libpng development files | 1.6 or newer | PNG screenshots in the built-in manual |
| bzip2 development files | Required | Compressed session storage |
| Python | 3.12 or newer, interpreter, embedding development files, and `venv` | Embedded scripting runtime; interpreter must match LLDB |
| LLDB | Executable, C++ headers, and shared library from one installation | Debugger backend |
| Rizin | `rz_core` exactly 0.8.2, supplied by the bootstrap script or the system | Binary and instruction analysis |
| rz-ghidra | Header, plugin, and Sleigh assets, supplied by the bootstrap script or the system | Decompilation |

CMake fetches these pinned source dependencies automatically during the first configuration:

- pybind11 3.0.1
- Dear ImGui 1.92.9b docking branch
- ImGuiColorTextEdit
- imgui_markdown

An internet connection is therefore required for the first configuration unless those `FetchContent` dependencies are already cached.

### System packages

Install the compiler and GUI/debugger development files through the host package manager. Typical package sets are:

```console
# Arch Linux
sudo pacman -S --needed base-devel cmake ninja git pkgconf python lldb sdl3 mesa libpng bzip2

# Debian/Ubuntu releases that provide SDL3
sudo apt install build-essential cmake ninja-build git pkg-config \
  python3 python3-dev python3-venv lldb liblldb-dev libsdl3-dev libgl-dev libpng-dev libbz2-dev
```

Package names vary by distribution. The `lldb` executable, LLDB headers, and LLDB shared library must come from compatible installations. Rizin and rz-ghidra do not need system packages when using the recommended bootstrap workflow below.

Development builds also require `lldb-server`, Clang, LLD, and the QEMU user-mode
executables `qemu-arm`, `qemu-mipsel`, and `qemu-ppc` for integration tests.
Install `clang lld qemu-user` on Arch Linux or Debian/Ubuntu in addition to the
packages above. The bootstrap script and supplied CMake presets require Ninja.

On NixOS, `nix-shell` uses the included `shell.nix` to provide the development
tools and system libraries. Run the build commands below inside that shell.

### Python and LLDB compatibility

The Python interpreter used for embedding must be the same interpreter reported by:

```console
lldb --print-script-interpreter-info
```

CMake checks this before compiling and rejects mismatched Python/LLDB installations. If several Python installations exist, select the compatible one explicitly:

```console
cmake -S . -B build -DPython_EXECUTABLE=/path/to/lldb-compatible-python
```

### Rizin and rz-ghidra paths

The pinned Rizin and rz-ghidra revisions require the analysis-provider patches in `patches/`, including DWARF integration and the standalone SHA256 export used by session storage. `scripts/bootstrap-analysis-deps.sh` applies them automatically and includes their hashes in its dependency stamp; rerun it when updating the project. Custom provider installations must use the same patches and matching headers/libraries, not unpatched system builds.

Rizin must expose `rz_core` version 0.8.2 through pkg-config. For a non-system installation, set `PKG_CONFIG_PATH` before configuring:

```console
export PKG_CONFIG_PATH=/path/to/rizin/lib/pkgconfig:$PKG_CONFIG_PATH
```

If rz-ghidra is installed outside standard search paths, provide its header and plugin library explicitly:

```console
cmake -S . -B build \
  -DRZ_GHIDRA_INCLUDE_DIR=/path/to/rz-ghidra/include \
  -DRZ_GHIDRA_LIBRARY=/path/to/rizin/plugins/core_ghidra.so
```

The directory containing `core_ghidra.so` must also contain the `rz_ghidra_sleigh/` specifications directory.

## Build

The recommended development workflow is:

```console
./scripts/build.sh
ctest --preset dev
```

The first command:

1. Builds the pinned Rizin 0.8.2 and rz-ghidra revisions into the ignored `.deps/` directory.
2. Installs pinned Meson 1.7.2 into a local Python virtual environment if Meson is not already available.
3. Configures the `dev` CMake preset and builds the application and tests in `build/dev/`.

The bootstrap is stamp-based; later builds skip dependency work unless the pinned revisions change. The resulting executable is `build/dev/mydbg`.

To use compatible Rizin and rz-ghidra installations already present on the system:

```console
./scripts/build.sh --skip-deps
ctest --preset system-dev
```

This uses the separate `system-dev` preset and `build/system-dev/` directory so an existing bootstrapped dependency cache cannot leak into the system build.

For an optimized application-only build:

```console
./scripts/bootstrap-analysis-deps.sh
cmake --preset release
cmake --build --preset release
```

The release executable is `build/release/mydbg`.

To keep bootstrapped analysis dependencies in another prefix, set the same environment variable during bootstrap and initial CMake configuration:

```console
MYDBG_DEPS_PREFIX="$HOME/.cache/mydbg-deps" ./scripts/build.sh
```

The equivalent manual development commands are:

```console
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```

## Run

Launch the graphical debugger without a target:

```console
./build/dev/mydbg
```

Open an ELF executable immediately:

```console
./build/dev/mydbg ./path/to/program
```

Open the GUI and immediately run a Python automation script:

```console
./build/dev/mydbg --script ./path/to/script.py
```

Run a Python automation script without the GUI:

```console
./build/dev/mydbg --headless-script ./path/to/script.py
```

The GUI initially stops launched programs at `main`. Press **F9** to start or continue, **F2** to toggle a breakpoint, **F7/F8** for instruction stepping, and **F11/F10** for source stepping.

Linux security policy can prevent attaching to unrelated processes. If attach fails, check permissions, namespaces or containers, and the host's `ptrace_scope` setting.

For remote debugging, select the matching profile in **Session**, enter the
stub endpoint, and select a local ELF or symbol image when available. QEMU
user mode uses `qemu-ARCH -g PORT PROGRAM`; QEMU system mode uses
`qemu-system-ARCH -S -gdb tcp::PORT`. x86 targets default to destination-first
Intel syntax. Other architectures use LLDB's architecture-native formatting;
the Intel/AT&T switch is not applied to them.

## Localization

First-party runtime text lives in `locales/en/*.ini`, grouped by subsystem.
CMake generates descriptive `l10n::Key` identifiers and embeds the English
catalogs in the executable; normal startup does not depend on external files.
For example, the restart button uses `l10n::label(l10n::Key::GuiPanelsLaunchRestart)`,
not a hardcoded caption.

Select a UTF-8 translation file or directory before starting the application:

```console
MYDBG_TRANSLATION=/path/to/fr.ini ./build/dev/mydbg
MYDBG_TRANSLATION=/path/to/fr ./build/dev/mydbg --headless-script script.py
```

Overrides may contain only the keys being translated. Missing keys use embedded
English. Catalogs load once per process; restart to change languages. A directory
loads its immediate `.ini` files in filename order. Duplicate keys, including
duplicates across files, are errors rather than overrides.

Values are JSON-quoted strings inside INI sections:

```ini
[labels]
WindowSession = "Séance"
GuiPanelsLaunchRestart = "Relancer"

[strings]
GuiPanelsContinue = "Continuer"

[formats]
GuiPanelsState = "État : %s"
```

Use the same section as the English key: `[labels]` for widget identities,
`[strings]` for plain text, and `[formats]` for printf messages. Keep key names
unchanged. Labels receive stable hidden ImGui IDs automatically; do not add `##`.
Existing English window layouts are migrated, so translating titles does not
reset their positions or docking identities.

Preserve printf argument types, including width/precision arguments. Positional
forms such as `%2$s: %1$s` allow reordering; when used, all arguments must be
positional. Keep portable integer tokens such as `%@PRIx64@`. Use `%%` for a
literal percent only in `[formats]`; plain strings and labels use `%`.
JSON escapes such as `\n`, `\"`, and `\u00e9` are supported. NUL-separated choice
lists use `\u0000`; preserve their option order, separator count, and ending.
Invalid catalogs are rejected atomically with a diagnostic and English fallback.

Command keywords, register names, Python API/status tokens, protocol fields,
and configuration keys remain stable identifiers, not translations. Target
output and third-party diagnostics remain as supplied. Manual chapters already
live separately as Markdown assets.

When adding text, add a descriptive key to the appropriate English catalog and
rebuild. Use `l10n::text`, `l10n::label`, or `l10n::format` according to its role.
Do not pass plain translated text as a printf format string. The build copies
the catalogs beside the executable as translator references.

Native plugins must be rebuilt for ABI version 2: registry command execution
now reports caught exceptions separately from their translated diagnostic.
Command callback signatures are unchanged.

## Test

Build with the `dev` preset, then run the complete CTest suite:

```console
ctest --preset dev
```

The suite covers catalog validation and translation-independent command status, the condition language, LLDB commands, launching and attaching, remote GDB-protocol sessions, QEMU cross-architecture fixtures, heap and value scanning, stop intelligence, Python/LLDB coexistence, scripting, plugins, and the headless CTF example.

## Project layout

```text
src/app/                 GUI, panels, headless runners, and application startup
src/backend/lldb/        LLDB worker, snapshots, scans, and backend utilities
src/backend/decompiler/  Rizin/rz-ghidra decompiler worker
src/backend/conditions/  Conditional-breakpoint parser and evaluator
src/scripting/           Embedded Python host, runtime, and bindings
src/plugins/             Native plugin API and loader
src/localization/         Catalog loading, validation, and checked lookup API
locales/en/               English runtime text and descriptive localization keys
python/mydbg/             Python-facing support package
docs/manual/             Built-in user manual
mydbg_default.ini        Compile-time baseline workspace layout
tests/                   Unit, integration, debuggee, plugin, and script fixtures
examples/                 Example ELF targets and Python automation
```

The repository-root `mydbg_default.ini` is compiled into the executable as its first-launch baseline. Runtime UI changes are written to `mydbg.ini` beside the executable and override that baseline on subsequent launches.

The GUI and debugger communicate through copied snapshots. LLDB objects remain on the debugger worker thread; the UI consumes immutable application-level state. This separation keeps GUI rendering independent from process-control operations.

## Further documentation

- [Getting started](docs/manual/01-getting-started.md)
- [Workspace and code analysis](docs/manual/02-workspace.md)
- [Execution and remote sessions](docs/manual/03-execution.md)
- [Breakpoints, conditions, and saved sessions](docs/manual/04-breakpoints.md)
- [Memory and analysis](docs/manual/05-memory-and-analysis.md)
- [Command reference](docs/manual/06-command-reference.md)
- [Troubleshooting and safety](docs/manual/07-troubleshooting.md)
- [Python automation and script debugging](docs/manual/08-python-automation.md)
- [Settings, layout, localization, and help](docs/manual/09-settings.md)
- [Native plugins](docs/manual/10-plugins.md)

Press F1 in the GUI to read the manual. Chapter text is embedded; keep the
generated `manual/` directory beside
the executable for screenshots. Building `mydbg` refreshes that asset directory
even when only an image changed.
