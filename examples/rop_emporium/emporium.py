"""Shared machinery for solving ROP Emporium challenges inside mydbg.

The engine spawns and owns the qemu-user stub (connect_remote with `qemu=`),
delivers raw stdin to the target (stdin_file=, or send_stdin through the
owned pipe), and binds symbol breakpoints through pending mode once the
target image maps — so the solve scripts stay small.

Sysroots: /tmp/sysroots/<name> built from Debian target glibc packages
(see docs/manual/11-symbolic-execution.md); override with MYDBG_ROP_SYSROOTS.
"""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path

from mydbg import symbolic

CHALLENGE_ROOT = (Path(__file__).resolve().parent / "rop_emporium" /
                  "rop_emporium_all_challenges")
SYSROOT_ROOT = Path(os.environ.get("MYDBG_ROP_SYSROOTS", "/tmp/sysroots"))
QEMU_TABLE = {
    "x64": ("qemu-x86_64", "x64"),
    "i386": ("qemu-i386", "i386"),
    "arm": ("qemu-arm", "armel"),
    "armhf": ("qemu-arm", "armhf"),
    "mipsel": ("qemu-mipsel", "mipsel"),
}
FOLDERS = {"x64": "x64", "i386": "32bit", "arm": "armv5", "mipsel": "mipsel"}
LINUX_LOADER = "/nix/store/2q9bh89ybmyf54mbzszdixl1gwd2gnhs-glibc-multi-2.40-218/lib/ld-linux-x86-64.so.2"


def require_sysroots(archs: tuple[str, ...]) -> None:
    """Exit with the harness skip code when a challenge's sysroot is absent.

    The sysroots are environment provisioning (Debian target glibc packages,
    see the manual); tests skip instead of failing where they were not built.
    """
    missing = []
    for arch in archs:
        if arch not in QEMU_TABLE:
            raise RuntimeError(f"unknown emporium arch {arch!r}")
        sysroot_name = QEMU_TABLE[arch][1]
        if sysroot_name and not (SYSROOT_ROOT / sysroot_name).is_dir():
            missing.append(f"{arch}:{SYSROOT_ROOT / sysroot_name}")
    if missing:
        print("skip: missing sysroots " + ", ".join(missing))
        raise SystemExit(77)


def challenge_path(arch: str, challenge: str) -> str:
    if arch not in FOLDERS:
        raise RuntimeError(f"unknown emporium arch {arch!r}")
    return str(CHALLENGE_ROOT / FOLDERS[arch] / challenge)


def qemu_connect(dbg, arch: str, binary: str, *, payload: bytes = b"",
                 arguments: tuple[str, ...] = (), timeout: float = 60.0):
    """Start an engine-owned qemu-user session with the payload on stdin.

    The engine spawns qemu, redirects the target's stdin to a payload file
    (raw bytes, no pty), connects to the stub, and tears the stub down with
    the session. Returns the process handle.
    """
    if arch not in QEMU_TABLE:
        raise RuntimeError(f"unknown emporium arch {arch!r}")
    qemu, sysroot_name = QEMU_TABLE[arch]
    sysroot = SYSROOT_ROOT / sysroot_name if sysroot_name else ""
    if sysroot and not Path(sysroot).is_dir():
        raise RuntimeError(f"missing sysroot {sysroot}; build it per the manual")
    stdin_file = ""
    if payload:
        with tempfile.NamedTemporaryFile(prefix="mydbg-rop-", delete=False) as handle:
            handle.write(payload)
            stdin_file = handle.name
    return dbg.connect_remote(binary, "", mode="qemu-user", timeout=timeout,
                              qemu=qemu, sysroot=str(sysroot),
                              arguments=list(arguments),
                              cwd=str(CHALLENGE_ROOT / FOLDERS[arch]),
                              stdin_file=stdin_file)


def native_connect(dbg, binary: str, *, input_path: str | None = None,
                   timeout: float = 30.0):
    """Launch natively through the system loader (NixOS needs an explicit one)."""
    return dbg.launch([LINUX_LOADER, binary], stop_at="main",
                      timeout=timeout,
                      stdin_path=input_path if input_path else "")


def _project_of(dbg):
    """angr project for the session's main binary."""
    snapshot = dbg.snapshot()
    if not (snapshot.target_path and Path(snapshot.target_path).is_file()):
        raise RuntimeError("no target image available")
    return symbolic._entry_project(dbg, binary=snapshot.target_path)  # noqa: SLF001


def symbol(dbg, name: str) -> int:
    """Resolve a main-binary symbol from the angr project, not the session.

    qemu-user stops dynamic binaries at the dynamic loader where session-side
    symbol resolution is unavailable; the project's own symbol table is
    authoritative for these static, non-PIE challenge binaries.
    """
    return symbolic.resolve_project_symbol(_project_of(dbg), name)


def after_read_address_in_project(project, *, pwnme: str = "pwnme",
                                  callees: tuple[str, ...] = ("read", "fgets", "gets")) -> int:
    """Address of the first instruction after pwnme's input call (project-based).

    Walks pwnme's blocks with angr. Direct calls match the PLT stub; MIPS PIC
    calls go through ``jalr $t9`` with $t9 loaded from a GOT slot, so the
    loaded offset is matched against the object's relocations (the static $gp
    value comes from pwnme's own ``lui/addiu`` pair).
    """
    plt = project.loader.main_object.plt
    targets = {plt[name] for name in callees if name in plt}
    got_slots: dict[int, str] = {}
    for relocation in project.loader.main_object.relocs:
        name = getattr(getattr(relocation, "symbol", None), "name", "")
        if name in callees:
            got_slots[relocation.rebased_addr] = name

    gp_value = None
    address = symbolic.resolve_project_symbol(project, pwnme)
    for _ in range(24):
        if not (project.loader.min_addr <= address < project.loader.max_addr):
            break
        block = project.factory.block(address)
        vex = block.vex
        if gp_value is None:
            for insn in block.capstone.insns:
                # lui $gp, high; addiu $gp, $gp, low — the PIC base.
                if insn.mnemonic == "lui" and "$gp" in insn.op_str:
                    high = int(insn.op_str.split(", ")[1], 16) << 16
                    gp_value = high
                elif gp_value is not None and insn.mnemonic == "addiu" \
                        and insn.op_str.startswith("$gp, $gp"):
                    low = int(insn.op_str.split(", ")[2], 16)
                    if low >= 0x8000:
                        low -= 0x10000
                    gp_value += low
                    break
        if vex.jumpkind == "Ijk_Call":
            callee = None
            call_target = vex.next
            if hasattr(call_target, "con"):  # pyvex Const wraps the address
                call_target = call_target.con.value
            if isinstance(call_target, int) and call_target in targets:
                callee = call_target
            elif gp_value is not None:
                # The PIC callee address is loaded from a GOT slot into any
                # register (often $v0, then moved to $t9) before jalr.
                for insn in block.capstone.insns:
                    if insn.mnemonic == "lw" and "$gp)" in insn.op_str:
                        offset_text = insn.op_str.split("(")[0].split(", ")[1]
                        slot = gp_value + int(offset_text, 16)
                        if slot in got_slots and got_slots[slot] in callees:
                            callee = slot
            if callee is not None:
                imarks = [s for s in vex.statements if s.tag == "Ist_IMark"]
                last = imarks[-1]
                return last.addr + last.len
            # The walk continues on the RETURN side of a call, never into the
            # callee: vex.next of a call block is the callee address.
            imarks = [s for s in vex.statements if s.tag == "Ist_IMark"]
            last = imarks[-1]
            nxt = last.addr + last.len
        else:
            nxt = vex.next
        if isinstance(nxt, object) and hasattr(nxt, "con"):  # pyvex Const
            nxt = nxt.con.value
        if not isinstance(nxt, int) or not (project.loader.min_addr <= nxt < project.loader.max_addr):
            break
        address = nxt
    raise RuntimeError(f"no {callees} call found in {pwnme}")


def library_base_via_link_map(dbg, needle: str) -> int:
    """Runtime base of a loaded library, walked from the guest's r_debug.

    qemu-user's gdbstub does not report guest libraries as modules, so the
    classic native technique applies: read DT_DEBUG from the (static-address)
    .dynamic, follow r_debug->r_map, and match l_name. Requires a stop after
    the dynamic loader ran (e.g. __libc_csu_init).
    """
    project = _project_of(dbg)
    dynamic = None
    for section in project.loader.main_object.sections:
        if section.name == ".dynamic":
            dynamic = section.vaddr
    if dynamic is None:
        raise RuntimeError("the main image has no .dynamic section")
    debug_pointer = None
    for index in range(64):
        tag = int.from_bytes(dbg.read_memory(dynamic + index * 16, 8), "little")
        if tag == 0:
            break
        value = int.from_bytes(dbg.read_memory(dynamic + index * 16 + 8, 8), "little")
        if tag == 21:  # DT_DEBUG
            debug_pointer = value
    if not debug_pointer:
        raise RuntimeError("DT_DEBUG was not populated (loader did not run?)")
    link_map = int.from_bytes(dbg.read_memory(debug_pointer + 8, 8), "little")
    for _ in range(64):
        if not link_map:
            break
        base = int.from_bytes(dbg.read_memory(link_map, 8), "little")
        name_pointer = int.from_bytes(dbg.read_memory(link_map + 8, 8), "little")
        name_bytes = b""
        if name_pointer:
            for offset in range(0, 256, 32):
                name_bytes += dbg.read_memory(name_pointer + offset, 32)
                if b"\x00" in name_bytes:
                    break
        name = name_bytes.split(b"\x00")[0].decode(errors="replace")
        if needle in name and base:
            return base
        link_map = int.from_bytes(dbg.read_memory(link_map + 24, 8), "little")
    raise RuntimeError(f"library matching {needle!r} not found in the link map")


def after_read_address(dbg, *, pwnme: str = "pwnme",
                       callees: tuple[str, ...] = ("read", "fgets", "gets")) -> int:
    """Session wrapper over ``after_read_address_in_project``."""
    return after_read_address_in_project(_project_of(dbg), pwnme=pwnme,
                                         callees=callees)


def drain(process, seconds: float = 3.0) -> bytes:
    """Collect target output, following until it stops growing.

    qemu's guest-side stdio buffers mean the success text can arrive in
    bursts; a single recv loses the tail.
    """
    collected = b""
    deadline = time.time() + seconds
    quiet = 0.0
    while time.time() < deadline:
        try:
            chunk = bytes(process.recv(65536, timeout=0.4))
        except Exception:  # noqa: BLE001 - target exited or no output yet
            chunk = b""
        if chunk:
            collected += chunk
            quiet = 0.0
        else:
            quiet += 0.4
            if collected and quiet >= 1.0:
                break
            time.sleep(0.1)
    return collected
