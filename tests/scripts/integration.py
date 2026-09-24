import os

module_run_count = globals().get("module_run_count", 0) + 1


def run(dbg):
    if module_run_count != 1:
        raise RuntimeError("script namespace was reused")

    executable = os.environ["MYDBG_TEST_INTERACTIVE"]
    working_directory = os.environ["MYDBG_TEST_WORKING_DIRECTORY"]
    process = dbg.launch(
        [executable, "python"],
        stop_at="main",
        environment={"MYDBG_SCRIPT_TEST": "runtime"},
        cwd=working_directory,
    )
    marker = dbg.evaluate("&script_marker")
    if marker.numeric_value is None:
        raise RuntimeError("marker expression is not numeric")
    original = dbg.read_memory(marker.numeric_value, 8)
    if original != bytes.fromhex("8877665544332211"):
        raise RuntimeError(f"unexpected marker bytes: {original!r}")
    patched = 0xAABBCCDDEEFF0011
    dbg.write_memory(marker.numeric_value, patched.to_bytes(8, "little"))
    pc = dbg.read_register("pc")
    dbg.write_register("pc", pc)
    dbg.set_breakpoint("script_checkpoint")

    dbg.continue_execution()
    process.sendline(b"python\x00payload")
    stop = dbg.wait_for_stop(timeout=5)
    ready = process.recvuntil(b"stderr-ready\r\n", timeout=5)
    if b"ready arg=python env=runtime cwd=" not in ready:
        raise RuntimeError(f"missing ready output: {ready!r}")
    if stop.state != "stopped":
        raise RuntimeError(f"unexpected stop: {stop.state}")
    dbg.continue_execution()
    expected = b"marker=0xaabbccddeeff0011 binary=707974686f6e007061796c6f6164"
    echoed = process.recvuntil(expected, timeout=5)
    if expected not in echoed:
        raise RuntimeError(f"missing echo output: {echoed!r}")
    exited = dbg.wait_for_exit(timeout=5)
    if exited.exit_status != 0:
        raise RuntimeError(f"debuggee exited with {exited.exit_status}")
    dbg.restart(timeout=5)
    dbg.terminate(timeout=5)
    print("python-runtime-ok")
