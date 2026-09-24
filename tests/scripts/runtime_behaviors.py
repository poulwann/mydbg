import os


def run(dbg):
    sleeper = os.environ["MYDBG_TEST_ATTACH"]
    basic = os.environ["MYDBG_TEST_BASIC"]
    interactive = os.environ["MYDBG_TEST_INTERACTIVE"]

    dbg.launch([sleeper], stop_at="main")
    dbg.continue_execution()
    try:
        dbg.wait_for_exit(timeout=0.05)
    except RuntimeError as error:
        if "timed out" not in str(error):
            raise
    else:
        raise RuntimeError("wait_for_exit unexpectedly ignored its timeout")
    dbg.terminate()

    old_process = dbg.launch([interactive], stop_at="main")
    dbg.launch([basic], stop_at="main")
    try:
        old_process.recv(timeout=0.05)
    except RuntimeError as error:
        if "generation changed" not in str(error):
            raise
    else:
        raise RuntimeError("stale process cursor crossed generations")

    terminal = dbg.continue_and_wait(timeout=5)
    if terminal.state != "exited" or terminal.exit_status != 0:
        raise RuntimeError(f"process exit during wait was lost: {terminal.state}")
    print("python-behaviors-ok")
