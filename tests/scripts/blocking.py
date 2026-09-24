import os


def run(dbg):
    sleeper = os.environ["MYDBG_TEST_ATTACH"]
    dbg.launch([sleeper], stop_at="main")
    dbg.continue_execution()
    print("blocking-start", flush=True)
    dbg.wait_for_exit(timeout=30)
