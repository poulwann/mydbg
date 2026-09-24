def nested_failure():
    raise RuntimeError("intentional traceback")


def run(dbg):
    nested_failure()
