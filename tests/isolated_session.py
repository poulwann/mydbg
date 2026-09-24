"""Run an existing program test without reading or changing a user's sessions."""

import os
import subprocess
import sys
import tempfile


with tempfile.TemporaryDirectory(prefix="mydbg-test-session-") as directory:
    environment = os.environ.copy()
    environment["MYDBG_SESSION_DIR"] = directory
    raise SystemExit(subprocess.call(sys.argv[1:], env=environment))
