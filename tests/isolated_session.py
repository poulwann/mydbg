"""Run a test with private session, home, configuration, and cache directories."""

import os
import subprocess
import sys
from pathlib import Path
import tempfile


with tempfile.TemporaryDirectory(prefix="mydbg-test-") as directory:
    environment = os.environ.copy()
    for variable, child in (
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("XDG_DATA_HOME", "data"),
        ("XDG_STATE_HOME", "state"),
        ("XDG_RUNTIME_DIR", "runtime"),
        ("MYDBG_SESSION_DIR", "sessions"),
    ):
        path = Path(directory) / child
        path.mkdir(mode=0o700)
        environment[variable] = str(path)
    raise SystemExit(subprocess.call(sys.argv[1:], env=environment))
