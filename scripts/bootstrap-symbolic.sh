#!/bin/sh
# Install the optional angr/angrop backend for mydbg's embedded interpreter.
#
# The interpreter must match LLDB's script interpreter (see README.md); this
# script queries LLDB, installs the pinned backend into a dedicated virtual
# environment beside the repository, and prints the PYTHONPATH to export.
#
# Usage:
#   ./scripts/bootstrap-symbolic.sh              # create/update .venv-symbolic
#   source .venv-symbolic/bin/activate           # or:
#   export MYDBG_SYMBOLIC_PYTHONPATH=.venv-symbolic/lib/python3.14/site-packages
set -eu

cd "$(dirname "$0")/.."

LLDB=${LLDB:-lldb}
INFO=$("$LLDB" --print-script-interpreter-info)
PYTHON=$(printf '%s' "$INFO" | sed -n 's/.*"executable"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
if [ -z "$PYTHON" ] || [ ! -x "$PYTHON" ]; then
  echo "error: could not query LLDB's script interpreter" >&2
  exit 1
fi
echo "Using LLDB interpreter: $PYTHON"

VENV=${MYDBG_SYMBOLIC_VENV:-.venv-symbolic}
if [ ! -x "$VENV/bin/python" ]; then
  "$PYTHON" -m venv "$VENV"
fi
"$VENV/bin/python" -m pip install -r requirements-symbolic.txt

SITE=$("$VENV/bin/python" -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')
cat <<EOF

Done. Point mydbg's embedded interpreter at the backend with:

  export MYDBG_SYMBOLIC_PYTHONPATH=$SITE

or run scripts under that environment. See docs/manual/11-symbolic-execution.md.
EOF
