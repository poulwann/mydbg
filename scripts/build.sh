#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
preset="dev"

case "${1:-}" in
  "")
    "${repo_root}/scripts/bootstrap-analysis-deps.sh"
    ;;
  "--skip-deps")
    preset="system-dev"
    shift
    ;;
  *)
    printf 'usage: %s [--skip-deps]\n' "$0" >&2
    exit 2
    ;;
esac
if (( $# != 0 )); then
  printf 'usage: %s [--skip-deps]\n' "$0" >&2
  exit 2
fi

cd -- "${repo_root}"
cmake --preset "${preset}"
cmake --build --preset "${preset}"
printf '\nBuild complete: %s/build/%s/mydbg\n' "${repo_root}" "${preset}"
printf 'Run tests with: ctest --preset %s\n' "${preset}"
