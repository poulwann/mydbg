#!/usr/bin/env bash
set -euo pipefail

readonly RIZIN_REVISION="5a611eee2999d312317ff90d600e37dde0f58992"
readonly RZ_GHIDRA_REVISION="c40f61621b4561da8da538ce3b12cd8892a59a93"
readonly MESON_VERSION="1.7.2"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
prefix="${MYDBG_DEPS_PREFIX:-${repo_root}/.deps}"
source_root="${prefix}/.sources"
build_root="${prefix}/.build"
stamp_file="${prefix}/.analysis-dependencies"

if (( $# != 0 )); then
  printf 'usage: %s\n' "$0" >&2
  exit 2
fi

missing=()
for command in cmake git ninja pkg-config python3 sha256sum; do
  if ! command -v "${command}" >/dev/null 2>&1; then
    missing+=("${command}")
  fi
done
if ! command -v c++ >/dev/null 2>&1; then
  missing+=("C++ compiler")
fi
if (( ${#missing[@]} != 0 )); then
  printf 'Missing tools:' >&2
  printf ' %s' "${missing[@]}" >&2
  printf '\nSee README.md#system-packages before running this script.\n' >&2
  exit 1
fi

readonly EXPECTED_STAMP="rizin=${RIZIN_REVISION}
rz-ghidra=${RZ_GHIDRA_REVISION}
rizin-cli=disabled
rizin-patch=$(sha256sum <"${repo_root}/patches/rizin-dwarf-integration.patch")
rz-ghidra-patch=$(sha256sum <"${repo_root}/patches/rz-ghidra-dwarf-types.patch")"

if [[ -f "${stamp_file}" ]] &&
   [[ "$(cat -- "${stamp_file}")" == "${EXPECTED_STAMP}" ]]; then
  printf 'Pinned Rizin and rz-ghidra dependencies are ready in %s\n' "${prefix}"
  exit 0
fi

mkdir -p -- "${source_root}" "${build_root}" "${prefix}"

meson_command="$(command -v meson || true)"
if [[ -z "${meson_command}" ]]; then
  tools_venv="${prefix}/.tools"
  if [[ ! -x "${tools_venv}/bin/meson" ]]; then
    printf 'Installing Meson %s in %s\n' "${MESON_VERSION}" "${tools_venv}"
    python3 -m venv "${tools_venv}"
    "${tools_venv}/bin/python" -m pip install \
      --disable-pip-version-check "meson==${MESON_VERSION}"
  fi
  meson_command="${tools_venv}/bin/meson"
fi

checkout_revision() {
  local repository="$1"
  local revision="$2"
  local destination="$3"

  if [[ ! -d "${destination}/.git" ]]; then
    if [[ -e "${destination}" ]]; then
      printf 'Refusing to replace non-git path: %s\n' "${destination}" >&2
      exit 1
    fi
    git clone --filter=blob:none --no-checkout "${repository}" "${destination}"
  fi
  git -C "${destination}" fetch --depth=1 origin "${revision}"
  git -C "${destination}" checkout --detach --force "${revision}"
}

rizin_source="${source_root}/rizin"
rizin_build="${build_root}/rizin"
checkout_revision \
  https://github.com/rizinorg/rizin.git \
  "${RIZIN_REVISION}" \
  "${rizin_source}"
git -C "${rizin_source}" apply "${repo_root}/patches/rizin-dwarf-integration.patch"

meson_setup_options=()
if [[ -f "${rizin_build}/build.ninja" ]]; then
  meson_setup_options+=(--reconfigure)
fi
"${meson_command}" setup "${meson_setup_options[@]}" \
  "${rizin_build}" "${rizin_source}" \
  --prefix="${prefix}" \
  --buildtype=release \
  -Dcli=disabled \
  -Denable_tests=false \
  -Denable_rz_test=false
"${meson_command}" compile -C "${rizin_build}"
"${meson_command}" install -C "${rizin_build}"

pkg_config_dirs=()
for directory in "${prefix}"/lib*/pkgconfig "${prefix}"/share/pkgconfig; do
  if [[ -d "${directory}" ]]; then
    pkg_config_dirs+=("${directory}")
  fi
done
if (( ${#pkg_config_dirs[@]} == 0 )); then
  printf 'Rizin installed without pkg-config metadata under %s\n' "${prefix}" >&2
  exit 1
fi

rz_ghidra_source="${source_root}/rz-ghidra"
rz_ghidra_build="${build_root}/rz-ghidra"
checkout_revision \
  https://github.com/rizinorg/rz-ghidra.git \
  "${RZ_GHIDRA_REVISION}" \
  "${rz_ghidra_source}"
git -C "${rz_ghidra_source}" apply "${repo_root}/patches/rz-ghidra-dwarf-types.patch"
git -C "${rz_ghidra_source}" submodule update --init --recursive --depth=1

cmake -S "${rz_ghidra_source}" -B "${rz_ghidra_build}" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${prefix}" \
  -DCMAKE_PREFIX_PATH="${prefix}" \
  -DBUILD_CUTTER_PLUGIN=OFF \
  -DBUILD_DECOMPILE_EXECUTABLE=OFF \
  -DBUILD_DECOMPILE_CLI_EXECUTABLE=OFF \
  -DBUILD_SLEIGH_PLUGIN=OFF
cmake --build "${rz_ghidra_build}" --parallel
cmake --install "${rz_ghidra_build}"

printf '%s\n' "${EXPECTED_STAMP}" >"${stamp_file}"
printf '\nPinned analysis dependencies installed in %s\n' "${prefix}"
printf 'Configure the debugger with: MYDBG_DEPS_PREFIX=%q cmake --preset dev\n' "${prefix}"
