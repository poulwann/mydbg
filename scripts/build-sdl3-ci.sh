#!/usr/bin/env bash
set -euo pipefail

sdl_config="${PWD}/.deps/lib/cmake/SDL3/SDL3Config.cmake"
if [[ -f "${sdl_config}" ]]; then
  exit 0
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "${tmpdir}" SDL3-3.4.16' EXIT

curl --fail --show-error --location \
  --connect-timeout 20 \
  --max-time 180 \
  --retry 5 \
  --retry-delay 2 \
  --retry-connrefused \
  https://github.com/libsdl-org/SDL/releases/download/release-3.4.16/SDL3-3.4.16.tar.gz \
  -o "${tmpdir}/SDL3.tar.gz"
cmake -E tar xf "${tmpdir}/SDL3.tar.gz"
cmake -S SDL3-3.4.16 -B "${tmpdir}/SDL3-build" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX="${PWD}/.deps" \
  -DSDL_SHARED=ON \
  -DSDL_STATIC=OFF \
  -DSDL_TEST_LIBRARY=OFF
cmake --build "${tmpdir}/SDL3-build" --target install --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-1}"
