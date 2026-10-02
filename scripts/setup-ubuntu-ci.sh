#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y --no-install-recommends software-properties-common
sudo add-apt-repository -y universe
sudo apt-get update

sudo apt-get install -y --no-install-recommends \
  build-essential ca-certificates cmake ninja-build git pkg-config curl \
  python3 python3-dev python3-venv lldb liblldb-dev clang lld \
  libgl-dev libpng-dev libbz2-dev dpkg-dev

sudo apt-get install -y --no-install-recommends \
  libx11-dev libxext-dev libxrandr-dev libxcursor-dev libxfixes-dev libxi-dev libxss-dev \
  libwayland-dev libxkbcommon-dev wayland-protocols libegl1-mesa-dev libgl1-mesa-dev libgles2-mesa-dev \
  libdrm-dev libgbm-dev libudev-dev libasound2-dev libpulse-dev libpipewire-0.3-dev libdbus-1-dev \
  libxtst-dev libibus-1.0-dev libfribidi-dev libthai-dev libusb-1.0-0-dev libdecor-0-dev liburing-dev

./scripts/build-sdl3-ci.sh
