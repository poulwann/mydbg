{ pkgs ? import <nixpkgs> {} }:

let
  llvm = pkgs.llvmPackages;
in
pkgs.mkShell {
  nativeBuildInputs = with pkgs; [
    cmake
    git
    meson
    ninja
    pkg-config
    qemu

    # Exposed for the freestanding cross-architecture test fixtures.  Use the
    # unwrapped compiler so Nix cc-wrapper hardening flags are not injected into
    # non-native targets.
    llvm.clang-unwrapped
    llvm.lld
    llvm.lldb
  ];

  buildInputs = with pkgs; [
    bzip2
    libGL
    libpng
    python3
    sdl3
    zlib

    # Provides liblldb and LLDB C++ headers for CMake's find_library/find_path.
    llvm.lldb
  ];

  shellHook = ''
    unset CC
    unset CXX

    export MYDBG_DEPS_PREFIX="''${MYDBG_DEPS_PREFIX:-$PWD/.deps}"
    export CMAKE_PREFIX_PATH="$MYDBG_DEPS_PREFIX''${CMAKE_PREFIX_PATH:+:$CMAKE_PREFIX_PATH}"
    export PKG_CONFIG_PATH="$MYDBG_DEPS_PREFIX/lib/pkgconfig:$MYDBG_DEPS_PREFIX/lib64/pkgconfig:$MYDBG_DEPS_PREFIX/share/pkgconfig''${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
  '';
}
