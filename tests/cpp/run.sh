#!/bin/sh
# Builds and tests the generated C++ code on Linux (in WSL on Windows).
# scripts/build_check.py and scripts/run_tests.py call this; it also works by hand:
#
#   sh tests/cpp/run.sh build [gcc|clang ...]    # configure + build (default: gcc clang)
#   sh tests/cpp/run.sh test  [gcc|clang ...]    # run the GoogleTest binary of each build
#
# Build directories go under ${PCAPNG_CPP_BUILD:-~/.cache/pcapng-kaitai-tests/cpp}/<compiler>,
# on the Linux filesystem: building on /mnt/c (the Windows drive in WSL) is slow.
# Exit code 3 means a tool is missing.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
action=${1:?usage: run.sh build|test [gcc|clang ...]}
shift
compilers=${*:-gcc clang}
build_root=${PCAPNG_CPP_BUILD:-$HOME/.cache/pcapng-kaitai-tests/cpp}

missing() {
    echo "missing: $1 (install with: sudo apt install g++ clang cmake ninja-build)" >&2
    exit 3
}

command -v cmake >/dev/null 2>&1 || missing cmake
command -v ninja >/dev/null 2>&1 || missing ninja

status=0
for cc in $compilers; do
    case $cc in
        gcc) cxx=g++ ;;
        clang) cxx=clang++ ;;
        *) echo "unknown compiler: $cc" >&2; exit 2 ;;
    esac
    command -v "$cxx" >/dev/null 2>&1 || missing "$cxx"
    dir="$build_root/$cc"
    echo "=== $action: $cc ($($cxx --version | head -n 1))"
    case $action in
        build)
            cmake -S "$here" -B "$dir" -G Ninja -DCMAKE_CXX_COMPILER="$cxx" -DCMAKE_BUILD_TYPE=Debug \
                -Wno-dev --log-level=WARNING >/dev/null || { status=1; continue; }
            cmake --build "$dir" || status=1
            ;;
        test)
            [ -x "$dir/pcapng_tests" ] || { echo "no build in $dir; run: sh $0 build $cc" >&2; status=1; continue; }
            "$dir/pcapng_tests" --gtest_brief=1 || status=1
            ;;
        *)
            echo "unknown action: $action" >&2; exit 2 ;;
    esac
done
exit $status
