#!/usr/bin/env bash
#
# Usage:
#   ./build.sh                                # build everything, Release/ReleaseFast
#   ./build.sh --no-zig                       # skip bootstrap build
#   ./build.sh --no-dotnet                    # skip .NET build
#   ./build.sh --zig-targets "x86_64-linux-gnu x86_64-windows-gnu"
#   CONFIG=Debug OPTIMIZE=Debug ./build.sh    # debug build both sides

set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

REPO_ROOT="$PWD"
BOOTSTRAP_DIR="$REPO_ROOT/Hauyne.Bootstrap"
BIN_DIR="$REPO_ROOT/bin"
SOLUTION="$REPO_ROOT/Hauyne.sln"

CONFIG="${CONFIG:-Release}"
OPTIMIZE="${OPTIMIZE:-ReleaseFast}"

DEFAULT_ZIG_TARGETS=(
    x86_64-linux-gnu
    x86_64-linux-musl
    x86_64-windows-gnu
)
ZIG_TARGETS=("${DEFAULT_ZIG_TARGETS[@]}")

DO_ZIG=1
DO_DOTNET=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-zig)      DO_ZIG=0; shift ;;
        --no-dotnet)   DO_DOTNET=0; shift ;;
        --zig-targets) read -ra ZIG_TARGETS <<<"$2"; shift 2 ;;
        -h|--help)     sed -n '2,9p' "$0"; exit 0 ;;
        *)             echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

check_tool() {
    local name="$1" cmd="$2" version_cmd="$3"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "missing: $name ($cmd not in PATH)" >&2
        return 1
    fi
    printf '  %-8s %s\n' "$name" "$($version_cmd 2>&1 | head -n1)"
}

missing=0
(( DO_ZIG ))    && { check_tool zig    zig    "zig version"      || missing=1; }
(( DO_DOTNET )) && { check_tool dotnet dotnet "dotnet --version" || missing=1; }
(( missing )) && exit 1

echo "  CONFIG=$CONFIG   OPTIMIZE=$OPTIMIZE"
(( DO_ZIG )) && echo "  ZIG_TARGETS=${ZIG_TARGETS[*]}"

artifact_for() {
    case "$1" in
        *windows*) echo "Hauyne.Bootstrap.dll" ;;
        *)         echo "libHauyne.Bootstrap.so" ;;
    esac
}

build_zig() {
    mkdir -p "$BIN_DIR"
    rm -f "$BIN_DIR/libHauyne.Bootstrap.so" "$BIN_DIR/Hauyne.Bootstrap.dll"
    for target in "${ZIG_TARGETS[@]}"; do
        echo "==> zig $target ($OPTIMIZE)"
        ( cd "$BOOTSTRAP_DIR" && zig build -Dtarget="$target" -Doptimize="$OPTIMIZE" )

        local artifact dest_dir
        artifact="$(artifact_for "$target")"
        dest_dir="$BIN_DIR/$target"
        mkdir -p "$dest_dir"
        mv "$BIN_DIR/$artifact" "$dest_dir/$artifact"
    done

    link_canonical() {
        local target="$1" artifact
        [[ " ${ZIG_TARGETS[*]} " == *" $target "* ]] || return 0
        artifact="$(artifact_for "$target")"
        ln -sfn "$target/$artifact" "$BIN_DIR/$artifact"
    }
    link_canonical x86_64-linux-gnu
    link_canonical x86_64-windows-gnu
}

build_dotnet() {
    echo "==> dotnet build $SOLUTION ($CONFIG)"
    dotnet build "$SOLUTION" -c "$CONFIG" --nologo
}

(( DO_ZIG ))    && build_zig
(( DO_DOTNET )) && build_dotnet

find "$BIN_DIR" -maxdepth 2 -type f \
    \( -name '*.dll' -o -name '*.so' -o -name 'Hauyne.Injector' -o -name '*.exe' \) \
    -printf '  %p\n' 2>/dev/null | sort
find "$BIN_DIR" -maxdepth 1 -type l -printf '  %p -> %l\n' 2>/dev/null | sort
