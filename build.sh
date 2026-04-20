#!/usr/bin/env bash
#
# Usage:
#   ./build.sh                                # build everything, Release/ReleaseFast
#   ./build.sh --no-zig                       # skip bootstrap + injector build
#   ./build.sh --no-dotnet                    # skip Payload build
#   ./build.sh --zig-targets "x86_64-linux-gnu x86_64-windows-gnu"
#   CONFIG=Debug OPTIMIZE=Debug ./build.sh    # debug build both sides

set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"

REPO_ROOT="$PWD"
BOOTSTRAP_DIR="$REPO_ROOT/Hauyne.Bootstrap"
INJECTOR_DIR="$REPO_ROOT/Hauyne.Injector"
PAYLOAD_CSPROJ="$REPO_ROOT/Hauyne.Payload/Hauyne.Payload.csproj"
BIN_DIR="$REPO_ROOT/bin"

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

bootstrap_artifact_for() {
    case "$1" in
        *windows*) echo "Hauyne.Bootstrap.dll" ;;
        *)         echo "libHauyne.Bootstrap.so" ;;
    esac
}

injector_artifact_for() {
    case "$1" in
        *windows*) echo "Hauyne.Injector.exe" ;;
        *)         echo "Hauyne.Injector" ;;
    esac
}

build_zig() {
    mkdir -p "$BIN_DIR"
    rm -f "$BIN_DIR/libHauyne.Bootstrap.so" "$BIN_DIR/Hauyne.Bootstrap.dll"
    rm -f "$BIN_DIR/Hauyne.Injector" "$BIN_DIR/Hauyne.Injector.exe"

    for target in "${ZIG_TARGETS[@]}"; do
        echo "==> zig bootstrap $target ($OPTIMIZE)"
        ( cd "$BOOTSTRAP_DIR" && zig build -Dtarget="$target" -Doptimize="$OPTIMIZE" )

        echo "==> zig injector $target ($OPTIMIZE)"
        ( cd "$INJECTOR_DIR" && zig build -Dtarget="$target" -Doptimize="$OPTIMIZE" )

        local dest_dir
        dest_dir="$BIN_DIR/$target"
        mkdir -p "$dest_dir"

        local bs_artifact inj_artifact
        bs_artifact="$(bootstrap_artifact_for "$target")"
        inj_artifact="$(injector_artifact_for "$target")"

        mv "$BIN_DIR/$bs_artifact"  "$dest_dir/$bs_artifact"
        mv "$BIN_DIR/$inj_artifact" "$dest_dir/$inj_artifact"
    done

    link_canonical() {
        local target="$1"
        [[ " ${ZIG_TARGETS[*]} " == *" $target "* ]] || return 0

        local bs_artifact inj_artifact
        bs_artifact="$(bootstrap_artifact_for "$target")"
        inj_artifact="$(injector_artifact_for "$target")"

        ln -sfn "$target/$bs_artifact"  "$BIN_DIR/$bs_artifact"
        ln -sfn "$target/$inj_artifact" "$BIN_DIR/$inj_artifact"
    }
    link_canonical x86_64-linux-gnu
    link_canonical x86_64-windows-gnu
}

build_dotnet() {
    echo "==> dotnet build Hauyne.Payload ($CONFIG)"
    dotnet build "$PAYLOAD_CSPROJ" -c "$CONFIG" --nologo
}

# Bootstrap resolves Hauyne.Payload.dll relative to its own .so directory (dladdr),
# so symlink the payload into each per-target subdir.
payload() {
    (( DO_ZIG )) || return 0
    for target in "${ZIG_TARGETS[@]}"; do
        local dest="$BIN_DIR/$target"
        [[ -d "$dest" ]] || continue
        [[ -f "$BIN_DIR/Hauyne.Payload.dll" ]] || continue
        ln -sfn "../Hauyne.Payload.dll" "$dest/Hauyne.Payload.dll"
    done
}

(( DO_ZIG ))    && build_zig
(( DO_DOTNET )) && build_dotnet
payload

find "$BIN_DIR" -maxdepth 2 -type f \
    \( -name '*.dll' -o -name '*.so' -o -name 'Hauyne.Injector' -o -name '*.exe' \) \
    -printf '  %p\n' 2>/dev/null | sort
find "$BIN_DIR" -maxdepth 1 -type l -printf '  %p -> %l\n' 2>/dev/null | sort
