#!/usr/bin/env bash
#
# Usage:
#   ./inject.sh <process-name>
#   HAUYNE_DEBUG=1 ./inject.sh <process-name>

set -euo pipefail

cd "$(dirname "$(readlink -f "$0")")"
INJECTOR_LINK="$PWD/bin/Hauyne.Injector"

if [[ ! -x "$INJECTOR_LINK" ]]; then
    echo "injector not built: $INJECTOR_LINK" >&2
    echo "run ./build.sh first" >&2
    exit 1
fi

INJECTOR="$(readlink -f "$INJECTOR_LINK")"

if ! getcap "$INJECTOR" 2>/dev/null | grep -q cap_sys_ptrace; then
    echo "[inject] setcap cap_sys_ptrace=eip $INJECTOR (sudo)" >&2
    sudo setcap cap_sys_ptrace=eip "$INJECTOR"
fi

exec "$INJECTOR" "$@"
