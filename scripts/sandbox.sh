#!/usr/bin/env bash
set -u
WS="${1:?workspace dir}"; shift
[ "${1:-}" = "--" ] && shift
[ "$#" -ge 1 ] || { echo "no command given" >&2; exit 64; }
mkdir -p "$WS"; WS="$(cd "$WS" && pwd)"

# Resource limits applied in the child shell before exec.
LIMITS='ulimit -t 120 2>/dev/null; ulimit -v 2000000 2>/dev/null; ulimit -f 1048576 2>/dev/null;'

# Wall-clock limit: kills the sandboxed process if it blocks on IO or sleeps.
WALL="${SANDBOX_WALL_TIMEOUT:-180}"
TIMEOUT=""
command -v timeout >/dev/null 2>&1 && TIMEOUT="timeout -s KILL $WALL"

if command -v bwrap >/dev/null 2>&1; then
  exec $TIMEOUT bwrap \
    --unshare-net --unshare-pid --unshare-ipc --unshare-uts \
    --die-with-parent --new-session \
    --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
    --bind "$WS" "$WS" --chdir "$WS" \
    -- /usr/bin/env bash -c "$LIMITS exec \"\$@\"" _ "$@"
elif command -v unshare >/dev/null 2>&1; then
  # Fallback: no-network namespace; rely on ulimits + cwd (weaker FS isolation).
  exec $TIMEOUT unshare -n -- /usr/bin/env bash -c "$LIMITS cd \"$WS\"; exec \"\$@\"" _ "$@"
else
  echo "no sandbox backend (need bwrap or unshare)" >&2; exit 69
fi
