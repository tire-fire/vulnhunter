#!/usr/bin/env bash
# sandbox.sh — run a command in a confined environment.
#
# DEFAULT (SANDBOX_ALLOW_NET unset or 0): network namespace is isolated.
#   Use for untrusted target-code execution (firmware detonation, local binary
#   fuzzing) — the process cannot phone home and cannot reach any network.
#   FS confinement (read-only bind of /, bind of workspace) and resource/wall
#   limits apply in both modes.
#
# SANDBOX_ALLOW_NET=1: network namespace is shared with the host.
#   Use for live in-scope probing (banner grabs, fuzz traffic to a live target)
#   and emulated-service fuzzing over loopback (the fuzzer and the qemu service
#   must both run with SANDBOX_ALLOW_NET=1 so they share 127.0.0.1).
#   FS confinement and resource/wall limits still apply.
set -u
WS="${1:?workspace dir}"; shift
[ "${1:-}" = "--" ] && shift
[ "$#" -ge 1 ] || { echo "no command given" >&2; exit 64; }
mkdir -p "$WS"; WS="$(cd "$WS" && pwd)"

ALLOWNET="${SANDBOX_ALLOW_NET:-0}"

# Resource limits applied in the child shell before exec.
LIMITS='ulimit -t 120 2>/dev/null; ulimit -v 2000000 2>/dev/null; ulimit -f 1048576 2>/dev/null;'

# Wall-clock limit: kills the sandboxed process if it blocks on IO or sleeps.
WALL="${SANDBOX_WALL_TIMEOUT:-180}"
TIMEOUT=""
command -v timeout >/dev/null 2>&1 && TIMEOUT="timeout -s KILL $WALL"

if command -v bwrap >/dev/null 2>&1; then
  NETFLAG="--unshare-net"
  [ "$ALLOWNET" = "1" ] && NETFLAG=""
  exec $TIMEOUT bwrap \
    $NETFLAG --unshare-pid --unshare-ipc --unshare-uts \
    --die-with-parent --new-session \
    --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
    --bind "$WS" "$WS" --chdir "$WS" \
    -- /usr/bin/env bash -c "$LIMITS exec \"\$@\"" _ "$@"
elif command -v unshare >/dev/null 2>&1; then
  # Fallback: no-network namespace; rely on ulimits + cwd (weaker FS isolation).
  UNS_N="-n"
  [ "$ALLOWNET" = "1" ] && UNS_N=""
  exec $TIMEOUT unshare $UNS_N -- /usr/bin/env bash -c "$LIMITS cd \"$WS\"; exec \"\$@\"" _ "$@"
else
  echo "no sandbox backend (need bwrap or unshare)" >&2; exit 69
fi
