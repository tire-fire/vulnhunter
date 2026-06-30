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
#
# BACKENDS, in order of preference:
#   1. bwrap    — full FS + net + pid/ipc/uts isolation (best).
#   2. unshare  — net (+pid/ipc/uts) namespace; weaker FS isolation. PROBED at
#                 runtime: `command -v unshare` is not enough, because restricted
#                 or rootless hosts ship the binary but deny namespace creation
#                 ("unshare: Operation not permitted"). We test it actually works
#                 before committing to it (otherwise the old code exec'd a doomed
#                 unshare and the whole sandbox failed instead of degrading).
#   3. degraded — resource/wall limits + cwd ONLY, no FS/net isolation. OPT-IN via
#                 SANDBOX_DEGRADED_OK=1. Intended for emulation of EXTRACTED code
#                 that does no host/network I/O (e.g. `qemu-arm -L rootfs` of a
#                 single function, or pyghidra p-code emulation). DO NOT use it to
#                 detonate untrusted network-active code.
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

# Probe whether unshare can actually create the namespaces we need on THIS host,
# echoing the working flag set. Returns non-zero if unshare is unusable at runtime.
pick_working_unshare() {
  local nflag="-n"; [ "$ALLOWNET" = "1" ] && nflag=""
  # Plain namespace creation (needs CAP_SYS_ADMIN or sysctl-enabled userns).
  if unshare $nflag true 2>/dev/null; then echo "$nflag"; return 0; fi
  # Rootless fallback: map our uid to root inside a fresh user namespace.
  if unshare -r $nflag true 2>/dev/null; then echo "-r $nflag"; return 0; fi
  return 1
}

if command -v bwrap >/dev/null 2>&1; then
  NETFLAG="--unshare-net"
  [ "$ALLOWNET" = "1" ] && NETFLAG=""
  exec $TIMEOUT bwrap \
    $NETFLAG --unshare-pid --unshare-ipc --unshare-uts \
    --die-with-parent --new-session \
    --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp \
    --bind "$WS" "$WS" --chdir "$WS" \
    -- /usr/bin/env bash -c "$LIMITS exec \"\$@\"" _ "$@"
elif command -v unshare >/dev/null 2>&1 && UNS="$(pick_working_unshare)"; then
  # Fallback: namespace isolation; weaker FS isolation (cwd only).
  exec $TIMEOUT unshare $UNS -- /usr/bin/env bash -c "$LIMITS cd \"$WS\"; exec \"\$@\"" _ "$@"
elif [ "${SANDBOX_DEGRADED_OK:-0}" = "1" ]; then
  # Degraded: resource/wall limits + cwd only. NO FS or network isolation.
  echo "sandbox: WARNING degraded mode — no FS/network isolation (bwrap absent; unshare unusable on this host). Resource/wall limits still apply. Only run code you accept executing unconfined (emulation of extracted code with no host/network I/O)." >&2
  [ "$ALLOWNET" = "1" ] || echo "sandbox: WARNING SANDBOX_ALLOW_NET=0 requested but cannot be enforced in degraded mode — network is NOT isolated." >&2
  exec $TIMEOUT /usr/bin/env bash -c "$LIMITS cd \"$WS\"; exec \"\$@\"" _ "$@"
else
  echo "no working sandbox backend: bwrap not installed, and unshare is $(command -v unshare >/dev/null 2>&1 && echo 'present but failed at runtime (restricted user namespaces)' || echo 'not installed')." >&2
  echo "Re-run with SANDBOX_DEGRADED_OK=1 to execute with resource/wall limits only (NO fs/net isolation) — appropriate for qemu-user / pyghidra emulation of extracted code that does no network I/O." >&2
  exit 69
fi
