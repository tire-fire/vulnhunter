#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"
. "$here/lib/assert.sh"
ws="$(mktemp -d)"
sb(){ bash "$root/scripts/sandbox.sh" "$ws" -- "$@"; }

# Detect whether an isolation backend (bwrap / working unshare) exists on this
# host. With none, sandbox.sh exits 69 unless SANDBOX_DEGRADED_OK=1. We test the
# isolation contract where a backend exists, and the degraded contract where not.
bash "$root/scripts/sandbox.sh" "$ws" -- true >/dev/null 2>&1
HAVE_BACKEND=$([ "$?" -eq 69 ] && echo 0 || echo 1)

if [ "$HAVE_BACKEND" = "1" ]; then
  # 1. Write inside workspace succeeds.
  sb /usr/bin/env bash -c 'echo hi > "$PWD/inside.txt"'; assert_exit_code 0 "$?" "write inside workspace ok"
  assert_file_exists "$ws/inside.txt"

  # 2. Write outside workspace fails (root is read-only).
  sb /usr/bin/env bash -c 'echo x > /vh_outside_probe 2>/dev/null'; assert_exit_code 1 "$([ -e /vh_outside_probe ] && echo 0 || echo 1)" "write outside workspace blocked"
  rm -f /vh_outside_probe 2>/dev/null || true

  # 3. Network is blocked: a TCP connect attempt must fail.
  sb /usr/bin/env python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(3)
try:
    s.connect(("1.1.1.1",53)); print("CONNECTED"); sys.exit(0)
except Exception: print("BLOCKED"); sys.exit(7)'
  assert_exit_code 7 "$?" "network connect blocked in sandbox"

  # 4. SANDBOX_ALLOW_NET=1 permits a loopback connection.
  ws3="$(mktemp -d)"
  _lport_file="$(mktemp)"
  # Background listener: writes port to a file then accepts one connection.
  python3 -c "
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('127.0.0.1', 0))
s.listen(1)
port = s.getsockname()[1]
open('$_lport_file', 'w').write(str(port))
s.settimeout(10)
try: c, _ = s.accept(); c.close()
except: pass
" &
  _listener_pid=$!
  sleep 0.5
  PORT="$(cat "$_lport_file")"
  export PORT
  SANDBOX_ALLOW_NET=1 bash "$root/scripts/sandbox.sh" "$ws3" -- python3 -c '
import os, socket, sys
s = socket.socket(); s.settimeout(5)
try:
    s.connect(("127.0.0.1", int(os.environ["PORT"]))); print("OK"); sys.exit(0)
except Exception as e:
    print("FAIL", e); sys.exit(7)'
  assert_exit_code 0 "$?" "SANDBOX_ALLOW_NET=1 permits loopback connect"
  kill "$_listener_pid" 2>/dev/null || true
  rm -f "$_lport_file"

  WALL_PREFIX=""
else
  echo "(no isolation backend on this host — testing the degraded-mode contract)"
  # D1. Without opt-in, sandbox refuses rather than running unconfined.
  sb true >/dev/null 2>&1; assert_exit_code 69 "$?" "refuses (rc69) when no backend and no opt-in"

  # D2. With SANDBOX_DEGRADED_OK=1 it runs and can write inside the workspace.
  SANDBOX_DEGRADED_OK=1 bash "$root/scripts/sandbox.sh" "$ws" -- /usr/bin/env bash -c 'echo hi > "$PWD/inside.txt"' 2>/dev/null
  assert_exit_code 0 "$?" "degraded mode runs with opt-in"
  assert_file_exists "$ws/inside.txt"

  WALL_PREFIX="SANDBOX_DEGRADED_OK=1"
fi

# 5-6. Wall-clock timeout kills a hung process quickly (both modes).
ws2="$(mktemp -d)"
start=$(date +%s)
env $WALL_PREFIX SANDBOX_WALL_TIMEOUT=2 bash "$root/scripts/sandbox.sh" "$ws2" -- /usr/bin/env sleep 30
rc=$?
end=$(date +%s)
assert_exit_code 1 "$([ "$rc" -ne 0 ] && echo 1 || echo 0)" "wall timeout kills hung process (rc=$rc)"
assert_exit_code 1 "$([ $((end-start)) -lt 10 ] && echo 1 || echo 0)" "hung process killed early (elapsed=$((end-start))s)"

finish
