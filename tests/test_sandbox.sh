#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"
. "$here/lib/assert.sh"
ws="$(mktemp -d)"
sb(){ bash "$root/scripts/sandbox.sh" "$ws" -- "$@"; }

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

# 4-5. Wall-clock timeout kills a hung process quickly.
ws2="$(mktemp -d)"
start=$(date +%s)
SANDBOX_WALL_TIMEOUT=2 bash "$root/scripts/sandbox.sh" "$ws2" -- /usr/bin/env sleep 30
rc=$?
end=$(date +%s)
assert_exit_code 1 "$([ "$rc" -ne 0 ] && echo 1 || echo 0)" "wall timeout kills hung process (rc=$rc)"
assert_exit_code 1 "$([ $((end-start)) -lt 10 ] && echo 1 || echo 0)" "hung process killed early (elapsed=$((end-start))s)"

finish
