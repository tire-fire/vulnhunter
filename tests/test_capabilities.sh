#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"
. "$here/lib/assert.sh"
out="$(mktemp -d)/caps.json"
bash "$root/scripts/capabilities.sh" --out "$out"; rc=$?
assert_exit_code 0 "$rc" "capabilities.sh exits 0"
assert_file_exists "$out"
jq -e . "$out" >/dev/null 2>&1 && _grn "ok: caps json valid" || assert_fail "caps json invalid"
# jq is known-present on this host -> must report present:true with a real path.
assert_eq "true" "$(jq -r '.jq.present' "$out")" "jq detected present"
assert_contains "$(jq -r '.jq.path' "$out")" "jq" "jq path looks real"
# Every probed key must exist and have a boolean present field.
for k in pyghidra ghidra gdb radare2 qemu_user qemu_system frida binwalk bwrap unshare uv jq; do
  v="$(jq -r ".$k.present" "$out")"
  case "$v" in true|false) _grn "ok: key $k present-bool";; *) assert_fail "key $k missing/non-bool";; esac
done
finish
