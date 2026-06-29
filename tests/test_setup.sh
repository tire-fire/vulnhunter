#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"
. "$here/lib/assert.sh"
out="$(bash "$root/scripts/setup.sh" --check 2>&1)"; rc=$?
assert_exit_code 0 "$rc" "setup --check exits 0"
assert_contains "$out" "radare2" "check mentions radare2"
assert_contains "$out" "qemu" "check mentions qemu"
assert_contains "$out" "frida" "check mentions frida"
finish
