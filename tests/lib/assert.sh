#!/usr/bin/env bash
# Minimal assertion helpers. Each test file sources this and calls assertions.
ASSERT_FAILS=0
_red(){ printf '\033[31m%s\033[0m\n' "$1"; }
_grn(){ printf '\033[32m%s\033[0m\n' "$1"; }
assert_eq(){ # expected actual msg
  if [ "$1" = "$2" ]; then _grn "ok: $3"; else _red "FAIL: $3 (expected='$1' actual='$2')"; ASSERT_FAILS=$((ASSERT_FAILS+1)); fi
}
assert_contains(){ # haystack needle msg
  case "$1" in *"$2"*) _grn "ok: $3";; *) _red "FAIL: $3 (missing '$2')"; ASSERT_FAILS=$((ASSERT_FAILS+1));; esac
}
assert_exit_code(){ # expected_code actual_code msg
  if [ "$1" = "$2" ]; then _grn "ok: $3"; else _red "FAIL: $3 (expected rc=$1 actual rc=$2)"; ASSERT_FAILS=$((ASSERT_FAILS+1)); fi
}
assert_file_exists(){ if [ -e "$1" ]; then _grn "ok: file $1"; else _red "FAIL: missing file $1"; ASSERT_FAILS=$((ASSERT_FAILS+1)); fi; }
assert_fail(){ _red "FAIL: $1"; ASSERT_FAILS=$((ASSERT_FAILS+1)); }
finish(){ if [ "$ASSERT_FAILS" -eq 0 ]; then _grn "ALL PASS"; exit 0; else _red "$ASSERT_FAILS FAILED"; exit 1; fi; }
