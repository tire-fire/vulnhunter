#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"
fails=0
for t in "$here"/test_*.sh; do
  [ -e "$t" ] || continue
  echo "== $(basename "$t") =="
  bash "$t" || fails=$((fails+1))
done
echo "===================="
if [ "$fails" -eq 0 ]; then echo "SUITE PASS"; else echo "SUITE FAIL ($fails files)"; fi
exit "$fails"
