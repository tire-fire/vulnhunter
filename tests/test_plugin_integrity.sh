#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"
. "$here/lib/assert.sh"

# Every skill/agent markdown must have YAML frontmatter with name + description.
check_frontmatter(){
  local f="$1"
  local fm; fm="$(awk 'NR==1&&$0=="---"{f=1;next} f&&$0=="---"{exit} f{print}' "$f")"
  case "$fm" in *"name:"*) ;; *) assert_fail "$f missing name:"; return;; esac
  case "$fm" in *"description:"*) _grn "ok: frontmatter $f";; *) assert_fail "$f missing description:";; esac
}
# Resolve ${CLAUDE_PLUGIN_ROOT}/... and references/... links mentioned in a file.
check_links(){
  local f="$1"
  grep -oE 'references/[A-Za-z0-9_./-]+\.(md|json)' "$f" 2>/dev/null | sort -u | while read -r rel; do
    [ -e "$root/$rel" ] || echo "BROKENLINK:$f:$rel"
  done
}
broken=""
for f in $(find "$root/skills" "$root/agents" -name '*.md' 2>/dev/null); do
  check_frontmatter "$f"
  bl="$(check_links "$f")"; [ -n "$bl" ] && broken="$broken
$bl"
done
if [ -n "$(echo "$broken" | tr -d '[:space:]')" ]; then assert_fail "broken reference links:$broken"; else _grn "ok: no broken reference links"; fi
finish
