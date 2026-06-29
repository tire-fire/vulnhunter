#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"
. "$here/lib/assert.sh"
jq -e . "$root/.claude-plugin/plugin.json" >/dev/null 2>&1 && _grn "ok: plugin.json valid" || assert_fail "plugin.json invalid"
jq -e . "$root/.claude-plugin/marketplace.json" >/dev/null 2>&1 && _grn "ok: marketplace.json valid" || assert_fail "marketplace.json invalid"
assert_eq "vulnhunter" "$(jq -r .name "$root/.claude-plugin/plugin.json")" "plugin name"
for a in recon-mapper static-re-chain dynamic-chain web-proto-chain finding-validator exploit-dev report-writer; do
  assert_file_exists "$root/agents/$a.md"; done
for s in attack-orchestrator attack-surface-mapping finding-validation vuln-taxonomy; do
  assert_file_exists "$root/skills/$s/SKILL.md"; done
finish
