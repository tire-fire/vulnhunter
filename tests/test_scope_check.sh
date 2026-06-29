#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"
. "$here/lib/assert.sh"
wd="$(mktemp -d)"; eng="$wd/eng.yaml"
cat > "$eng" <<'YAML'
program: t
in_scope:
  - "example.com"
  - "*.api.example.com"
  - "10.0.0.0/24"
out_of_scope:
  - "secret.api.example.com"
rate_limit_rps: 5
rules: ["no-dos"]
YAML
run(){ bash "$root/scripts/scope-check.sh" "$1" "$2"; echo $?; }
assert_eq 0 "$(run "$eng" example.com)"            "exact host in scope"
assert_eq 0 "$(run "$eng" foo.api.example.com)"    "domain glob in scope"
assert_eq 0 "$(run "$eng" 10.0.0.5)"               "ip in CIDR in scope"
assert_eq 2 "$(run "$eng" secret.api.example.com)" "explicit out-of-scope blocked"
assert_eq 2 "$(run "$eng" other.com)"              "unlisted target blocked"
assert_eq 2 "$(run "$eng" 192.168.1.1)"            "ip outside CIDR blocked"
assert_eq 3 "$(run "$wd/missing.yaml" example.com)" "missing engagement file"
finish
