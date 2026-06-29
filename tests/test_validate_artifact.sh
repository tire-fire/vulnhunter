#!/usr/bin/env bash
set -u
here="$(cd "$(dirname "$0")" && pwd)"; root="$(cd "$here/.." && pwd)"
. "$here/lib/assert.sh"
wd="$(mktemp -d)"
v(){ bash "$root/scripts/validate-artifact.sh" "$1" "$2" >/dev/null 2>&1; echo $?; }

cat > "$wd/good_finding.json" <<'JSON'
{"id":"F-1","title":"Stack overflow in parser","status":"exploitable","severity":"high",
 "cwe":["CWE-121"],"attack_techniques":["T1203"],
 "cvss":{"version":"3.1","vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","score":9.8},
 "asset":"/bin/parser","summary":"x","evidence":["crash with PoC input"]}
JSON
cat > "$wd/bad_finding.json" <<'JSON'
{"id":"F-2","status":"EXPLOITABLE","severity":"high","cwe":["121"],"asset":"x"}
JSON

cat > "$wd/ruled_out_finding.json" <<'JSON'
{"id":"F-3","title":"Not reachable","status":"ruled_out","asset":"/bin/x","summary":"path not reachable from any entry point"}
JSON
cat > "$wd/confirmed_no_evidence.json" <<'JSON'
{"id":"F-4","title":"x","status":"confirmed","severity":"high","cwe":["CWE-787"],"attack_techniques":["T1190"],"cvss":{"version":"3.1","vector":"x","score":8.1},"asset":"a","summary":"s"}
JSON

assert_eq 0 "$(v finding "$wd/good_finding.json")" "valid finding accepted"
assert_eq 2 "$(v finding "$wd/bad_finding.json")"  "invalid finding rejected"
assert_eq 3 "$(v finding "$wd/missing.json")"      "missing file -> rc3"
assert_eq 3 "$(v bogustype "$wd/good_finding.json")" "unknown type -> rc3"
assert_eq 0 "$(v finding "$wd/ruled_out_finding.json")" "minimal ruled_out finding accepted"
assert_eq 2 "$(v finding "$wd/confirmed_no_evidence.json")" "confirmed without evidence rejected"
finish
