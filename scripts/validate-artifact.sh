#!/usr/bin/env bash
set -u
TYPE="${1:?type}"; FILE="${2:?file}"
HERE="$(cd "$(dirname "$0")" && pwd)"; ROOT="$(cd "$HERE/.." && pwd)"
SCHEMA="$ROOT/references/schemas/$TYPE.schema.json"
[ -r "$SCHEMA" ] || { echo "unknown type: $TYPE" >&2; exit 3; }
[ -r "$FILE" ] || { echo "missing file: $FILE" >&2; exit 3; }
uv run --quiet --with jsonschema python - "$SCHEMA" "$FILE" <<'PY'
import json,sys
from jsonschema import Draft202012Validator
schema=json.load(open(sys.argv[1])); data=json.load(open(sys.argv[2]))
errs=sorted(Draft202012Validator(schema).iter_errors(data), key=lambda e:e.path)
if errs:
    for e in errs: print("INVALID:", "/".join(map(str,e.path)) or "<root>", e.message)
    sys.exit(2)
print("VALID")
PY
