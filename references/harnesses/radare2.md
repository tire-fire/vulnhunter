# Radare2 Harness

Scripted disassembly, cross-reference analysis, and ROP-gadget search.

## Availability check — degrade if absent

```bash
# capabilities.json is written by setup.sh (Task 21) into the workspace root
RADARE2_PRESENT=$(python3 -c "import json; d=json.load(open('capabilities.json')); print(d.get('radare2',{}).get('present','false'))")

if [ "$RADARE2_PRESENT" != "true" ]; then
  echo "radare2 not available — falling back to pyghidra playbook"
  # Use references/harnesses/pyghidra.md for disassembly and sink search
  exit 0
fi
```

## Auto-analysis and function listing

```bash
BIN=/path/to/target.elf

# Analyze and print all functions
r2 -A -q -c "afl" "$BIN"

# Full analysis with verbose output
r2 -A -q -c "aflv" "$BIN"

# Disassemble a specific function
r2 -A -q -c "pdf @ sym.main" "$BIN"
```

## Cross-reference search (xrefs to a sink)

```bash
# Find all callers of strcpy
r2 -A -q -c "axt sym.imp.strcpy" "$BIN"

# Find all callers of system
r2 -A -q -c "axt sym.imp.system" "$BIN"

# Cross-refs to all dangerous sinks in one pass
for SINK in strcpy memcpy system sprintf popen gets; do
  echo "=== xrefs to $SINK ==="
  r2 -A -q -c "axt sym.imp.$SINK" "$BIN" 2>/dev/null
done
```

## r2pipe scripted analysis

```python
#!/usr/bin/env python3
import r2pipe, json

SINKS = ["strcpy", "memcpy", "system", "sprintf", "popen", "gets"]

r2 = r2pipe.open("/path/to/target.elf", flags=["-2", "-A"])
r2.cmd("aaa")   # full analysis

results = {"functions": [], "xrefs": {}}
results["functions"] = r2.cmdj("aflj") or []

for sink in SINKS:
    xrefs = r2.cmdj(f"axtj sym.imp.{sink}") or []
    if xrefs:
        results["xrefs"][sink] = [{"from": x.get("from"), "fcn_name": x.get("fcn_name")} for x in xrefs]

r2.quit()
print(json.dumps(results, indent=2))
```

## ROP-gadget search

```bash
# Search for all ROP gadgets (ret-terminated instruction sequences)
r2 -A -q -c "/R" "$BIN" 2>/dev/null | head -100

# Search for specific gadget type (pop; ret)
r2 -A -q -c "/R pop" "$BIN" 2>/dev/null

# Via r2pipe
r2 = r2pipe.open("$BIN", flags=["-2", "-A"])
r2.cmd("aaa")
gadgets = r2.cmd("/R")
print(gadgets)
r2.quit()
```

## Strings with addresses

```bash
r2 -A -q -c "iz" "$BIN"   # strings in data section
r2 -A -q -c "izz" "$BIN"  # strings anywhere in the binary
```
