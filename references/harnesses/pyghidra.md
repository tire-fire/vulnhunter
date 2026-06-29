# PyGhidra Harness

Headless static reverse-engineering via PyGhidra and Ghidra's `analyzeHeadless`.

## Paths

- PyGhidra wrapper: `~/.local/bin/pyghidra`
- analyzeHeadless: `/opt/ghidra/support/analyzeHeadless`
- Project store: `~/ghidra_projects`

## Headless import and analysis

```bash
PROJ=~/ghidra_projects
BIN=/path/to/target.elf

# Import binary and run Ghidra auto-analysis (creates project on first run)
/opt/ghidra/support/analyzeHeadless "$PROJ" vulnhunter \
  -import "$BIN" \
  -analysisTimeoutPerFile 300 \
  -readOnly
```

## Dump imports, exports, strings, and functions via pyghidra

```python
#!/usr/bin/env python3
# Run with: ~/.local/bin/pyghidra /path/to/target.elf dump_info.py
import pyghidra
import json, sys

def run(flat_api):
    program = flat_api.getCurrentProgram()
    em = program.getExternalManager()
    sym_table = program.getSymbolTable()
    listing = program.getListing()

    results = {"imports": [], "exports": [], "strings": [], "functions": [], "dangerous_calls": []}

    # Imports
    for ref in em.getExternalLibraryNames():
        results["imports"].append(str(ref))

    # Exports (external entry points)
    for sym in sym_table.getExternalEntryPointIterator():
        results["exports"].append(str(sym))

    # Strings
    str_iter = listing.getDefinedData(True)
    for d in str_iter:
        if d.getDataType().getName() in ("string", "unicode"):
            results["strings"].append(str(d.getValue()))

    # Functions with addresses
    for fn in listing.getFunctions(True):
        results["functions"].append({
            "name": fn.getName(),
            "address": str(fn.getEntryPoint())
        })

    print(json.dumps(results, indent=2))

pyghidra.run_script(sys.argv[1], run)
```

## Dangerous-sink call finder

```python
#!/usr/bin/env python3
# Run with: ~/.local/bin/pyghidra /path/to/target.elf find_sinks.py
import pyghidra, json, sys

SINKS = {"strcpy", "strncpy", "memcpy", "memmove", "system", "sprintf", "snprintf", "popen", "gets"}

def run(flat_api):
    program = flat_api.getCurrentProgram()
    sym_table = program.getSymbolTable()
    refs = program.getReferenceManager()
    findings = []

    for sink in SINKS:
        for sym in sym_table.getSymbols(sink):
            addr = sym.getAddress()
            for ref in refs.getReferencesTo(addr):
                caller = str(ref.getFromAddress())
                findings.append({"sink": sink, "sink_addr": str(addr), "caller_addr": caller})

    print(json.dumps(findings, indent=2))

pyghidra.run_script(sys.argv[1], run)
```

## Emit candidate JSON

Map sink-call output to `references/schemas/candidate.schema.json`:

```python
import json, uuid

sinks = json.load(open("sinks.json"))
candidates = []
for s in sinks:
    candidates.append({
        "id": f"cand-{uuid.uuid4().hex[:8]}",
        "source_chain": "static-re",
        "asset": "/path/to/target.elf",
        "hypothesis": f"Unsafe call to {s['sink']} at {s['caller_addr']} may allow memory corruption",
        "cwe_guess": ["CWE-120"],
        "evidence": [f"caller={s['caller_addr']} -> sink={s['sink']} at {s['sink_addr']}"],
        "priority_score": 6.0
    })

with open("candidate-pyghidra.json", "w") as f:
    json.dump(candidates[0], f, indent=2)  # write one file per candidate
```
