# PyGhidra Harness

Headless static reverse-engineering via PyGhidra and Ghidra's `analyzeHeadless`.

## Paths

- PyGhidra CLI: `pyghidra` (on PATH)
- analyzeHeadless: `$GHIDRA_INSTALL_DIR/support/analyzeHeadless` (export GHIDRA_INSTALL_DIR; see note below)
- Project store: a fresh per-run directory (e.g. `$WS/ghidra-proj`)

> **`GHIDRA_INSTALL_DIR` is required** by the `pyghidra` CLI and module — both
> abort with "GHIDRA_INSTALL_DIR is not set" otherwise. Locate it once
> (`find / -name ghidraRun -maxdepth 6 2>/dev/null`) and `export` it. CLI form
> `pyghidra --skip-analysis <binary> <script.py>` runs the script with
> `currentProgram`/`monitor` pre-bound (no `pyghidra.start()` call needed).

> To **emulate a single exported function** — run real firmware bytes on chosen
> inputs, hooking external PLT calls — see `firmware-fn-emulation.md`.

## Headless import and analysis

```bash
# GHIDRA_INSTALL_DIR must be exported before running; see note above.
mkdir -p "$WS/ghidra-proj"
BIN=/path/to/target.elf

# Import binary and run Ghidra auto-analysis (creates project on first run)
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$WS/ghidra-proj" vulnhunter \
  -import "$BIN" \
  -analysisTimeoutPerFile 300 \
  -readOnly
```

## Dump imports, exports, strings, and functions via pyghidra

```python
#!/usr/bin/env python3
# Run with: pyghidra dump_info.py /path/to/target.elf
import pyghidra
import json, sys

def run(flat_api, program):
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

pyghidra.start()
with pyghidra.open_program(sys.argv[1]) as flat_api:
    program = flat_api.getCurrentProgram()
    run(flat_api, program)
```

## Dangerous-sink call finder

```python
#!/usr/bin/env python3
# Run with: pyghidra find_sinks.py /path/to/target.elf
import pyghidra, json, sys

SINKS = {"strcpy", "strncpy", "memcpy", "memmove", "system", "sprintf", "snprintf", "popen", "gets"}

def run(flat_api, program):
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

pyghidra.start()
with pyghidra.open_program(sys.argv[1]) as flat_api:
    program = flat_api.getCurrentProgram()
    run(flat_api, program)
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
