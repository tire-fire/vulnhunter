# GDB Harness

Batch-mode crash triage and PoC-evidence capture for the `finding.evidence` field.

## Batch-mode single-shot crash triage

```bash
BIN=/path/to/target
INPUT=/path/to/crash_input.bin

gdb --batch \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "run < $INPUT" \
  -ex "bt" \
  -ex "info registers" \
  -ex "x/8xw \$sp" \
  -ex "info proc mappings" \
  "$BIN" 2>&1 | tee /tmp/crash_triage.txt
```

## Capture fault address and $pc for evidence

```bash
gdb --batch \
  -ex "set pagination off" \
  -ex "handle SIGSEGV stop print" \
  -ex "handle SIGABRT stop print" \
  -ex "run < $INPUT" \
  -ex "printf \"PC=%s\n\", (void*)\$pc" \
  -ex "printf \"FAULT_ADDR=%s\n\", (void*)\$cr2" \
  -ex "bt full" \
  -ex "info registers" \
  "$BIN" 2>&1 | tee /tmp/crash_evidence.txt
```

## Attach to a running or QEMU-emulated process

```bash
# Attach by PID (local process)
gdb --batch -p "$(pgrep -n target)" \
  -ex "set pagination off" \
  -ex "bt" \
  -ex "detach"

# Attach to QEMU-user gdb stub (see qemu.md, -g 1234)
gdb-multiarch "$BIN" \
  -ex "set pagination off" \
  -ex "set sysroot /path/to/rootfs" \
  -ex "target remote :1234" \
  -ex "continue" \
  -ex "bt" \
  -ex "info registers" \
  -ex "quit"
```

## Produce PoC-evidence text for finding.evidence

After collecting `/tmp/crash_evidence.txt`, extract the relevant lines and format as
`finding.evidence` array items (see `references/schemas/finding.schema.json`):

```python
import re, json

raw = open("/tmp/crash_evidence.txt").read()

# Pull signal, PC, backtrace header
signal = re.search(r"(Program received signal \S+.*)", raw)
pc     = re.search(r"PC=(\S+)", raw)
bt     = re.search(r"(#0\s+.*?)(?=\n#[1-9]|\Z)", raw, re.DOTALL)

evidence = []
if signal: evidence.append(signal.group(1).strip())
if pc:     evidence.append(f"$pc = {pc.group(1)}")
if bt:     evidence.append("Backtrace: " + bt.group(1).strip())

# Write into a partial finding record for review
finding_stub = {
    "id": "find-XXXX",
    "title": "Crash in target at <function>",
    "status": "confirmed",
    "severity": "high",
    "cwe": ["CWE-120"],
    "attack_techniques": [],
    "cvss": {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8},
    "asset": "/path/to/target",
    "summary": "Stack overflow triggered by crafted input",
    "evidence": evidence
}
print(json.dumps(finding_stub, indent=2))
```

## Script to reproduce with a specific offset (PoC harness)

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*256 + b'BBBB')" | \
  gdb --batch \
    -ex "set pagination off" \
    -ex "run" \
    -ex "bt" \
    "$BIN" 2>&1
```
