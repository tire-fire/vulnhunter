# Frida Harness

Dynamic instrumentation: spawn/attach, function hooking, and sink tracing.

## Availability check — degrade if absent

```bash
# capabilities.json is written by setup.sh (Task 21) into the workspace root
FRIDA_PRESENT=$(python3 -c "import json; d=json.load(open('capabilities.json')); print(d.get('frida',{}).get('present','false'))")

if [ "$FRIDA_PRESENT" != "true" ]; then
  echo "frida not available — falling back to gdb tracing (see references/harnesses/gdb.md)"
  # Use gdb --batch with watchpoints or hardware breakpoints to trace sink inputs
  exit 0
fi
```

## Spawn a process and hook a function

```bash
frida -l hook_strcpy.js /path/to/target -- arg1 arg2
```

```javascript
// hook_strcpy.js — intercept strcpy and log src argument
Interceptor.attach(Module.getExportByName(null, "strcpy"), {
    onEnter: function(args) {
        var dest = args[0];
        var src  = args[1];
        console.log("[strcpy] src='" + src.readCString() + "' dest=" + dest);
        console.log("[strcpy] backtrace:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join("\n"));
    }
});
```

## Attach to a running process

```bash
frida -p "$(pgrep -n target)" -l hook_strcpy.js
```

## Trace inputs flowing into dangerous sinks

```javascript
// trace_sinks.js — log all calls to multiple sinks with argument values
var SINKS = ["strcpy", "strncpy", "memcpy", "system", "sprintf", "popen"];

SINKS.forEach(function(name) {
    var sym = Module.findExportByName(null, name);
    if (!sym) { console.log("[-] " + name + " not found"); return; }

    Interceptor.attach(sym, {
        onEnter: function(args) {
            var entry = { sink: name, ts: Date.now() };
            try { entry.arg0 = args[0].readCString(256); } catch(e) {}
            try { entry.arg1 = args[1].readCString(256); } catch(e) {}
            console.log(JSON.stringify(entry));
        }
    });
});
```

```bash
frida -f /path/to/target --no-pause -l trace_sinks.js -- --arg1 2>&1 | tee /tmp/frida_trace.txt
```

## Frida script for QEMU-user processes

When the target runs under qemu-user (see `references/harnesses/qemu.md`):

```bash
# qemu-arm exposes itself as a local process; attach by PID
PID=$(pgrep -n qemu-arm)
frida -p "$PID" -l trace_sinks.js
```

## Parse trace output for candidate evidence

```python
import json

evidence = []
for line in open("/tmp/frida_trace.txt"):
    line = line.strip()
    if not line.startswith("{"):
        continue
    rec = json.loads(line)
    evidence.append(f"sink={rec['sink']} arg0={rec.get('arg0','')} arg1={rec.get('arg1','')}")

print(json.dumps(evidence, indent=2))
```

## GDB fallback: tracing sinks without Frida

```bash
# Set a breakpoint on strcpy and print args when hit (batch mode, first 5 hits)
BIN=/path/to/target
gdb --batch \
  -ex "set pagination off" \
  -ex "set confirm off" \
  -ex "break strcpy" \
  -ex "commands 1\nprintf \"strcpy src=%s\\n\", (char*)\$rsi\ncontinue\nend" \
  -ex "run < /path/to/input" \
  "$BIN" 2>&1 | head -80
```
