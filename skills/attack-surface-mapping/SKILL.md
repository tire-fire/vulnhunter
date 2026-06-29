---
name: attack-surface-mapping
description: Phase-1 enumeration that produces a schema-valid attack-surface.json. Covers firmware extraction with binwalk + pyghidra binary inventory, scope-checked network/web enumeration, and local binary format analysis. Used by the recon-mapper agent; not user-invocable.
user-invocable: false
---

# attack-surface-mapping

Phase 1 of the vulnhunter pipeline. Given a target, enumerate all components and entry points, then write and validate `attack-surface.json` against `references/schemas/attack-surface.schema.json`.

The output schema requires:
- `target` (string) — identifier for the asset
- `target_kind` — one of `firmware | network_host | local_binary | web_app`
- `components` — array of `{name, kind, path?, notes?}`
- `entry_points` — array of `{name, exposure}` where `exposure` is one of `network | local | physical | ipc`
- `trust_boundaries` (optional) — array of strings naming trust boundary lines

---

## Procedure by target_kind

### firmware

Follow `references/harnesses/binwalk.md` for extraction and surface enumeration, then `references/harnesses/pyghidra.md` for binary analysis.

**Step 1 — Extract firmware**

```bash
FIRMWARE=/path/to/firmware.bin
WORKDIR=/tmp/fw-extract

# Recursive extraction (handles nested archives common in firmware)
binwalk -Me --directory "$WORKDIR" "$FIRMWARE"
```

**Step 2 — Locate root filesystem**

```bash
ROOTFS=$(find "$WORKDIR" -name "squashfs-root" -type d | head -1)
[ -z "$ROOTFS" ] && ROOTFS=$(find "$WORKDIR" -name "etc" -type d | sort | head -1 | xargs dirname)
```

**Step 3 — Inventory init scripts and network daemons**

```bash
# Init scripts
find "$ROOTFS/etc/init.d" "$ROOTFS/etc/rc.d" -type f 2>/dev/null

# Named daemons in sbin
find "$ROOTFS/sbin" "$ROOTFS/usr/sbin" -type f 2>/dev/null | xargs -I{} basename {}

# Binaries that reference socket/bind/listen (network-listening heuristic)
find "$ROOTFS" -type f -executable 2>/dev/null | xargs file 2>/dev/null \
  | grep ELF | cut -d: -f1 \
  | xargs -I{} strings {} 2>/dev/null \
  | grep -E "(LISTEN|bind|accept|socket|0\.0\.0\.0|:[0-9]{2,5})" | sort -u
```

**Step 4 — Find embedded credentials and keys**

```bash
# Private key material
find "$ROOTFS" -type f | xargs grep -rl "BEGIN.*PRIVATE KEY" 2>/dev/null
find "$ROOTFS" -type f \( -name "*.pem" -o -name "*.key" -o -name "*.crt" \) 2>/dev/null

# Hardcoded credentials in config files
grep -rE "(password|passwd|secret|token|apikey)\s*[=:]\s*\S+" "$ROOTFS/etc" 2>/dev/null \
  | grep -v "^Binary"
```

**Step 5 — Binary inventory with pyghidra**

For each ELF binary of interest (network daemons, setuid binaries), run the headless import and dump from `references/harnesses/pyghidra.md`:

```bash
/opt/ghidra/support/analyzeHeadless ~/ghidra_projects vulnhunter \
  -import "$BIN" \
  -analysisTimeoutPerFile 300 \
  -readOnly
```

Then run the pyghidra dump script (imports/exports/strings/functions) and the dangerous-sink finder (strcpy, system, sprintf, gets, popen, etc.) per `references/harnesses/pyghidra.md`. Record any confirmed dangerous-sink callers as entry_point `sink` values in the output.

**Step 6 — Populate attack-surface.json**

Map findings to schema fields:

| Finding type | Schema field | kind value |
|---|---|---|
| Root filesystem | `components` | `filesystem` |
| Network daemon | `components` | `network_daemon` |
| Embedded key/cert | `components` | `credential` |
| Config file | `components` | `config` |
| Init script | `components` | `init_script` |
| Network-reachable port/CGI | `entry_points` | exposure: `network` |
| Serial console | `entry_points` | exposure: `physical` |
| D-Bus / Unix socket | `entry_points` | exposure: `ipc` |
| WAN/LAN demarcation | `trust_boundaries` | — |

```python
import json

attack_surface = {
    "target": "firmware.bin",
    "target_kind": "firmware",
    "components": [
        {
            "name": "squashfs-root",
            "kind": "filesystem",
            "path": "/tmp/fw-extract/_firmware.bin.extracted/squashfs-root",
            "notes": "Primary root filesystem extracted from image"
        },
        {
            "name": "httpd",
            "kind": "network_daemon",
            "path": "/tmp/fw-extract/_firmware.bin.extracted/squashfs-root/usr/sbin/httpd",
            "notes": "Listens on :80; processes CGI POST requests"
        }
    ],
    "entry_points": [
        {
            "name": "HTTP CGI /cgi-bin/admin",
            "exposure": "network",
            "sink": "system()"
        }
    ],
    "trust_boundaries": ["WAN interface", "LAN interface", "serial console"]
}

with open("attack-surface.json", "w") as f:
    json.dump(attack_surface, f, indent=2)
```

---

### network_host / web_app

**Scope check is mandatory before every active enumeration step.** Run:

```bash
scripts/scope-check.sh <engagement.yaml> <target>
```

Only proceed if exit code is 0 (IN_SCOPE). If exit code is 2, stop — target is out of scope or not listed. Any active probe that skips this check violates engagement rules.

**Step 1 — Port and protocol enumeration**

```bash
ENGAGEMENT_FILE="<path-to-engagement.yaml>"

# Scope check first
scripts/scope-check.sh "$ENGAGEMENT_FILE" "$TARGET" || exit 1

# TCP port scan
nmap -sV -p- --open -oX nmap-tcp.xml "$TARGET"

# UDP top ports
nmap -sU --top-ports 200 -oX nmap-udp.xml "$TARGET"
```

For each discovered port, record a component (`kind: service`) and entry point (`exposure: network`).

**Step 2 — Web endpoint enumeration (web_app only)**

```bash
scripts/scope-check.sh "$ENGAGEMENT_FILE" "$TARGET" || exit 1

# Directory/endpoint discovery
ffuf -u "http://$TARGET/FUZZ" -w /usr/share/wordlists/dirb/common.txt -o ffuf-out.json
```

For each HTTP endpoint found, note the auth surface (no auth, basic, cookie/session, bearer token, client cert) and add to `entry_points`.

**Step 3 — Authentication surface**

For each entry point:
- Note whether authentication is required and what mechanism is used (set as a `notes` field in the entry_point).
- Flag unauthenticated network-exposed interfaces as higher priority.

**Step 4 — Populate attack-surface.json**

```python
import json

attack_surface = {
    "target": "192.168.1.1",
    "target_kind": "network_host",
    "components": [
        {"name": "sshd", "kind": "service", "notes": "OpenSSH 8.2 on :22"},
        {"name": "nginx", "kind": "service", "notes": "nginx/1.18 on :443, TLS 1.2"}
    ],
    "entry_points": [
        {"name": "SSH :22", "exposure": "network"},
        {"name": "HTTPS :443 /admin", "exposure": "network", "sink": "/admin endpoint, no rate limit"}
    ],
    "trust_boundaries": ["external network", "management VLAN"]
}

with open("attack-surface.json", "w") as f:
    json.dump(attack_surface, f, indent=2)
```

For `target_kind: "web_app"`, use HTTP-specific components and endpoint entry_points:

```json
{
  "target": "api.example.com",
  "target_kind": "web_app",
  "components": [
    {"name": "nginx", "kind": "web-server", "notes": "Reverse proxy, TLS termination on :443"},
    {"name": "REST API /api/v1", "kind": "http-endpoint", "notes": "JWT-authenticated JSON API"}
  ],
  "entry_points": [
    {"name": "POST /api/v1/login", "exposure": "network", "sink": "auth handler"},
    {"name": "GET /api/v1/users/{id}", "exposure": "network"},
    {"name": "POST /api/v1/upload", "exposure": "network", "sink": "file write handler"}
  ],
  "trust_boundaries": ["external internet", "internal API backend"]
}
```

---

### local_binary

No active network probes; scope-check is not required for static analysis of a binary already in hand.

**Step 1 — File format and metadata**

```bash
BIN=/path/to/target
file "$BIN"
readelf -h "$BIN" 2>/dev/null || otool -h "$BIN" 2>/dev/null
checksec --file="$BIN" 2>/dev/null   # NX, PIE, RELRO, stack canary
```

**Step 2 — Import and string inventory**

```bash
# Dynamic imports
nm -D "$BIN" 2>/dev/null | grep " U "
objdump -p "$BIN" 2>/dev/null | grep NEEDED

# Strings (min length 6 to reduce noise)
strings -n 6 "$BIN" | grep -E "(password|secret|token|http|socket|exec|system|/etc/)" | sort -u
```

**Step 3 — PyGhidra binary inventory**

Run the dump and sink-finder scripts from `references/harnesses/pyghidra.md` to produce imports, exports, function list, and dangerous-sink call sites. Attach sink findings to entry_points.

**Step 4 — Populate attack-surface.json**

```python
import json

attack_surface = {
    "target": "/usr/bin/target",
    "target_kind": "local_binary",
    "components": [
        {"name": "target", "kind": "elf_binary", "path": "/usr/bin/target",
         "notes": "x86-64 ELF, no PIE, no stack canary; imports system(), gets()"}
    ],
    "entry_points": [
        {"name": "main() argv[1]", "exposure": "local", "sink": "gets()"},
        {"name": "UNIX socket /run/target.sock", "exposure": "ipc"}
    ],
    "trust_boundaries": ["process boundary", "setuid privilege boundary"]
}

with open("attack-surface.json", "w") as f:
    json.dump(attack_surface, f, indent=2)
```

---

## Validation

After writing `attack-surface.json`, validate it against `references/schemas/attack-surface.schema.json`:

```bash
scripts/validate-artifact.sh attack-surface attack-surface.json
```

The script exits 0 and prints `VALID` on success. Any `INVALID:` lines indicate schema violations that must be fixed before proceeding to Phase 2 (candidate generation).

Do not pass a partially populated file for validation — all three required fields (`target`, `components`, `entry_points`) must be present and non-empty arrays before calling the validator.
