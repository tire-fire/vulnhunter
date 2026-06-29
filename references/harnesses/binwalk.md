# Binwalk Harness

Firmware extraction, surface enumeration, and attack-surface.json population.

## Extract firmware

```bash
FIRMWARE=/path/to/firmware.bin
WORKDIR=/tmp/fw-extract

binwalk -e --extract --directory "$WORKDIR" "$FIRMWARE"
# Recurse into nested archives (common in firmware)
binwalk -Me --extract --directory "$WORKDIR" "$FIRMWARE"
```

## Locate root filesystem

```bash
# After extraction, find the squashfs/jffs2/ext2 mount point
find "$WORKDIR" -maxdepth 4 \( -name "bin" -o -name "sbin" -o -name "etc" \) -type d | head -20
# Usually under $WORKDIR/_firmware.bin.extracted/squashfs-root/ or similar
ROOTFS=$(find "$WORKDIR" -name "squashfs-root" -type d | head -1)
[ -z "$ROOTFS" ] && ROOTFS=$(find "$WORKDIR" -name "etc" -type d | sort | head -1 | xargs dirname)
```

## Enumerate init scripts and network daemons

```bash
# Init scripts
find "$ROOTFS/etc" -name "rc*" -o -name "init.d" -type d 2>/dev/null | xargs ls -1 2>/dev/null
find "$ROOTFS/etc/init.d" "$ROOTFS/etc/rc.d" -type f 2>/dev/null

# Processes listening on network (strings heuristic when no /proc available)
find "$ROOTFS" -type f -executable 2>/dev/null | xargs file 2>/dev/null | grep ELF | cut -d: -f1 | \
  xargs -I{} strings {} 2>/dev/null | grep -E "(LISTEN|bind|accept|socket|0\.0\.0\.0|:[0-9]{2,5})" | sort -u

# Named daemons
find "$ROOTFS/sbin" "$ROOTFS/usr/sbin" -type f 2>/dev/null | xargs -I{} basename {}
```

## Find embedded keys, certs, and hardcoded credentials

```bash
# Private keys
find "$ROOTFS" -type f | xargs grep -rl "BEGIN.*PRIVATE KEY" 2>/dev/null
find "$ROOTFS" -type f -name "*.pem" -o -name "*.key" -o -name "*.crt" 2>/dev/null

# Hardcoded passwords in config files
grep -rE "(password|passwd|secret|token|apikey)\s*[=:]\s*\S+" "$ROOTFS/etc" 2>/dev/null | grep -v "^Binary"

# Default credentials in executables (strings approach)
find "$ROOTFS" -type f -executable 2>/dev/null | xargs -I{} strings {} 2>/dev/null | \
  grep -iE "(admin|root|password|default|1234)" | sort -u | head -50
```

## Record components into attack-surface.json

Map findings to `references/schemas/attack-surface.schema.json`:

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
            "notes": "Primary root filesystem; contains /etc/passwd and init scripts"
        },
        {
            "name": "httpd",
            "kind": "network_daemon",
            "path": "/tmp/fw-extract/_firmware.bin.extracted/squashfs-root/usr/sbin/httpd",
            "notes": "Listens on :80; processes CGI POST requests"
        },
        {
            "name": "device.key",
            "kind": "credential",
            "path": "/tmp/fw-extract/_firmware.bin.extracted/squashfs-root/etc/ssl/device.key",
            "notes": "RSA private key embedded in firmware image"
        }
    ],
    "entry_points": [
        {
            "name": "HTTP CGI /cgi-bin/admin",
            "exposure": "network",
            "sink": "system()"
        },
        {
            "name": "Telnet :23",
            "exposure": "network",
            "sink": "login shell"
        }
    ],
    "trust_boundaries": ["WAN interface", "LAN interface", "serial console"]
}

with open("attack-surface.json", "w") as f:
    json.dump(attack_surface, f, indent=2)
```
