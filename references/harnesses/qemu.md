# QEMU Harness

Emulating firmware binaries and full system images under QEMU.

**REQUIRED:** Every QEMU invocation must be wrapped by `scripts/sandbox.sh`:
```bash
scripts/sandbox.sh <workspace_dir> -- <qemu_command>
```
This enforces CPU/RAM/filesystem limits and network isolation via bwrap or unshare.

## qemu-user: Run a single ELF against a firmware rootfs

```bash
ROOTFS=/tmp/fw-extract/_firmware.bin.extracted/squashfs-root
BIN="$ROOTFS/usr/sbin/httpd"
WS=/tmp/qemu-ws

# ARM little-endian example; replace qemu-arm with qemu-mips, qemu-aarch64, etc.
scripts/sandbox.sh "$WS" -- \
  qemu-arm -L "$ROOTFS" "$BIN" -p 8080
```

`QEMU_LD_PREFIX` is equivalent to `-L` for qemu-user:
```bash
scripts/sandbox.sh "$WS" -- \
  env QEMU_LD_PREFIX="$ROOTFS" qemu-arm "$BIN" -p 8080
```

## qemu-user with gdb stub for live debugging

```bash
WS=/tmp/qemu-ws-dbg

# Start target under qemu-user, pause and expose gdb stub on port 1234
scripts/sandbox.sh "$WS" -- \
  env QEMU_LD_PREFIX="$ROOTFS" qemu-arm -g 1234 "$BIN" &

# Attach from a second terminal (or via gdb.md playbook)
gdb-multiarch "$BIN" \
  -ex "set sysroot $ROOTFS" \
  -ex "target remote :1234"
```

## qemu-system: Boot a full firmware image

```bash
IMAGE=/path/to/firmware.img
WS=/tmp/qemu-sys-ws

scripts/sandbox.sh "$WS" -- \
  qemu-system-arm \
    -M versatilepb \
    -kernel "$IMAGE" \
    -nographic \
    -serial mon:stdio \
    -net nic -net user,hostfwd=tcp:127.0.0.1:8080-:80
```

## qemu-system with gdbserver port

```bash
scripts/sandbox.sh "$WS" -- \
  qemu-system-arm \
    -M versatilepb \
    -kernel "$IMAGE" \
    -nographic \
    -serial mon:stdio \
    -net nic -net user,hostfwd=tcp:127.0.0.1:8080-:80 \
    -S -gdb tcp::5555 &

# Attach gdb once QEMU is listening
gdb-multiarch \
  -ex "target remote :5555" \
  -ex "continue"
```

## Determining the correct qemu-user binary

```bash
file "$BIN"
# e.g. "ELF 32-bit LSB, ARM" → qemu-arm
# e.g. "ELF 32-bit MSB, MIPS"  → qemu-mips
# e.g. "ELF 64-bit LSB, AArch64" → qemu-aarch64
```

## Sandbox wall-clock timeout override

```bash
# Default is 180 s; extend for slower boot sequences
SANDBOX_WALL_TIMEOUT=600 scripts/sandbox.sh "$WS" -- qemu-arm -L "$ROOTFS" "$BIN"
```
