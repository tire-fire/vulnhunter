# QEMU Harness

Emulating firmware binaries and full system images under QEMU.

**REQUIRED:** Every QEMU invocation must be wrapped by `scripts/sandbox.sh`:
```bash
scripts/sandbox.sh <workspace_dir> -- <qemu_command>
```
This enforces CPU/RAM/filesystem limits and network isolation via bwrap or unshare.
On hosts with neither (no bwrap, restricted user namespaces) `sandbox.sh` refuses
unless you opt into degraded mode with `SANDBOX_DEGRADED_OK=1` (resource/wall
limits only — acceptable for emulating extracted code that does no network I/O).

> To run **one exported function** rather than a whole binary (crypto/parser
> proof-of-behavior), see `firmware-fn-emulation.md`.

**Network mode for emulated services:** An emulated service that exposes a port via hostfwd (e.g., `hostfwd=tcp:127.0.0.1:8080-:80`) and any client or fuzzer that connects to it **must both** run under `SANDBOX_ALLOW_NET=1` so they share the host loopback. Without it each `sandbox.sh` call runs in a separate network namespace and `127.0.0.1:PORT` is unreachable from the other side. Use `SANDBOX_ALLOW_NET=0` (the default) only for pure file-input execution where no network I/O is needed.

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
