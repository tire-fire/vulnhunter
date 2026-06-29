#!/usr/bin/env bash
set -u
OUT="capabilities.json"
[ "${1:-}" = "--out" ] && OUT="${2:?}"
# qemu probed across common arch suffixes; analyzeHeadless implies ghidra headless.
declare -A PROBE=(
  [pyghidra]=pyghidra [ghidra]=ghidra [gdb]=gdb [radare2]=radare2
  [frida]=frida [binwalk]=binwalk [bwrap]=bwrap [unshare]=unshare [uv]=uv [jq]=jq
)
emit_one(){ local key="$1" bin="$2" p; p="$(command -v "$bin" 2>/dev/null || true)"; if [ -n "$p" ]; then printf '"%s":{"present":true,"path":"%s"}' "$key" "$p"; else printf '"%s":{"present":false,"path":""}' "$key"; fi; }
probe_qemu(){ local key="$1" pat="$2" p=""; for c in $pat; do p="$(command -v "$c" 2>/dev/null || true)"; [ -n "$p" ] && break; done; if [ -n "$p" ]; then printf '"%s":{"present":true,"path":"%s"}' "$key" "$p"; else printf '"%s":{"present":false,"path":""}' "$key"; fi; }
{
  printf '{'
  first=1
  for k in "${!PROBE[@]}"; do [ $first -eq 1 ] || printf ','; first=0; emit_one "$k" "${PROBE[$k]}"; done
  printf ','; probe_qemu qemu_user "qemu-arm-static qemu-arm qemu-mipsel qemu-mips qemu-aarch64"
  printf ','; probe_qemu qemu_system "qemu-system-arm qemu-system-aarch64 qemu-system-mips qemu-system-mipsel"
  printf '}'
} | jq -S . > "$OUT"
echo "wrote $OUT"
