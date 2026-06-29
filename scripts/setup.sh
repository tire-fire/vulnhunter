#!/usr/bin/env bash
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
check(){
  echo "== vulnhunter tool check =="
  for t in pyghidra ghidra gdb binwalk jq bwrap uv; do command -v "$t" >/dev/null 2>&1 && echo "present: $t" || echo "MISSING(core): $t"; done
  for t in radare2 frida; do command -v "$t" >/dev/null 2>&1 && echo "present: $t" || echo "MISSING(optional): $t"; done
  if command -v qemu-arm-static >/dev/null 2>&1 || command -v qemu-arm >/dev/null 2>&1; then echo "present: qemu-user"; else echo "MISSING(optional): qemu-user"; fi
  if command -v qemu-system-arm >/dev/null 2>&1; then echo "present: qemu-system"; else echo "MISSING(optional): qemu-system"; fi
}
if [ "${1:-}" = "--check" ]; then check; exit 0; fi
echo "Installing optional analysis tools (radare2, qemu, frida-tools)..."
if command -v pacman >/dev/null 2>&1; then
  sudo pacman -S --needed --noconfirm radare2 qemu-user-static qemu-system-arm || echo "pacman step had errors; continuing"
else
  echo "no pacman; install radare2/qemu manually" >&2
fi
if command -v uv >/dev/null 2>&1; then uv tool install frida-tools || echo "frida-tools install failed; continuing"; else echo "no uv; install frida-tools manually" >&2; fi
echo; check
bash "$HERE/capabilities.sh" --out "$HERE/../capabilities.json" >/dev/null 2>&1 || true
echo "done"
