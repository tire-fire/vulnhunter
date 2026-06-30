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
elif command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update && sudo apt-get install -y radare2 qemu-user-static qemu-system-arm || echo "apt-get step had errors; continuing"
elif command -v dnf >/dev/null 2>&1; then
  sudo dnf install -y radare2 qemu-user-static qemu-system-arm || echo "dnf step had errors; continuing"
elif command -v zypper >/dev/null 2>&1; then
  sudo zypper install -y radare2 qemu-linux-user qemu-arm || echo "zypper step had errors; continuing"
elif command -v brew >/dev/null 2>&1; then
  echo "Note: qemu-user-mode static binaries are Linux-only; macOS gets system emulation only."
  brew install radare2 qemu || echo "brew step had errors; continuing"
else
  echo "No supported package manager found. Install manually: radare2, qemu-user-static, qemu-system, frida-tools"
fi
if command -v uv >/dev/null 2>&1; then
  uv tool install frida-tools || echo "uv frida-tools step had errors; continuing"
elif command -v pipx >/dev/null 2>&1; then
  pipx install frida-tools || echo "pipx frida-tools step had errors; continuing"
elif command -v pip >/dev/null 2>&1; then
  pip install --user frida-tools || echo "pip frida-tools step had errors; continuing"
else
  echo "install frida-tools manually"
fi
echo; check
bash "$HERE/capabilities.sh" --out "$HERE/../capabilities.json" >/dev/null 2>&1 || true
echo "done"
