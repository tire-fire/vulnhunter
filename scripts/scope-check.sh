#!/usr/bin/env bash
set -u
ENG="${1:?engagement file}"; TARGET="${2:?target}"
[ -r "$ENG" ] || { echo "engagement file unreadable: $ENG" >&2; exit 3; }

# Parse simple YAML list under a key into newline-separated values (quotes stripped).
list_under(){ awk -v key="$1:" '
  $0 ~ "^"key"[ \t]*(#.*)?$" {inblk=1; next}
  inblk && /^[A-Za-z_]/ {inblk=0}
  inblk && /^[ \t]*-/ {
    sub(/^[ \t]*-[ \t]*/,"")
    sub(/[ \t]+#.*$/,"")
    gsub(/^[ \t]+|[ \t]+$/,"")
    gsub(/^"|"$/,""); gsub(/^'"'"'|'"'"'$/,"")
    if (length($0)) print
  }
' "$ENG"; }

ip_to_int(){ local IFS=.; read -r a b c d <<EOF
$1
EOF
echo $(( (a<<24)+(b<<16)+(c<<8)+d )); }

ip_in_cidr(){ local ip="$1" cidr="$2" net mask bits ipi neti
  net="${cidr%/*}"; bits="${cidr#*/}"
  case "$bits" in ''|*[!0-9]*) return 1;; esac; [ "$bits" -gt 32 ] && return 1
  case "$ip" in *[!0-9.]*|"") return 1;; esac
  case "$net" in *[!0-9.]*|"") return 1;; esac
  ipi="$(ip_to_int "$ip")"; neti="$(ip_to_int "$net")"
  if [ "$bits" -eq 0 ]; then return 0; fi
  mask=$(( 0xffffffff ^ ((1<<(32-bits))-1) ))
  [ $(( ipi & mask )) -eq $(( neti & mask )) ]; }

match_entry(){ local target="$1" entry="$2"
  case "$entry" in
    */[0-9]*) ip_in_cidr "$target" "$entry"; return $?;;
    \*.*) local suf="${entry#\*.}"; case "$target" in *".$suf"|"$suf") return 0;; *) return 1;; esac;;
    *) [ "$target" = "$entry" ];;
  esac; }

while IFS= read -r e; do [ -n "$e" ] && match_entry "$TARGET" "$e" && { echo "OUT_OF_SCOPE: $TARGET ~ $e" >&2; exit 2; }; done < <(list_under out_of_scope)
while IFS= read -r e; do [ -n "$e" ] && match_entry "$TARGET" "$e" && { echo "IN_SCOPE: $TARGET ~ $e" >&2; exit 0; }; done < <(list_under in_scope)
echo "NOT_IN_SCOPE: $TARGET" >&2; exit 2
