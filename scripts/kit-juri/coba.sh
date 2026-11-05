#!/bin/sh
# Memverifikasi semua contoh bundle dengan biner yang cocok untuk mesin ini (Linux/macOS).
#   ./coba.sh
set -u
cd "$(dirname "$0")"

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) echo "OS $(uname -s) belum didukung skrip ini. Di Windows, jalankan coba.cmd."; exit 1 ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  armv7*) arch=armv7 ;;
  *) echo "Arsitektur $(uname -m) belum didukung. Lihat isi folder bin/."; exit 1 ;;
esac
BIN=bin/sigap-$os-$arch
chmod +x "$BIN" 2>/dev/null
# macOS menandai biner unduhan sebagai karantina; biner ini tidak ditandatangani Apple.
[ "$os" = darwin ] && xattr -d com.apple.quarantine "$BIN" 2>/dev/null

echo "SIGAP verifier offline ($("$BIN" version)), trust store: trust_store.json"
echo
printf '%-26s %-18s %-18s %s\n' "BUNDLE" "HASIL" "HARAPAN" ""
lolos=0
beda=0
while read -r file want; do
  [ -n "$file" ] || continue
  got=$("$BIN" verify --trust trust_store.json "bundle/$file" </dev/null 2>/dev/null | head -n 1 | cut -d ' ' -f 1)
  if [ "$got" = "$want" ]; then
    mark="cocok"; lolos=$((lolos + 1))
  else
    mark="BEDA"; beda=$((beda + 1))
  fi
  printf '%-26s %-18s %-18s %s\n' "$file" "${got:-galat}" "$want" "$mark"
done < bundle/harapan.txt

echo
echo "$lolos cocok, $beda beda."
echo "Lihat alasan lengkap satu bundle, misalnya:"
echo "  $BIN verify --trust trust_store.json bundle/01_flip_byte.zip"
[ "$beda" -eq 0 ]
