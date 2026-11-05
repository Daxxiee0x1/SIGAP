#!/bin/sh
# Membangun situs "coba online" untuk GitHub Pages: halaman statis, verifier SIGAP yang
# dikompilasi ke WebAssembly, dan 10 contoh bundle sintetis.
#
#   sh scripts/build-site.sh       ->  dist/site/
#   python3 -m http.server -d dist/site 8080   (pratinjau lokal di http://127.0.0.1:8080)
set -eu
cd "$(dirname "$0")/.."
OUT=dist/site
rm -rf "$OUT"
mkdir -p "$OUT"
cp -R site/. "$OUT/"

GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/sigap.wasm" ./cmd/sigap-wasm
GOROOT=$(go env GOROOT)
for f in "$GOROOT/lib/wasm/wasm_exec.js" "$GOROOT/misc/wasm/wasm_exec.js"; do
  if [ -f "$f" ]; then cp "$f" "$OUT/wasm_exec.js"; break; fi
done
[ -f "$OUT/wasm_exec.js" ] || { echo "wasm_exec.js tidak ditemukan di $GOROOT" >&2; exit 1; }

sh scripts/make-samples.sh "$OUT/samples"
touch "$OUT/.nojekyll"
echo "Situs siap di $OUT ($(du -sh "$OUT" | cut -f1))"
