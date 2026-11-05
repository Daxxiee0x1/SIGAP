#!/bin/sh
# Membangun aset GitHub Release: biner sigap statis untuk laptop juri (Linux, macOS,
# Windows) dan "kit juri" berisi contoh bundle, sehingga `sigap verify` bisa dicoba
# tanpa Docker, Go, atau Python.
#
#   scripts/build-release.sh [versi]      ->  dist/release/  dan  dist/release-notes.md
#
# Isi bundle contoh sepenuhnya sintetis (/proc tiruan sebuah node sensor), bukan data
# mesin build. Kunci privat demo dibuat di direktori sementara lalu dibuang.
set -eu
cd "$(dirname "$0")/.."

VERSION=${1:-dev}
OUT=dist/release
KIT_NAME=sigap-kit-juri-$VERSION
KIT=dist/$KIT_NAME
rm -rf "$OUT" "$KIT"
mkdir -p "$OUT" "$KIT/bin" "$KIT/bundle"

echo "== 1. Biner lintas platform"
for target in linux/amd64 linux/arm64 linux/arm/7 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%%/*}; rest=${target#*/}; arch=${rest%%/*}
  arm=""; [ "$arch" = "arm" ] && arm=${rest#*/}
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  name="sigap-$os-$arch${arm:+v$arm}$ext"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=$arm go build -trimpath -ldflags "-s -w" -o "$KIT/bin/$name" ./cmd/sigap
  cp "$KIT/bin/$name" "$OUT/$name"
  echo "   $name"
done

echo "== 2. Contoh bundle dari node sensor sintetis"
sh scripts/make-samples.sh "$KIT"

echo "== 3. Skrip dan panduan"
cp scripts/kit-juri/BACA-SAYA.md scripts/kit-juri/coba.sh scripts/kit-juri/coba.ps1 scripts/kit-juri/coba.cmd "$KIT/"
chmod +x "$KIT/coba.sh" "$KIT"/bin/sigap-linux-* "$KIT"/bin/sigap-darwin-*

echo "== 4. Uji kit di mesin ini"
if [ "$(uname -s)" = "Linux" ] || [ "$(uname -s)" = "Darwin" ]; then
  "$KIT/coba.sh"
fi

echo "== 5. Paket"
python3 -m zipfile -c "$OUT/$KIT_NAME.zip" "$KIT"
if command -v sha256sum >/dev/null; then
  (cd "$OUT" && sha256sum -- * > SHA256SUMS)
else
  (cd "$OUT" && shasum -a 256 -- * > SHA256SUMS)
fi
sed "s/{{VERSI}}/$VERSION/g" scripts/kit-juri/CATATAN_RILIS.md > dist/release-notes.md
ls -l "$OUT"
echo "Aset rilis siap di $OUT"
