#!/bin/sh
# Build an offline kit on a connected machine: static binaries for common edge CPUs,
# Python wheels for the vault, and saved Docker images for the demo.
set -eu
cd "$(dirname "$0")/.."
OUT=dist/sigap-offline
rm -rf "$OUT" && mkdir -p "$OUT/bin" "$OUT/wheelhouse" "$OUT/images"

for target in linux/amd64 linux/arm64 linux/arm/7; do
  os=${target%%/*}; rest=${target#*/}; arch=${rest%%/*}
  arm=""; [ "$arch" = "arm" ] && arm=${rest#*/}
  name="sigap-$os-$arch${arm:+v$arm}"
  CGO_ENABLED=0 GOOS=$os GOARCH=$arch GOARM=$arm go build -trimpath -ldflags "-s -w" -o "$OUT/bin/$name" ./cmd/sigap
done

pip download --only-binary=:all: --dest "$OUT/wheelhouse" -r vault/requirements.txt
docker compose build
docker save sigap-vault sigap-sensor-01 python:3.12-slim-bookworm -o "$OUT/images/sigap-images.tar"
cp -r docker-compose.yml offline/install.sh configs "$OUT/"
(cd "$OUT" && sha256sum bin/* images/* wheelhouse/* > SHA256SUMS)
tar -C dist -czf dist/sigap-offline.tar.gz sigap-offline
echo "Kit offline: dist/sigap-offline.tar.gz"
