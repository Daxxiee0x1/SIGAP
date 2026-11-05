#!/bin/sh
# Install from the offline kit on a machine without internet.
set -eu
cd "$(dirname "$0")"
sha256sum -c SHA256SUMS

case "$(uname -m)" in
  x86_64) bin=bin/sigap-linux-amd64 ;;
  aarch64) bin=bin/sigap-linux-arm64 ;;
  armv7l) bin=bin/sigap-linux-armv7 ;;
  *) echo "arsitektur tidak didukung: $(uname -m)"; exit 1 ;;
esac
install -m 0755 "$bin" /usr/local/bin/sigap
echo "sigap terpasang: $(sigap version)"

if command -v docker >/dev/null 2>&1; then
  docker load -i images/sigap-images.tar
  echo "Image demo dimuat. Jalankan: docker compose up -d"
fi
echo "Vault tanpa Docker: pip install --no-index --find-links wheelhouse fastapi uvicorn python-multipart"
