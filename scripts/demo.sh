#!/usr/bin/env bash
# Runner demo SIGAP: menjalankan setiap adegan video demo secara berurutan dan berhenti
# menunggu Enter, supaya rekaman bisa diulang tanpa galat.
#
#   ./scripts/demo.sh             interaktif (untuk rekaman video)
#   AUTO=1 ./scripts/demo.sh      tanpa jeda (untuk latihan/uji)
#   KEEP=1 ./scripts/demo.sh      jangan hapus volume lama di awal
#
# Kebutuhan host: Docker (Compose v2) dan curl. Go/Python tidak wajib.
# Windows: jalankan dari Git Bash dengan Docker Desktop (bash scripts/demo.sh).
set -euo pipefail
cd "$(dirname "$0")/.."

# Git Bash di Windows mengubah argumen berawalan / (mis. /opt/sigap/...) menjadi path
# Windows saat memanggil docker.exe, dan $PWD berbentuk /c/Users/... yang tidak dikenali
# bind mount Docker Desktop. Matikan konversi itu dan pakai path C:/... untuk -v.
HOST_PWD=$PWD
USER_OPT=(--user "$(id -u):$(id -g)")
case "$(uname -s)" in
  MINGW* | MSYS*)
    export MSYS_NO_PATHCONV=1
    HOST_PWD=$(pwd -W)
    USER_OPT=()   # UID Git Bash tidak berarti apa-apa di dalam container
    ;;
esac

TOKEN="${SIGAP_VAULT_TOKEN:-sigap-demo-token}"
VAULT="http://127.0.0.1:8000"
OUT="build/demo"
VAULT_IMG="sigap-vault"
PY_IMG="python:3.12-slim-bookworm"

b=$'\e[1m'; d=$'\e[2m'; c=$'\e[36m'; g=$'\e[32m'; r=$'\e[0m'
scene() { printf '\n%s━━━ %s ━━━%s\n' "$b" "$1" "$r"; }
say()   { printf '%s» %s%s\n' "$d" "$1" "$r"; }
show()  { printf '%s$ %s%s\n' "$c" "$1" "$r"; }
run()   { show "$*"; "$@"; }
pause() { [ "${AUTO:-0}" = 1 ] && return 0; read -r -p "  ${g}[Enter] adegan berikutnya${r} " _; }

wait_for() { # wait_for "keterangan" detik perintah...
  local desc=$1 t=$2; shift 2
  printf '%s  menunggu: %s%s' "$d" "$desc" "$r"
  for _ in $(seq "$t"); do
    if "$@" >/dev/null 2>&1; then printf ' %sok%s\n' "$g" "$r"; return 0; fi
    printf '.'; sleep 1
  done
  printf '\n  gagal menunggu: %s. Cek: docker compose logs\n' "$desc" >&2; exit 1
}

sensor() { docker compose exec -T sensor-01 "$@"; }
vault_count() { curl -fsS "$VAULT/api/bundles" | grep -o '"bundle_sha256"' | wc -l | tr -d ' '; }
vault_has() { [ "$(vault_count)" -ge "$1" ]; }

# Analyst laptop with no network at all: the same Go verifier, in a container with --network none.
verify_offline() {
  show "sigap verify --trust trust_store.json $1    # docker run --network none"
  docker run --rm --network none -v "$HOST_PWD/$OUT:/demo:ro" "$VAULT_IMG" \
    sigap verify --trust /demo/trust_store.json "/demo/$1" || true
}
pyrun() { docker run --rm --network none ${USER_OPT[@]+"${USER_OPT[@]}"} -v "$HOST_PWD:/w" -w /w "$PY_IMG" python3 "$@"; }
submit() {
  show "curl -H 'Authorization: Bearer ****' -F file=@$1 $VAULT/api/bundles"
  curl -fsS -H "Authorization: Bearer $TOKEN" -F "file=@$1" -F "note=$2" "$VAULT/api/bundles"; echo
}
copy_out() { docker compose cp "sensor-01:$1" "$2" >/dev/null && chmod a+r "$2"; }

command -v docker >/dev/null || { echo "Docker tidak ditemukan"; exit 1; }
command -v curl >/dev/null || { echo "curl tidak ditemukan"; exit 1; }
docker compose version >/dev/null || { echo "Perlu Docker Compose v2"; exit 1; }

# ── 0 ─────────────────────────────────────────────────────────────────────────
scene "0 · Persiapan (tidak direkam; adegan 1-3 = slide pengenalan, masalah, solusi)"
if [ "${KEEP:-0}" != 1 ]; then run docker compose down -v --remove-orphans; fi
run docker compose up -d --build
wait_for "vault siap di $VAULT" 180 curl -fsS "$VAULT/api/bundles"
wait_for "kunci node terdaftar di trust store" 60 sensor test -s /data/trust/trust_store.json
rm -rf "$OUT" && mkdir -p "$OUT"
say "Buka $VAULT di browser (dashboard audit), atur terminal di kiri dan browser di kanan."
say "Mulai rekam, lalu tekan Enter."
pause

# ── 2 ─────────────────────────────────────────────────────────────────────────
scene "4 · Arsitektur dan node normal (1:35-2:15)"
run docker compose ps --format "table {{.Service}}\t{{.Status}}"
run docker compose logs --no-log-prefix --tail 4 sensor-01
say "Dashboard masih kosong: belum ada bundle."
pause

# ── 3 ─────────────────────────────────────────────────────────────────────────
scene "5a · Link terputus, insiden terjadi (2:15-2:45)"
run docker compose stop vault
show "python3 inject_anomaly.py reverse_shell   # simulasi aman: proses tidur berpola, tanpa koneksi"
sensor python3 /opt/sigap/simulation/inject_anomaly.py reverse_shell --seconds 90
pause

# ── 4 ─────────────────────────────────────────────────────────────────────────
scene "5b · Deteksi dan koleksi otomatis (2:45-3:30)"
wait_for "bundle muncul di outbox" 30 sensor sh -c 'ls /var/lib/sigap/outbox/*.zip'
sleep 4
run docker compose logs --no-log-prefix --tail 8 sensor-01
run sensor sh -c 'ls -l /var/lib/sigap/outbox/'
pause

# ── 5 ─────────────────────────────────────────────────────────────────────────
scene "6 · Verifikasi offline di laptop analis (3:30-4:10)"
BUNDLE=$(sensor sh -c 'ls -t /var/lib/sigap/outbox/*.zip | head -1' | tr -d '\r')
copy_out "$BUNDLE" "$OUT/bundle.zip"
copy_out /data/trust/trust_store.json "$OUT/trust_store.json"
say "Bundle dan trust_store.json disalin ke laptop analis (bisa lewat flashdisk)."
show "python3 -m zipfile -l bundle.zip"
pyrun -m zipfile -l "$OUT/bundle.zip"
verify_offline bundle.zip
pause

# ── 6 ─────────────────────────────────────────────────────────────────────────
scene "7 · Link pulih, vault dan timeline kustodi (4:10-5:00)"
run docker compose start vault
wait_for "bundle diterima vault" 90 vault_has 1
run docker compose logs --no-log-prefix --tail 3 sensor-01
say "Di dashboard: klik bundle -> VALID, daftar artefak + redaksi, timeline kustodi."
pause

# ── 7 ─────────────────────────────────────────────────────────────────────────
scene "8 · Uji manipulasi (5:00-6:10)"
show "python3 tools/make_tampered.py bundle.zip tampered/"
pyrun tools/make_tampered.py "$OUT/bundle.zip" "$OUT/tampered"
for f in "$OUT"/tampered/*.zip; do verify_offline "tampered/$(basename "$f")"; done

say "Penyerang memakai kunci Ed25519 sah miliknya sendiri, yang tidak ada di trust store:"
sensor sh -c '
  rm -rf /tmp/atk && mkdir -p /tmp/atk &&
  sigap keygen --key-id attacker-laptop --out /tmp/atk/atk.key >/dev/null &&
  python3 -c "import json; c = json.load(open(\"/etc/sigap/agent.json\")); c.update(key_file=\"/tmp/atk/atk.key\", outbox=\"/tmp/atk/out\", vault_url=\"\"); json.dump(c, open(\"/tmp/atk/agent.json\", \"w\"))" &&
  sigap collect --config /tmp/atk/agent.json --trigger "bukti palsu" >/dev/null 2>&1'
copy_out "$(sensor sh -c 'ls /tmp/atk/out/*.zip' | tr -d '\r')" "$OUT/foreign.zip"
verify_offline foreign.zip

say "Kirim ke vault: hasilnya sama karena vault memanggil verifier Go yang sama."
submit "$OUT/tampered/01_flip_byte.zip" "uji: ubah 1 byte"
submit "$OUT/foreign.zip" "uji: kunci asing"
submit "$OUT/bundle.zip" "uji: replay bundle asli"
say "Dashboard: TAMPERED dan UNTRUSTED_SIGNER muncul; replay dicatat duplicate_ignored."
pause

# ── 8 ─────────────────────────────────────────────────────────────────────────
scene "9 · Audit rantai kustodi (6:10-6:40)"
run curl -fsS "$VAULT/api/custody/verify"; echo
run curl -fsS "$VAULT/api/custody/head"; echo
say "Admin nakal menghapus trigger dan menulis ulang satu entri langsung di SQLite:"
show "DROP TRIGGER custody_no_update; UPDATE custody_log SET detail='VALID' WHERE detail='TAMPERED'"
docker compose exec -T vault python3 -c "
import sqlite3
c = sqlite3.connect('/data/vault/vault.sqlite3')
c.execute('DROP TRIGGER IF EXISTS custody_no_update')
c.execute(\"UPDATE custody_log SET detail = 'VALID' WHERE action = 'verified' AND detail = 'TAMPERED'\")
c.commit()"
run curl -fsS "$VAULT/api/custody/verify"; echo
say "Klik 'Periksa rantai' di dashboard: PUTUS di entri yang diubah."
pause

# ── 9 ─────────────────────────────────────────────────────────────────────────
scene "10-11 · Manfaat dan penutup (6:40-8:00, slide)"
say "Berhenti merekam. Bersihkan dengan: docker compose down -v"
