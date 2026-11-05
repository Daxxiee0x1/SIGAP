# Cara mencoba SIGAP

Panduan ini ditulis untuk Dewan Juri dan siapa pun yang ingin menjalankan purwarupa dari
nol. Pilih satu jalur:

| Jalur | Untuk | Kebutuhan | Waktu |
| --- | --- | --- | --- |
| Coba online | Juri yang ingin langsung mencoba verifier di browser | Browser modern. Buka <https://daxxiee0x1.github.io/SIGAP/> | ±1 menit |
| [A. Docker](#a-docker-jalur-utama) | Demo lengkap seperti di video | Docker Compose v2.20+, curl | ±3 menit setelah build |
| [B. Tanpa Docker](#b-tanpa-docker-linux) | Pengembangan, atau host tanpa Docker | Linux, Go 1.22, Python 3.11+ | ±5 menit |
| [C. Verifier saja](#c-verifier-saja-laptop-analis) | Juri yang ingin mencoba tanpa memasang apa pun, atau analis yang memeriksa bundle | Kit juri dari GitHub Releases (Windows, macOS, Linux) | ±1 menit |

Situs coba online menjalankan verifier yang sama (`internal/verify`), dikompilasi ke
WebAssembly. Verifikasi berlangsung di browser dan bundle tidak dikirim ke server mana pun.
Situs ini hanya mencakup verifikasi. Deteksi oleh agen, vault, dan rantai kustodi dicoba
lewat jalur A atau B.

Semua jalur aman dijalankan. Skenario serangan hanyalah simulasi: reverse shell berupa proses
tidur dengan pola di baris perintahnya, dan lalu lintas jaringan hanya menuju rentang
dokumentasi `203.0.113.0/24` di jaringan Docker internal.

---

## A. Docker (jalur utama)

### Prasyarat

- Docker dengan Compose v2.20 atau lebih baru (`docker compose version`)
- `curl`
- Port `127.0.0.1:8000` belum dipakai aplikasi lain
- Internet hanya untuk build pertama (mengunduh image `golang` dan `python`). Setelah itu
  semuanya berjalan tanpa internet.

### Langkah

**1. Ambil kode dan jalankan.**

```sh
git clone https://github.com/Daxxiee0x1/SIGAP.git sigap && cd sigap
make up
```

`make up` membangun dua image lalu menjalankan tiga layanan di jaringan internal
`203.0.113.0/24`:

| Layanan | Alamat | Isi |
| --- | --- | --- |
| `vault` | 203.0.113.10, juga `127.0.0.1:8000` di host | FastAPI, SQLite, dan verifier Go |
| `sensor-01` | 203.0.113.21 | agen `sigap` dan sensor telemetri simulasi |
| `sink` | 203.0.113.50 | host "luar" yang aman untuk skenario egress |

Hasil yang diharapkan: `docker compose ps` menampilkan ketiga layanan berstatus `Up`.

**2. Buka dashboard.** Buka <http://127.0.0.1:8000>. Tabel "Bundle diterima" masih kosong.

**3. Pantau log agen** di terminal kedua:

```sh
make logs
```

Tunggu baris `agen sensor-01 aktif, baseline diambil, interval 2s`.

**4. Picu insiden.**

```sh
make inject-reverse_shell
```

Dalam sekitar 2 detik, log menampilkan:

```
[sigap] ALERT reverse_shell_pattern [critical] pid ... cocok pola "/dev/tcp/": ...
[sigap] bundle bnd-sensor-01-YYYYMMDD-001: 6 artefak, sha256 ..., /var/lib/sigap/outbox/...
[sigap] uplink: 1 bundle terkirim ke vault
```

**5. Periksa di dashboard.** Muncul satu baris berstatus `VALID`. Klik baris itu untuk
melihat:

- alasan verifikasi: `tanda tangan sah (node-sensor-01-2026-a); 6 artefak cocok`
- enam artefak dengan SHA-256 dan ukuran. `config_redacted.txt` menunjukkan 1 redaksi
  karena `api_key` disamarkan sebelum di-hash.
- timeline kustodi. Peristiwa dari node diberi label "dilaporkan sendiri", sedangkan
  peristiwa vault memakai waktu vault.

**6. Uji manipulasi secara offline.**

```sh
make tamper-demo
```

Perintah ini menyalin bundle terbaru dan `trust_store.json` keluar dari container, membuat
8 varian manipulasi, lalu memverifikasi semuanya di container `--network none`. Go atau
Python tidak perlu terpasang di host. Hasil yang diharapkan:

| Berkas | Status |
| --- | --- |
| `bundle.zip` | `VALID` |
| `01_flip_byte.zip`, `02_add_unlisted.zip`, `04_edit_manifest.zip`, `05_swap_signature.zip` | `TAMPERED` |
| `03_remove_listed.zip` | `INCOMPLETE` |
| `07a_zip_slip.zip`, `07b_symlink.zip`, `08_decompression_bomb.zip` | `MALFORMED` |

**7. Kirim bundle manipulasi ke vault.** Vault memakai verifier yang sama, jadi hasilnya
sama:

```sh
TOKEN=sigap-demo-token
curl -H "Authorization: Bearer $TOKEN" -F file=@build/demo/tampered/01_flip_byte.zip -F "note=uji: ubah 1 byte" http://127.0.0.1:8000/api/bundles
curl -H "Authorization: Bearer $TOKEN" -F file=@build/demo/bundle.zip -F "note=uji: replay" http://127.0.0.1:8000/api/bundles
curl -F file=@build/demo/bundle.zip http://127.0.0.1:8000/api/bundles   # tanpa token
```

Hasil yang diharapkan: `"status":"TAMPERED"`, lalu `"duplicate":true`, lalu HTTP `401`.

**8. Audit rantai kustodi.** Klik **Periksa rantai** di dashboard. Hasilnya `utuh (N entri)`.
Untuk mensimulasikan admin nakal yang menulis ulang database:

```sh
docker compose exec -T vault python3 -c "
import sqlite3
c = sqlite3.connect('/data/vault/vault.sqlite3')
c.execute('DROP TRIGGER IF EXISTS custody_no_update')
c.execute(\"UPDATE custody_log SET detail = 'VALID' WHERE action = 'verified' AND detail = 'TAMPERED'\")
c.commit()"
```

Klik **Periksa rantai** lagi. Hasilnya `PUTUS di entri #N`.

**9. Skenario lain** (opsional):

```sh
make inject-egress          # koneksi ke 203.0.113.50 di luar allowlist
make inject-listen_port     # port 31337 baru
make inject-config_change   # hash /etc/sensor/sensor.conf berubah
make inject-cpu_spike       # lonjakan CPU
make inject-tmp_exec        # eksekusi biner dari /tmp
```

Alert yang sama ditahan selama cooldown 60 detik. Tunggu sebentar bila skenario yang sama
diulang.

**10. Demo penuh seperti di video.** `make demo` menjalankan semua adegan berurutan dan
berhenti di setiap adegan. `AUTO=1 make demo` berjalan tanpa jeda.

**11. Bersihkan.**

```sh
make down   # menghapus container dan volume (kunci node, outbox, database)
```

---

## B. Tanpa Docker (Linux)

> **Windows dengan Git Bash?** Jalur A tetap bisa dipakai dengan Docker Desktop. Lihat
> [Windows (Git Bash)](#windows-git-bash) di bawah.

Agen membaca `/proc`, jadi jalur ini hanya bisa dijalankan di Linux. Langkah ini
dijalankan ulang pada 5 November 2026. Hasilnya ada di [bukti_demo.md](bukti_demo.md).

### 1. Build dan siapkan folder lab

```sh
make build                                   # ./build/sigap
LAB=$HOME/sigap-lab
mkdir -p $LAB/node/outbox $LAB/vault
cp simulation/sensor.conf $LAB/sensor.conf
printf 'telemetry ok\n%.0s' $(seq 40) > $LAB/sensor.log
./build/sigap keygen --key-id node-sensor-01-2026-a --out $LAB/node/node.key --trust $LAB/trust_store.json
```

### 2. Buat konfigurasi agen lokal

```sh
cat > $LAB/agent.json <<EOF
{
  "node_id": "sensor-01",
  "proc_root": "/proc",
  "key_file": "$LAB/node/node.key",
  "outbox": "$LAB/node/outbox",
  "log_files": ["$LAB/sensor.log"],
  "config_files": ["$LAB/sensor.conf"],
  "interval_seconds": 2,
  "trigger_file": "$LAB/node/trigger",
  "vault_url": "http://127.0.0.1:8000",
  "vault_token_env": "SIGAP_VAULT_TOKEN",
  "rules": {
    "shell_patterns": ["/dev/tcp/", "nc -e", "ncat -e", "bash -i", "socat exec:"],
    "egress_allowlist": ["0.0.0.0/0", "::/0"],
    "watched_files": ["$LAB/sensor.conf"],
    "suspicious_exec_dirs": ["/tmp/", "/var/tmp/", "/dev/shm/"],
    "cpu_threshold_pct": 85, "mem_threshold_pct": 95, "spike_samples": 3, "cooldown_seconds": 60
  }
}
EOF
```

`egress_allowlist` dibuka lebar karena host pengembang selalu punya koneksi keluar yang sah.
Di jaringan Docker internal, allowlist-nya ketat (lihat `configs/agent.json`).

### 3. Jalankan vault

```sh
python3 -m venv .venv && .venv/bin/pip install -r vault/requirements.txt
SIGAP_DATA_DIR=$LAB/vault SIGAP_TRUST_STORE=$LAB/trust_store.json \
SIGAP_BIN=$PWD/build/sigap SIGAP_VAULT_TOKEN=sigap-demo-token \
.venv/bin/python -m uvicorn app.main:app --app-dir vault --host 127.0.0.1 --port 8000
```

### 4. Jalankan agen di terminal kedua, lalu picu insiden

Jalankan vault **sebelum** agen. Agen mengambil baseline port saat mulai, jadi port yang
dibuka setelahnya akan dilaporkan sebagai `new_listen_port`.

```sh
SIGAP_VAULT_TOKEN=sigap-demo-token ./build/sigap agent --config $LAB/agent.json
```

```sh
python3 simulation/inject_anomaly.py reverse_shell --seconds 30   # terminal ketiga
```

Untuk melihat perilaku DDIL, hentikan vault (Ctrl+C) sebelum menjalankan inject. Agen akan
mencatat `uplink tertunda, bundle tetap di outbox`. Setelah vault dijalankan lagi, muncul
`link ke vault pulih` dan `uplink: 1 bundle terkirim ke vault`.

### 5. Verifikasi dan manipulasi

```sh
cp $LAB/node/outbox/sent/bnd-*.zip bundle.zip 2>/dev/null || cp $LAB/node/outbox/bnd-*.zip bundle.zip
./build/sigap verify --trust $LAB/trust_store.json bundle.zip
python3 tools/make_tampered.py bundle.zip tampered/
for f in tampered/*.zip; do ./build/sigap verify --trust $LAB/trust_store.json "$f"; done
```

Tanpa agen, satu bundle juga bisa dibuat secara manual:
`./build/sigap collect --config $LAB/agent.json --trigger manual`.

---

## C. Verifier saja (laptop analis)

### Kit juri dari GitHub Releases (tanpa memasang apa pun)

1. Buka halaman **Releases** repositori, lalu unduh `sigap-kit-juri-<versi>.zip`.
2. Ekstrak, lalu jalankan:
   - Windows: klik dua kali `coba.cmd`. Kalau SmartScreen muncul, pilih *More info* lalu
     *Run anyway*, karena biner belum ditandatangani.
   - macOS atau Linux: `./coba.sh`
3. Skrip memilih biner yang cocok dari `bin/`, memverifikasi 10 contoh bundle, lalu
   membandingkan hasilnya dengan `bundle/harapan.txt`.

Hasil yang diharapkan: `10 cocok, 0 beda`.

| Bundle | Hasil |
| --- | --- |
| `00_asli.zip` | `VALID` |
| `01_flip_byte`, `02_add_unlisted`, `04_edit_manifest`, `05_swap_signature` | `TAMPERED` |
| `03_remove_listed` | `INCOMPLETE` |
| `06_kunci_asing` (kunci sah yang tidak terdaftar di trust store) | `UNTRUSTED_SIGNER` |
| `07a_zip_slip`, `07b_symlink`, `08_decompression_bomb` | `MALFORMED` |

Isi bundle sepenuhnya sintetis: `/proc` tiruan sebuah node sensor yang dibuat saat rilis
dibangun. Kunci privat penanda tangan dibuang setelah itu. Rilis dibangun oleh
`.github/workflows/release.yml` dengan `scripts/build-release.sh`, dan bisa dibangun ulang
secara lokal dengan `VERSION=v1.0.0 make release` (hasilnya di `dist/release/`).

### Dengan bundle dan trust store sendiri

Analis hanya membutuhkan biner `sigap`, `trust_store.json` dari kanal tepercaya, dan bundle.

```sh
# dari kit offline (dibuat dengan: make offline)
sha256sum -c SHA256SUMS && sudo install -m 0755 bin/sigap-linux-amd64 /usr/local/bin/sigap

sigap verify --trust trust_store.json bnd-sensor-01-20261105-001.zip
sigap verify --json --trust trust_store.json bundle.zip   # keluaran mesin, dipakai vault
```

| Status | Exit | Arti | Tindakan |
| --- | --- | --- | --- |
| `VALID` | 0 | Tanda tangan sah dari kunci di trust store, semua hash cocok | Lanjutkan analisis |
| `TAMPERED` | 2 | Byte berubah atau ada berkas tak terdaftar | Karantina dan minta salinan baru |
| `INCOMPLETE` | 3 | Berkas di manifest hilang | Minta bundle utuh dari outbox node |
| `UNTRUSTED_SIGNER` | 4 | Kunci tidak ada, dicabut, atau kedaluwarsa | Periksa trust store dan asal bundle |
| `MALFORMED` | 5 | Bukan zip, nama berbahaya, symlink, atau bom dekompresi | Jangan diekstrak |

Kit offline menyediakan biner Linux untuk `amd64`, `arm64`, dan `armv7`. GitHub Releases
juga menyediakan biner macOS (`darwin-amd64`, `darwin-arm64`) dan Windows
(`windows-amd64.exe`, `windows-arm64.exe`).

---

## Windows (Git Bash)

Butuh Docker Desktop (backend WSL 2) dan Git for Windows. `curl` sudah ada di Git Bash,
tetapi `make` tidak, jadi pakai padanan di bawah.

Git Bash mengubah argumen berawalan `/` menjadi path Windows saat memanggil `docker.exe`.
Matikan dulu di setiap jendela Git Bash:

```sh
export MSYS_NO_PATHCONV=1
```

| `make` | Padanan di Git Bash |
| --- | --- |
| `make up` | `docker compose up -d --build` |
| `make logs` | `docker compose logs -f sensor-01 vault` |
| `make inject-reverse_shell` | `docker compose exec -T sensor-01 python3 /opt/sigap/simulation/inject_anomaly.py reverse_shell` |
| `make demo` | `bash scripts/demo.sh` (atau `AUTO=1 bash scripts/demo.sh`) |
| `make tamper-demo` | Sudah tercakup di adegan 6 dan 8 `scripts/demo.sh` |
| `make down` | `docker compose down -v` |

`scripts/demo.sh` mengenali Git Bash sendiri: konversi path dimatikan otomatis, dan bind
mount memakai path `C:/...`.

## Pengujian otomatis

```sh
pip install pytest -r vault/requirements.txt
make test   # go vet, go test, pytest
```

CI (`.github/workflows/ci.yml`) menjalankan langkah yang sama ditambah `docker compose build`
pada setiap push.

## Variabel lingkungan

| Variabel | Default | Keterangan |
| --- | --- | --- |
| `SIGAP_VAULT_TOKEN` | `sigap-demo-token` di Docker Compose, kosong di vault | Token Bearer untuk unggah dan verifikasi ulang. **Ganti di luar demo.** Jika kosong, vault menolak unggahan dengan 503. |
| `SIGAP_DATA_DIR` | `/data/vault` | Lokasi SQLite dan bundle tersimpan |
| `SIGAP_TRUST_STORE` | `/data/trust/trust_store.json` | Trust store yang dipakai vault |
| `SIGAP_BIN` | `/usr/local/bin/sigap` | Biner verifier yang dipanggil vault |
| `SIGAP_NODE_ID` | dari `agent.json` | Menimpa `node_id` agen |

## Masalah umum

| Gejala | Penyebab | Tindakan |
| --- | --- | --- |
| `vault siap` tidak kunjung ok, atau dashboard tidak terbuka | Port 8000 dipakai aplikasi lain | Hentikan aplikasi tersebut atau ubah port di `docker-compose.yml` |
| Tidak ada bundle setelah inject | Agen belum selesai mengambil baseline, atau masih dalam cooldown 60 detik | Tunggu 5 detik setelah `make up`, lalu ulangi |
| Banyak alert `new_listen_port` di jalur B | Program lain (browser otomatis, server pengembangan) membuka port setelah baseline | Wajar di host bersama. Jalankan layanan lain sebelum agen, atau gunakan jalur A |
| `cpu_spike` tidak memicu | Lonjakan dihitung terhadap seluruh CPU host | Pakai skenario lain |
| `docker compose cp` gagal | Compose versi lama | Perbarui ke Compose v2.20+ |
| Unggah ke vault menghasilkan 503 | `SIGAP_VAULT_TOKEN` tidak diset | Set token saat menjalankan vault |
| Ingin mengulang dari awal | Volume lama masih ada | `make down`, lalu `make up` |
