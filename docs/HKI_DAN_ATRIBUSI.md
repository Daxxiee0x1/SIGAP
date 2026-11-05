# Hak kekayaan intelektual, atribusi, dan deklarasi karya

Dokumen ini memuat atribusi dan deklarasi karya yang diminta Rulebook Kartika Cyber
Hackathon 2026 bagian G "Pengumpulan dan Ketentuan Karya". Repositori ini tidak memakai
lisensi open source.

## 1. Atribusi komponen pihak ketiga

Semua komponen di bawah ini open source dengan lisensi yang sah. Agen Go (`cmd/`, `internal/`)
hanya memakai pustaka standar Go dan tidak memiliki dependensi pihak ketiga.

### Dipakai saat SIGAP berjalan

| Komponen | Versi | Lisensi | Dipakai oleh |
| --- | --- | --- | --- |
| Go standard library | 1.22 | BSD-3-Clause | agen dan verifier `sigap` |
| FastAPI | 0.115.6 | MIT | vault (`vault/requirements.txt`) |
| Uvicorn | 0.34.0 | BSD-3-Clause | vault |
| python-multipart | 0.0.20 | Apache-2.0 | vault (unggah bundle) |
| Starlette | 0.41.3 | BSD-3-Clause | dependensi FastAPI |
| Pydantic / pydantic-core | 2.14.2 / 2.50.2 | MIT | dependensi FastAPI |
| AnyIO | 4.16.0 | MIT | dependensi Starlette |
| h11 | 0.16.0 | MIT | dependensi Uvicorn |
| Click | 8.5.0 | BSD-3-Clause | dependensi Uvicorn |
| idna | 3.20 | BSD-3-Clause | dependensi AnyIO |
| typing-extensions | 4.16.0 | PSF-2.0 | dependensi Pydantic |
| annotated-types | 0.8.0 | MIT | dependensi Pydantic |
| typing-inspection | 0.4.5 | MIT | dependensi Pydantic |
| Python | 3.11 / 3.12 | PSF-2.0 | vault, simulasi, alat uji |

Versi dependensi tidak langsung mengikuti hasil `pip install` dan diperiksa pada 5 November
2026. Periksa ulang dengan `pip list` bila `vault/requirements.txt` berubah.

### Dipakai untuk build, uji, dan materi submission

| Komponen | Lisensi | Kegunaan |
| --- | --- | --- |
| Image Docker `golang:1.22-bookworm`, `python:3.12-slim-bookworm` | BSD-3-Clause (Go), PSF-2.0 (Python), lisensi paket Debian | build dan demo Docker |
| Docker Engine dan Docker Compose | Apache-2.0 | menjalankan demo (`docker-compose.yml`, `make up`, `make demo`) |
| curl | curl license (mirip MIT) | memanggil API vault di demo (`scripts/demo.sh`, `docs/cara_mencoba.md`) |
| pytest | MIT | pengujian (`tests/`) |
| IBM Plex Mono dan IBM Plex Sans Condensed | SIL Open Font License 1.1 | huruf di slide dan thumbnail, tertanam di PDF slide |
| Chromium | BSD-3-Clause dan lainnya | merender slide ke PDF |
| GitHub Actions `actions/checkout`, `actions/setup-go`, `actions/setup-python` | MIT | CI dan pembangunan rilis (`.github/workflows/`) |
| GitHub CLI (`gh`) | MIT | menerbitkan GitHub Release (`.github/workflows/release.yml`) |

### Standar dan spesifikasi publik yang diterapkan

Standar berikut diterapkan lewat pustaka standar Go dan Python. Tidak ada kode yang disalin
dari dokumen standar.

| Standar | Dipakai untuk |
| --- | --- |
| Ed25519 (RFC 8032) | tanda tangan manifest bundle (`internal/signing`) |
| SHA-256 (FIPS 180-4) | hash artefak, bundle, dan rantai log kustodi |
| Format ZIP (PKWARE APPNOTE) | kemasan bundle (`internal/bundle`, `internal/verify`) |
| RFC 3339 | format waktu di manifest dan log |
| RFC 5737 | rentang alamat dokumentasi `203.0.113.0/24` di jaringan demo |

RFC 3161 (stempel waktu tepercaya) hanya disebut sebagai rencana pengembangan dan belum
diimplementasikan. Velociraptor, UAC, dan Autopsy hanya disebut sebagai pembanding di
dokumentasi dan slide. Tidak ada kode atau aset dari ketiganya yang dipakai.

### Kerangka desain yang dirujuk

Slide memakai kerangka publik berikut sebagai rujukan metode, bukan sebagai kode atau aset
yang disalin: ISO 9241-210 (human-centered
design), *The Elements of User Experience* (Jesse James Garrett), 10 heuristik kegunaan
(Jakob Nielsen), hukum Fitts, Hick, Miller, dan Doherty, metrik lostness (Smith, 1996), serta
Customer Needs Analysis Matrix. Ikon dan piktogram digambar sendiri oleh tim.

## 2. Deklarasi originalitas

Rulebook meminta karya pre-existing dideklarasikan secara jelas.

| Pernyataan | Isi |
| --- | --- |
| Kode atau karya yang sudah ada sebelum periode program | **Kode program: tidak ada.** Seluruh kode di `cmd/`, `internal/`, `vault/`, `simulation/`, `tools/`, `tests/`, `scripts/`, `deploy/`, dan `offline/` ditulis untuk karya ini. Tidak ada potongan kode yang disalin dari proyek lain. **Karya pihak lain yang sudah ada dan dipakai tanpa diubah:** (1) pustaka, framework, dan image Docker di bagian 1, yang dipasang sebagai dependensi dan tidak disertakan sebagai salinan kode di repositori; (2) huruf IBM Plex Mono dan IBM Plex Sans Condensed (IBM Corp., 2017, SIL OFL 1.1) yang dipakai di slide dan thumbnail. |
| Alat bantu AI | Model AI **Claude** (Anthropic), termasuk melalui Figma Make, dipakai sebagai asisten untuk menulis dan meninjau kode, menyusun konfigurasi menjalankan proyek, dokumentasi, slide, tangkapan layar, dan alur rilis GitHub. Seluruh hasil ditinjau dan diuji oleh tim, dan menjadi tanggung jawab tim. |

Tim menyatakan bahwa:

1. Karya dikerjakan oleh anggota tim selama periode program, kecuali bagian yang
   dideklarasikan di atas.
2. Komponen pihak ketiga dipakai sesuai lisensinya dan diberi atribusi di bagian 1.
3. Karya tidak memuat malware aktif. Skenario serangan di `simulation/` hanya simulasi:
   reverse shell berupa proses tidur berpola tanpa koneksi, dan lalu lintas jaringan hanya ke
   rentang dokumentasi RFC 5737 di jaringan Docker internal.
4. Karya tidak memuat data pribadi pihak ketiga. Nilai seperti `api_key=demo-not-a-real-secret-123`
   di `simulation/sensor.conf` dan token `sigap-demo-token` adalah nilai demo, bukan kredensial nyata.
5. Karya tidak melanggar hak kekayaan intelektual pihak lain.
