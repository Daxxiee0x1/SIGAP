# Kit Juri SIGAP: coba verifier offline dalam 1 menit

Kit ini untuk mencoba bagian inti SIGAP, yaitu verifier bundle bukti yang berjalan
**tanpa Docker, tanpa internet, dan tanpa memasang apa pun**. Demo lengkap (agen, deteksi,
vault, dashboard) tetap memakai Docker. Lihat `docs/cara_mencoba.md` di repositori.

## Cara mencoba

Ekstrak zip ini, lalu:

| Sistem | Langkah |
| --- | --- |
| Windows | Klik dua kali `coba.cmd`. Kalau SmartScreen muncul, pilih *More info* lalu *Run anyway* (biner belum ditandatangani). |
| macOS | Buka Terminal di folder ini, jalankan `./coba.sh` |
| Linux | Jalankan `./coba.sh` |

Skrip memilih biner yang cocok dari `bin/`, memverifikasi setiap berkas di `bundle/`, lalu
membandingkan hasilnya dengan `bundle/harapan.txt`. Hasil yang diharapkan: semua baris
`cocok`.

| Bundle | Manipulasi | Hasil yang benar |
| --- | --- | --- |
| `00_asli.zip` | Tidak ada. Bundle asli dari node `sensor-01` | `VALID` |
| `01_flip_byte.zip` | 1 bit di `process_list.txt` dibalik | `TAMPERED` |
| `02_add_unlisted.zip` | Berkas tambahan yang tidak tercantum di manifest | `TAMPERED` |
| `03_remove_listed.zip` | `system_log.log` dihapus dari zip | `INCOMPLETE` |
| `04_edit_manifest.zip` | Nomor urut di `manifest.json` diubah | `TAMPERED` |
| `05_swap_signature.zip` | Tanda tangan diganti tanda tangan palsu | `TAMPERED` |
| `06_kunci_asing.zip` | Ditandatangani kunci sah yang tidak terdaftar di trust store | `UNTRUSTED_SIGNER` |
| `07a_zip_slip.zip` | Entri berjalur `../../etc/cron.d/...` | `MALFORMED` |
| `07b_symlink.zip` | Entri symlink ke `/etc/shadow` | `MALFORMED` |
| `08_decompression_bomb.zip` | Entri 110 MB yang memadat jadi sangat kecil | `MALFORMED` |

## Mencoba manual

```sh
bin/sigap-linux-amd64 verify --trust trust_store.json bundle/00_asli.zip
bin/sigap-linux-amd64 verify --json --trust trust_store.json bundle/01_flip_byte.zip
```

Ganti nama biner sesuai sistem: `sigap-darwin-arm64` (Mac Apple Silicon),
`sigap-darwin-amd64` (Mac Intel), `sigap-windows-amd64.exe`, `sigap-linux-arm64`,
`sigap-linux-armv7`. Kode keluar: 0 `VALID`, 2 `TAMPERED`, 3 `INCOMPLETE`,
4 `UNTRUSTED_SIGNER`, 5 `MALFORMED`.

Untuk melihat isi bukti, ekstrak `bundle/00_asli.zip` dengan pengelola arsip biasa. Isinya
`manifest.json`, `manifest.sig`, dan enam artefak. Nilai `api_key` di
`config_redacted.txt` sudah disamarkan sebelum di-hash.

## Catatan

- **Data sintetis.** Bundle dibuat dari `/proc` tiruan sebuah node sensor saat rilis
  dibangun. Tidak ada data pribadi atau data sistem sungguhan. "Reverse shell" di daftar
  proses hanyalah teks simulasi.
- **Varian 07a, 07b, dan 08 sengaja berbahaya bentuknya** untuk menguji pertahanan
  verifier. Isinya tidak berbahaya, tetapi jangan diekstrak dengan alat lain. Antivirus
  bisa saja menandai varian ini.
- Kunci privat yang menandatangani bundle dibuang setelah rilis dibangun. Yang ada di
  kit hanya kunci publik di `trust_store.json`, berlaku 2 tahun sejak rilis.
- Keaslian biner bisa dicek dengan `SHA256SUMS` di halaman rilis GitHub.
