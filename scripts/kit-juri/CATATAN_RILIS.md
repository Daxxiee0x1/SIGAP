Purwarupa SIGAP untuk Kartika Cyber Hackathon 2026, kategori Dukungan Teknologi.

## Untuk juri: coba tanpa Docker (±1 menit)

1. Unduh **`sigap-kit-juri-{{VERSI}}.zip`** di bawah, lalu ekstrak.
2. Windows: klik dua kali `coba.cmd`. macOS/Linux: jalankan `./coba.sh`.
3. Verifier memeriksa 10 bundle: 1 asli (`VALID`) dan 9 manipulasi yang harus tertolak
   (`TAMPERED`, `INCOMPLETE`, `UNTRUSTED_SIGNER`, `MALFORMED`).

Kit berisi biner untuk Windows, macOS, dan Linux, sehingga tidak perlu memasang apa pun.
Data di dalam bundle sepenuhnya sintetis.

Demo lengkap (agen, deteksi otomatis, vault, dan dashboard rantai kustodi) memakai Docker.
Panduannya ada di `docs/cara_mencoba.md`.

## Aset

| Berkas | Isi |
| --- | --- |
| `sigap-kit-juri-{{VERSI}}.zip` | Kit juri: biner semua platform, contoh bundle, trust store, skrip `coba` |
| `sigap-linux-amd64`, `-arm64`, `-armv7` | Biner untuk node dan laptop Linux |
| `sigap-darwin-amd64`, `-arm64` | Biner untuk macOS (Intel dan Apple Silicon) |
| `sigap-windows-amd64.exe`, `-arm64.exe` | Biner untuk Windows |
| `SHA256SUMS` | Checksum semua aset |

Biner dibangun otomatis oleh GitHub Actions dari kode sumber pada tag ini.
