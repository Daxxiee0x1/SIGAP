# Model ancaman (ringkas)

**Penyerang yang ditangani:** dapat membaca dan mengubah bundle setelah dibuat (transit,
penyimpanan, pihak lain) dan **tidak** memegang kunci penandatanganan node.

| Ancaman | Penanganan | Uji |
| --- | --- | --- |
| Ubah byte artefak | SHA-256 di manifest bertanda tangan | `01_flip_byte` |
| Tambah / hapus berkas | Isi zip = daftar manifest | `02_add_unlisted`, `03_remove_listed` |
| Ubah manifest | Ed25519 atas byte manifest | `04_edit_manifest` |
| Tukar tanda tangan | Verifikasi gagal | `05_swap_signature` |
| Tanda tangan kunci penyerang | Kunci hanya dari trust store | `test_foreign_key_is_untrusted` |
| Zip slip, symlink, bom dekompresi | Validasi sebelum membaca entri | `07a`, `07b`, `08` |
| Replay / duplikat | Hash bundle unik, dicatat `duplicate_ignored` | API vault |
| XSS lewat `node_id`/`note` | `textContent` + CSP ketat | dashboard |
| Kebocoran kredensial | Redaksi sebelum hashing, jumlah dicatat | `test_config_is_redacted_before_hashing` |
| Admin menulis ulang log | Hash chain + head hash diekspor (deteksi) | `test_rewrite_is_detected` |

**Di luar model:** node yang sudah dikompromi (artefak bisa dipalsukan sebelum ditandatangani;
rootkit kernel tidak ditahan), pencurian kunci dari node, kebenaran waktu node, distribusi
kunci otomatis.
