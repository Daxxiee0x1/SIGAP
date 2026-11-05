# Arsitektur SIGAP

```
NODE (edge, Go)                                       PUSAT (saat ada koneksi)
detector ──alert──► collector (/proc)                 ┌─► vault (Python FastAPI + SQLite)
   ▲                   │ redaksi + SHA-256            │     ├─ sigap verify --json  (Go, biner sama)
   │ trigger file      ▼                              │     ├─ custody_log (append-only, hash chain)
   └───────────── manifest.json ─Ed25519─► manifest.sig     └─ dashboard statis (textContent, CSP)
                       │                              │
                       ▼                              │
                  bundle.zip ──► outbox ──uplink (retry)──┘
                       │
                       └─► sigap verify (offline, trust_store.json)
```

## Kontrak Go ↔ Python

Vault tidak pernah membuka zip. Ia menyimpan bundle dengan nama `<sha256>.zip`, lalu
menjalankan:

```
sigap verify --json --trust /data/trust/trust_store.json /data/vault/bundles/<sha>.zip
```

Keluaran (stdout) dan kode keluar:

```json
{
  "status": "VALID",
  "reasons": ["tanda tangan sah (node-sensor-01-2026-a); 6 artefak cocok"],
  "bundle_sha256": "9f2c...",
  "key_id": "node-sensor-01-2026-a",
  "manifest": { "bundle_id": "bnd-sensor-01-20261115-012", "...": "..." }
}
```

`manifest` hanya muncul setelah tanda tangan lolos, sehingga dashboard tidak pernah
menampilkan isi manifest yang belum diautentikasi.

## Urutan pemeriksaan verifier

1. Batas struktur: ukuran ≤ 20 MB, ≤ 50 berkas, nama cocok allowlist, tanpa symlink, total terdekompresi ≤ 100 MB.
2. `manifest.sig` → cari `key_id` di trust store lokal (bukan dari bundle) → `UNTRUSTED_SIGNER` bila tidak ada/dicabut/kedaluwarsa.
3. Verifikasi Ed25519 atas **byte** `manifest.json` sebelum di-parse.
4. Parse ketat (`DisallowUnknownFields`), cocokkan `signer_key_id`.
5. Setiap artefak: SHA-256 dan ukuran; berkas tak terdaftar → `TAMPERED`; berkas hilang → `INCOMPLETE`.
