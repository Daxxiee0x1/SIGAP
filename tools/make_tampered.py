"""Produce manipulated copies of a bundle for the integrity test plan (PRD section 10).

    python3 tools/make_tampered.py bundle.zip out_dir/

Each variant maps to the status the verifier must return.
"""

import base64
import json
import sys
import zipfile
from pathlib import Path


def read_entries(src: Path) -> list[tuple[zipfile.ZipInfo, bytes]]:
    with zipfile.ZipFile(src) as z:
        return [(info, z.read(info)) for info in z.infolist()]


def write_entries(dst: Path, entries: list[tuple[zipfile.ZipInfo | str, bytes]]) -> None:
    with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
        for info, data in entries:
            name = info if isinstance(info, str) else info.filename
            if isinstance(info, zipfile.ZipInfo) and info.external_attr:
                z.writestr(info, data)
            else:
                z.writestr(name, data)


def _edit(src: Path, dst: Path, member: str, fn) -> None:
    write_entries(dst, [(i.filename, fn(d) if i.filename == member else d) for i, d in read_entries(src)])


def flip_byte(src, dst):
    _edit(src, dst, "artifacts/process_list.txt", lambda d: bytes([d[0] ^ 1]) + d[1:])


def add_unlisted(src, dst):
    write_entries(dst, [(i.filename, d) for i, d in read_entries(src)] + [("artifacts/extra_payload.txt", b"x")])


def remove_listed(src, dst):
    write_entries(dst, [(i.filename, d) for i, d in read_entries(src) if i.filename != "artifacts/system_log.log"])


def edit_manifest(src, dst):
    _edit(src, dst, "manifest.json", lambda d: d.replace(b'"sequence": ', b'"sequence": 9', 1))


def swap_signature(src, dst):
    def forge(d: bytes) -> bytes:
        sig = json.loads(d)
        sig["signature"] = base64.b64encode(bytes(64)).decode()
        return json.dumps(sig).encode()

    _edit(src, dst, "manifest.sig", forge)


def zip_slip(src, dst):
    write_entries(dst, [(i.filename, d) for i, d in read_entries(src)] + [("../../etc/cron.d/backdoor", b"* * * * * root id\n")])


def symlink_entry(src, dst):
    link = zipfile.ZipInfo("artifacts/link_to_shadow.txt")
    link.external_attr = (0o120777 << 16)  # S_IFLNK
    write_entries(dst, [(i.filename, d) for i, d in read_entries(src)] + [(link, b"/etc/shadow")])


def decompression_bomb(src, dst):
    write_entries(dst, [(i.filename, d) for i, d in read_entries(src)] + [("artifacts/bomb.txt", bytes(110 * 1024 * 1024))])


VARIANTS = {
    "01_flip_byte": (flip_byte, "TAMPERED"),
    "02_add_unlisted": (add_unlisted, "TAMPERED"),
    "03_remove_listed": (remove_listed, "INCOMPLETE"),
    "04_edit_manifest": (edit_manifest, "TAMPERED"),
    "05_swap_signature": (swap_signature, "TAMPERED"),
    "07a_zip_slip": (zip_slip, "MALFORMED"),
    "07b_symlink": (symlink_entry, "MALFORMED"),
    "08_decompression_bomb": (decompression_bomb, "MALFORMED"),
}

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    for name, (fn, expected) in VARIANTS.items():
        fn(src, out / f"{name}.zip")
        print(f"{name:24s} -> harus {expected}")
