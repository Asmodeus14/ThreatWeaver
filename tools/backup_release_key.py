"""Write a passphrase-encrypted backup of the ThreatWeaver release signing key.

The passphrase is read from the terminal (never from arguments or the environment), the backup is
decrypted again to check it matches the original key, and the public-key fingerprint is printed.

    python tools/backup_release_key.py D:\\ThreatWeaver-key-backup

Restore: decrypt the .enc.pem with the same passphrase back to
%USERPROFILE%\\.threatweaver\\release_keys\\threatweaver_release_ed25519.pem
(e.g. `python tools/backup_release_key.py --restore D:\\ThreatWeaver-key-backup`).
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

KEY_NAME = "threatweaver_release_ed25519.pem"
BACKUP_NAME = "threatweaver_release_ed25519.enc.pem"
SOURCE = Path.home() / ".threatweaver" / "release_keys" / KEY_NAME


def fingerprint(key) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def backup(dest_dir: Path) -> int:
    if not SOURCE.is_file():
        print(f"[-] No release key at {SOURCE}")
        return 1
    key = serialization.load_pem_private_key(SOURCE.read_bytes(), password=None)
    pw = getpass.getpass("Backup passphrase (12+ characters): ")
    if len(pw) < 12:
        print("[-] Passphrase too short; nothing written.")
        return 1
    if getpass.getpass("Repeat passphrase: ") != pw:
        print("[-] Passphrases differ; nothing written.")
        return 1
    blob = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.BestAvailableEncryption(pw.encode("utf-8")))
    dest_dir.mkdir(parents=True, exist_ok=True)
    out = dest_dir / BACKUP_NAME
    out.write_bytes(blob)
    check = serialization.load_pem_private_key(out.read_bytes(), password=pw.encode("utf-8"))
    if fingerprint(check) != fingerprint(key):
        print("[-] Verification failed; the backup does not match the key.")
        return 1
    pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    (dest_dir / "threatweaver_release_ed25519.pub.pem").write_bytes(pub)
    print(f"[+] Encrypted backup written and verified: {out}")
    print(f"    Key fingerprint {fingerprint(key)} (matches trusted_keys/release_<fingerprint>.pub)")
    print("    Keep the passphrase somewhere other than this drive.")
    return 0


def restore(src_dir: Path) -> int:
    src = src_dir / BACKUP_NAME
    if SOURCE.exists():
        print(f"[-] {SOURCE} already exists; move it away first.")
        return 1
    pw = getpass.getpass("Backup passphrase: ")
    key = serialization.load_pem_private_key(src.read_bytes(), password=pw.encode("utf-8"))
    SOURCE.parent.mkdir(parents=True, exist_ok=True)
    SOURCE.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
    print(f"[+] Restored key {fingerprint(key)} to {SOURCE}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("directory", type=Path)
    ap.add_argument("--restore", action="store_true", help="Restore the key from a backup directory")
    a = ap.parse_args()
    return restore(a.directory) if a.restore else backup(a.directory)


if __name__ == "__main__":
    sys.exit(main())
