"""Release signing for ThreatWeaver checkpoints (Ed25519).

Generate a release key once (private key is written OUTSIDE the repository):
    python tools/sign_release_checkpoints.py --generate-key

Sign shipped checkpoints:
    python tools/sign_release_checkpoints.py artifacts/checkpoints/*.pt

The private key file must never be committed. Back it up somewhere safe; anyone holding
it can produce checkpoints that every ThreatWeaver install will trust.
"""

from __future__ import annotations

import argparse
import glob
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from threatweaver.models import signing

DEFAULT_PRIVATE_KEY = Path.home() / ".threatweaver" / "release_keys" / "threatweaver_release_ed25519.pem"


def generate(private_path: Path) -> int:
    if private_path.exists():
        print(f"[!] Refusing to overwrite existing release key: {private_path}")
        return 1
    key = Ed25519PrivateKey.generate()
    private_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    pub = key.public_key()
    key_id = signing.public_key_id(pub)
    signing.TRUSTED_KEYS_DIR.mkdir(parents=True, exist_ok=True)
    pub_file = signing.TRUSTED_KEYS_DIR / f"release_{key_id}.pub"
    pub_file.write_text(signing.public_key_to_text(pub) + "\n", encoding="utf-8")
    print(f"[+] Release private key: {private_path}  (keep secret, back it up, never commit)")
    print(f"[+] Release public key:  {pub_file}  (commit this)")
    return 0


def sign(private_path: Path, patterns: list[str]) -> int:
    key = signing.load_release_private_key(private_path)
    files = sorted({Path(f) for pat in patterns for f in glob.glob(pat)})
    if not files:
        print("[!] No files matched.")
        return 1
    for f in files:
        out = signing.sign_file(f, key=key, role="release")
        res = signing.verify_file(f)
        print(f"  {'[OK]' if res.valid else '[FAIL]'} {f} -> {out.name} ({res.reason})")
        if not res.valid:
            return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", help="Checkpoint files or glob patterns to sign")
    ap.add_argument("--key", type=Path, default=DEFAULT_PRIVATE_KEY, help="Release private key (PEM)")
    ap.add_argument("--generate-key", action="store_true", help="Create a new release keypair")
    args = ap.parse_args()
    if args.generate_key:
        return generate(args.key)
    if not args.files:
        ap.error("no files given")
    return sign(args.key, args.files)


if __name__ == "__main__":
    sys.exit(main())
