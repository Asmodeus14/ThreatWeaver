"""Ed25519 checkpoint signing and fail-closed verification.

Replaces the v0.1 HMAC scheme, whose key was embedded in the source code (anyone
could re-sign a tampered checkpoint).

Trust model
-----------
* Release key   — signs checkpoints shipped in artifacts/checkpoints/. The private key
                  lives outside the repository; only the public key ships, in
                  ``threatweaver/models/trusted_keys/*.pub``.
* Local key     — generated per install, signs models adapted on this machine. The
                  private key is stored DPAPI-protected (Windows) under the key directory.
                  Its public key is trusted only on this machine.

A checkpoint loads only if ``<file>.ed25519`` holds a valid signature, by a trusted
key, over the file's exact bytes. Anything else is refused unless the caller passes
``allow_unsigned=True`` or sets ``THREATWEAVER_ALLOW_UNSIGNED_MODELS=1`` (research only).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIG_SUFFIX = ".ed25519"
TRUSTED_KEYS_DIR = Path(__file__).resolve().parent / "trusted_keys"
LOCAL_KEY_FILE = "local_signing_key.bin"
ALLOW_UNSIGNED_ENV = "THREATWEAVER_ALLOW_UNSIGNED_MODELS"


# ---------------------------------------------------------------------------
# Key storage
# ---------------------------------------------------------------------------

def key_dir() -> Path:
    override = os.environ.get("THREATWEAVER_KEY_DIR")
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA")
    return (Path(base) / "ThreatWeaver" / "keys") if base else (Path.home() / ".threatweaver" / "keys")


def _dpapi(data: bytes, protect: bool) -> bytes:
    """Windows DPAPI (CurrentUser scope). Raises OSError on failure."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    ok = fn(ctypes.byref(blob_in), None, None, None, None, 0x01, ctypes.byref(blob_out))  # UI_FORBIDDEN
    if not ok:
        raise OSError(f"DPAPI {'protect' if protect else 'unprotect'} failed (error {ctypes.GetLastError()})")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def _store_private(raw: bytes, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if sys.platform == "win32":
        payload = b"DPAPI1" + _dpapi(raw, protect=True)
    else:
        payload = b"RAW1" + raw
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(payload)
    if sys.platform != "win32":
        os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _load_private(path: Path) -> bytes:
    payload = path.read_bytes()
    if payload.startswith(b"DPAPI1"):
        return _dpapi(payload[6:], protect=False)
    if payload.startswith(b"RAW1"):
        return payload[4:]
    raise ValueError(f"Unrecognized key file format: {path}")


def public_key_id(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def public_key_to_text(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def public_key_from_text(text: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(text.strip()))


def get_local_signing_key(create: bool = True) -> Optional[Ed25519PrivateKey]:
    path = key_dir() / LOCAL_KEY_FILE
    if path.is_file():
        return Ed25519PrivateKey.from_private_bytes(_load_private(path))
    if not create:
        return None
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    _store_private(raw, path)
    return key


def load_release_private_key(pem_path: str | Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(Path(pem_path).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Release key must be an Ed25519 private key.")
    return key


def trusted_public_keys() -> Dict[str, Tuple[str, Ed25519PublicKey]]:
    """key_id -> (role, public key). Release keys from the package, plus this install's local key."""
    keys: Dict[str, Tuple[str, Ed25519PublicKey]] = {}
    if TRUSTED_KEYS_DIR.is_dir():
        for f in sorted(TRUSTED_KEYS_DIR.glob("*.pub")):
            try:
                pub = public_key_from_text(f.read_text(encoding="utf-8"))
                keys[public_key_id(pub)] = ("release", pub)
            except Exception:
                continue
    local = get_local_signing_key(create=False)
    if local is not None:
        pub = local.public_key()
        keys.setdefault(public_key_id(pub), ("local", pub))
    return keys


# ---------------------------------------------------------------------------
# Sign / verify
# ---------------------------------------------------------------------------

def signature_path(file_path: str | Path) -> Path:
    p = Path(file_path)
    return p.with_name(p.name + SIG_SUFFIX)


def sign_file(file_path: str | Path, key: Optional[Ed25519PrivateKey] = None, role: str = "local") -> Path:
    """Signs the exact bytes of file_path; writes <file>.ed25519 and returns its path."""
    path = Path(file_path)
    key = key or get_local_signing_key(create=True)
    data = path.read_bytes()
    sig = key.sign(data)
    record = {
        "alg": "ed25519",
        "role": role,
        "key_id": public_key_id(key.public_key()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "signature": base64.b64encode(sig).decode("ascii"),
        "signed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out = signature_path(path)
    out.write_text(json.dumps(record, indent=2), encoding="utf-8")
    return out


@dataclass
class VerificationResult:
    valid: bool
    status: str            # "valid", "unsigned", "invalid", "untrusted_key", "malformed"
    role: Optional[str]    # "release" or "local" when valid
    reason: str


def verify_file(file_path: str | Path) -> VerificationResult:
    path = Path(file_path)
    sig_p = signature_path(path)
    if not sig_p.is_file():
        return VerificationResult(False, "unsigned", None, f"No {SIG_SUFFIX} signature file next to {path.name}")
    try:
        record = json.loads(sig_p.read_text(encoding="utf-8"))
        sig = base64.b64decode(record["signature"])
        key_id = record["key_id"]
    except Exception as e:
        return VerificationResult(False, "malformed", None, f"Malformed signature file: {e}")
    keys = trusted_public_keys()
    if key_id not in keys:
        return VerificationResult(False, "untrusted_key", None, f"Signed by unknown key {key_id}")
    role, pub = keys[key_id]
    try:
        pub.verify(sig, path.read_bytes())
    except InvalidSignature:
        return VerificationResult(False, "invalid", None, "Signature does not match file contents (tampered or corrupted)")
    return VerificationResult(True, "valid", role, f"Valid {role} signature (key {key_id})")


def unsigned_allowed(explicit: bool = False) -> bool:
    return explicit or os.environ.get(ALLOW_UNSIGNED_ENV) == "1"
