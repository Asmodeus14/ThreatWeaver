"""Request authentication and path policy for the local ThreatWeaver API.

Threat model: the API listens on loopback, but any web page the user visits can
send requests to it. Defences, in order:

1. Host header allow-list   -> blocks DNS-rebinding (attacker domain resolving to 127.0.0.1).
2. Per-session secret token  -> required on every /api request in a custom header. Cross-origin
                                pages cannot read the token (same-origin policy) and cannot send a
                                custom header without a CORS preflight, which this server never approves.
3. Origin check              -> state-changing requests from a foreign Origin are rejected outright.
4. JSON-only bodies + size cap -> no "simple request" form/text bodies, no memory exhaustion.
5. Path policy               -> client-supplied paths are normalised and device/UNC/ADS paths refused.
"""

from __future__ import annotations

import hmac
import re
import secrets
from pathlib import Path
from typing import Iterable, Optional, Set, Tuple

TOKEN_HEADER = "X-ThreatWeaver-Token"
MAX_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB
LOOPBACK_NAMES = ("127.0.0.1", "localhost", "[::1]")
QUARANTINE_ID_RE = re.compile(r"^[0-9a-fA-F-]{8,36}$")


def generate_token() -> str:
    return secrets.token_urlsafe(32)


def allowed_hosts(bind_host: str, port: int) -> Set[str]:
    """Host header values accepted for a server bound to bind_host:port."""
    names = set(LOOPBACK_NAMES)
    if bind_host and bind_host not in ("0.0.0.0", "::"):
        names.add(bind_host if ":" not in bind_host else f"[{bind_host}]")
    return {f"{n}:{port}" for n in names}


def check_host(host_header: Optional[str], allowed: Iterable[str]) -> bool:
    return bool(host_header) and host_header.strip().lower() in {h.lower() for h in allowed}


def check_origin(origin_header: Optional[str], allowed: Iterable[str]) -> bool:
    """Absent Origin (same-origin GETs, CLI clients) is allowed; a present Origin must be ours."""
    if not origin_header:
        return True
    origin = origin_header.strip().lower()
    return origin in {f"http://{h.lower()}" for h in allowed}


def check_token(supplied: Optional[str], expected: str) -> bool:
    return bool(supplied) and hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def check_json_content_type(content_type: Optional[str]) -> bool:
    return bool(content_type) and content_type.split(";")[0].strip().lower() == "application/json"


class PathPolicyError(ValueError):
    """Raised when a client-supplied path is not acceptable."""


def validate_user_path(raw: object, must_exist: bool = True, allow_unc: bool = False) -> Path:
    """Normalises a path supplied over the API and refuses dangerous forms.

    Refused: empty/non-string, NUL bytes, Win32 device namespaces (\\\\.\\, \\\\?\\),
    UNC shares (unless allow_unc), and NTFS alternate data streams (file.exe:stream).
    """
    if not isinstance(raw, str) or not raw.strip():
        raise PathPolicyError("A non-empty path string is required.")
    text = raw.strip().strip("'\"")
    if "\x00" in text:
        raise PathPolicyError("Path contains a NUL byte.")
    normalized = text.replace("/", "\\")
    if normalized.startswith("\\\\.\\") or normalized.startswith("\\\\?\\"):
        raise PathPolicyError("Device-namespace paths are not allowed.")
    if normalized.startswith("\\\\") and not allow_unc:
        raise PathPolicyError("Network (UNC) paths are not allowed.")
    # A colon is legal only as the drive separator at index 1 ("C:\...").
    if ":" in normalized[2:] or (":" in normalized[:2] and not re.match(r"^[A-Za-z]:", normalized)):
        raise PathPolicyError("Alternate data streams and colon-separated paths are not allowed.")

    path = Path(text).expanduser()
    try:
        path = path.resolve(strict=False)
    except (OSError, RuntimeError) as e:
        raise PathPolicyError(f"Path could not be resolved: {e}")
    if must_exist and not path.exists():
        raise PathPolicyError(f"Path not found on disk: '{path}'")
    return path


def validate_quarantine_id(qid: object) -> str:
    if not isinstance(qid, str) or not QUARANTINE_ID_RE.match(qid):
        raise PathPolicyError("Invalid quarantine id.")
    return qid


def guard_request(
    method: str,
    path: str,
    headers,
    token: str,
    hosts: Set[str],
) -> Optional[Tuple[int, str]]:
    """Returns (status, reason) if the request must be rejected, else None."""
    if not check_host(headers.get("Host"), hosts):
        return 403, "Host header not allowed."
    if not path.startswith("/api/"):
        return None  # the UI page itself; protected by the Host check above
    if method != "GET" and not check_origin(headers.get("Origin"), hosts):
        return 403, "Cross-origin request rejected."
    if not check_token(headers.get(TOKEN_HEADER), token):
        return 401, f"Missing or invalid {TOKEN_HEADER} header."
    if method in ("POST", "PUT", "PATCH", "DELETE"):
        try:
            length = int(headers.get("Content-Length") or 0)
        except ValueError:
            return 400, "Invalid Content-Length."
        if length > MAX_BODY_BYTES:
            return 413, "Request body too large."
        if length > 0 and not check_json_content_type(headers.get("Content-Type")):
            return 415, "Content-Type must be application/json."
    return None
