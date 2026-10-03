"""Input validation, redaction, hashing, SSRF guards, and trusted model loading."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import joblib

from src.exceptions import UnsafeInputError, ValidationFailed

SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|otp|pin|cvv|ssn|api[_-]?key|token|secret)\s*[:=]\s*\S+"),
    re.compile(r"\b\d{10,16}\b"),
    re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"),
]

PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+?\d[\d\-\s]{8,}\d)")
SHORTENER_HOSTS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
}
METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "metadata"}


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def redact_text(value: str, *, max_len: int = 240) -> str:
    redacted = SECRET_PATTERNS[0].sub("[REDACTED_SECRET]", value)
    redacted = PHONE_PATTERN.sub("[REDACTED_PHONE]", redacted)
    redacted = SECRET_PATTERNS[2].sub("[REDACTED_EMAIL]", redacted)
    if len(redacted) > max_len:
        return redacted[:max_len] + "…"
    return redacted


def content_hash(value: str) -> str:
    return sha256_text(value.strip())


def verify_api_key(provided: str | None, expected_sha256_hex: str) -> bool:
    if not provided or not expected_sha256_hex:
        return False
    digest = sha256_text(provided)
    return hmac.compare_digest(digest.lower(), expected_sha256_hex.strip().lower())


def safe_join(root: Path, *parts: str) -> Path:
    base = root.resolve()
    target = base.joinpath(*parts).resolve()
    if not str(target).startswith(str(base)):
        raise UnsafeInputError("Path traversal is not allowed")
    return target


def load_trusted_joblib(path: Path, *, model_dir: Path, expected_sha256: str | None = None) -> Any:
    """Load a local sklearn artifact. Never load files outside the model directory."""
    resolved = path.resolve()
    model_root = model_dir.resolve()
    if not str(resolved).startswith(str(model_root)):
        raise UnsafeInputError("Model path is outside the configured model directory")
    if not resolved.is_file():
        raise ValidationFailed(f"Model file not found: {resolved.name}")
    if expected_sha256:
        actual = sha256_file(resolved)
        if not hmac.compare_digest(actual.lower(), expected_sha256.lower()):
            raise UnsafeInputError("Model checksum mismatch; refusing to load untrusted artifact")
    return joblib.load(resolved)


def hostname_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def classify_host_risk(host: str) -> dict[str, Any]:
    """Return address-class flags. Does not connect to the host."""
    flags = {
        "is_ip": False,
        "is_private": False,
        "is_loopback": False,
        "is_link_local": False,
        "is_multicast": False,
        "is_reserved": False,
        "is_metadata": False,
    }
    lowered = host.lower().strip("[]")
    if lowered in METADATA_HOSTS or lowered.endswith(".internal"):
        flags["is_metadata"] = True
    try:
        ip = ipaddress.ip_address(lowered)
        flags["is_ip"] = True
        flags["is_private"] = ip.is_private
        flags["is_loopback"] = ip.is_loopback
        flags["is_link_local"] = ip.is_link_local
        flags["is_multicast"] = ip.is_multicast
        flags["is_reserved"] = ip.is_reserved
    except ValueError:
        if lowered in {"localhost"}:
            flags["is_loopback"] = True
            flags["is_private"] = True
    return flags


def is_blocked_ssrf_target(host: str, *, allow_private: bool = False) -> bool:
    flags = classify_host_risk(host)
    blocked = any(
        [
            flags["is_loopback"],
            flags["is_link_local"],
            flags["is_multicast"],
            flags["is_reserved"],
            flags["is_metadata"],
            flags["is_private"] and not allow_private,
        ]
    )
    return blocked


def parse_url_safely(raw: str, *, max_length: int, allow_private: bool = False) -> dict[str, Any]:
    if len(raw) > max_length:
        raise ValidationFailed("URL exceeds the configured maximum length")
    stripped = raw.strip()
    if not stripped:
        raise ValidationFailed("URL is empty")
    if any(ch.isspace() for ch in stripped):
        raise ValidationFailed("URL must not contain whitespace")
    parsed = urlparse(stripped)
    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        raise ValidationFailed("Only http and https URL schemes are accepted")
    if not parsed.netloc:
        raise ValidationFailed("URL is missing a hostname")
    host = parsed.hostname or ""
    if not host:
        raise ValidationFailed("URL hostname could not be parsed")
    flags = classify_host_risk(host)
    if is_blocked_ssrf_target(host, allow_private=allow_private):
        raise UnsafeInputError(
            "Refusing to analyze a private, loopback, link-local, multicast, or metadata URL",
            code="ssrf_blocked",
        )
    query_keys = list(parse_qs(parsed.query).keys())
    return {
        "scheme": scheme,
        "host": host.lower(),
        "port": parsed.port,
        "path": parsed.path or "/",
        "query_key_count": len(query_keys),
        "has_userinfo": bool(parsed.username or parsed.password),
        "flags": flags,
        "raw_length": len(stripped),
    }


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict):
        raise ValidationFailed("Expected a JSON object")
    return data
