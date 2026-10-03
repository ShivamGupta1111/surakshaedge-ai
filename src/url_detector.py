"""Phishing URL detector. Never fetches the submitted URL."""

from __future__ import annotations

import csv
import re
from functools import lru_cache
from pathlib import Path
from typing import Any
from src.config import Settings, get_settings
from src.schemas import DetectorResult
from src.security import (
    SHORTENER_HOSTS,
    hostname_is_ip,
    load_json,
    load_trusted_joblib,
    parse_url_safely,
)

SUSPICIOUS_TERMS = (
    "login",
    "verify",
    "reward",
    "wallet",
    "secure",
    "account",
    "update",
    "billing",
    "password",
    "invoice",
)
UNUSUAL_TLDS = {".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".zip", ".mov", ".country"}


def url_features(raw: str, parsed: dict[str, Any], redirect_count: int | None) -> dict[str, float]:
    host = parsed["host"]
    labels = host.split(".")
    path = parsed["path"]
    blob = f"{host}{path}".lower()
    feats = {
        "url_length": float(parsed["raw_length"]),
        "host_length": float(len(host)),
        "subdomain_count": float(max(0, len(labels) - 2)),
        "is_ip": float(hostname_is_ip(host)),
        "at_symbol": float("@" in raw),
        "hyphen_count": float(host.count("-")),
        "punycode": float(host.startswith("xn--") or "xn--" in host),
        "non_ascii": float(any(ord(ch) > 127 for ch in raw)),
        "encoded_chars": float(raw.lower().count("%")),
        "redirects": float(redirect_count or 0),
        "suspicious_terms": float(sum(1 for t in SUSPICIOUS_TERMS if t in blob)),
        "shortener": float(host in SHORTENER_HOSTS),
        "unusual_tld": float(any(host.endswith(tld) for tld in UNUSUAL_TLDS)),
        "query_keys": float(parsed["query_key_count"]),
        "has_userinfo": float(parsed["has_userinfo"]),
    }
    return feats


URL_FEATURE_ORDER = [
    "url_length",
    "host_length",
    "subdomain_count",
    "is_ip",
    "at_symbol",
    "hyphen_count",
    "punycode",
    "non_ascii",
    "encoded_chars",
    "redirects",
    "suspicious_terms",
    "shortener",
    "unusual_tld",
    "query_keys",
    "has_userinfo",
]


def fallback_from_features(feats: dict[str, float]) -> tuple[str, float, list[str]]:
    evidence: list[str] = []
    score = 0.05
    mapping = [
        ("is_ip", 0.25, "ip_address_hostname"),
        ("at_symbol", 0.2, "userinfo_or_at_symbol"),
        ("punycode", 0.18, "punycode_hostname"),
        ("non_ascii", 0.12, "non_ascii_characters"),
        ("shortener", 0.16, "known_url_shortener"),
        ("unusual_tld", 0.12, "uncommon_tld"),
        ("has_userinfo", 0.15, "credentials_embedded_in_url"),
    ]
    for key, weight, ev in mapping:
        if feats.get(key, 0) >= 1:
            score += weight
            evidence.append(ev)
    if feats["url_length"] > 90:
        score += 0.08
        evidence.append("long_url")
    if feats["subdomain_count"] >= 3:
        score += 0.1
        evidence.append("many_subdomains")
    if feats["suspicious_terms"] >= 1:
        score += min(0.22, 0.07 * feats["suspicious_terms"])
        evidence.append("login_or_verify_terms")
    if feats["encoded_chars"] >= 3:
        score += 0.08
        evidence.append("heavy_percent_encoding")
    if feats["redirects"] >= 3:
        score += 0.1
        evidence.append("excessive_redirects_reported")
    if feats["hyphen_count"] >= 3:
        score += 0.06
        evidence.append("hyphenated_hostname")
    score = min(0.97, score)
    if score >= 0.7:
        label = "malicious"
    elif score >= 0.45:
        label = "phishing_suspected"
    elif score >= 0.25:
        label = "suspicious"
    else:
        label = "benign"
        if not evidence:
            evidence.append("no_high_risk_url_indicators")
    return label, round(score, 4), evidence


def local_threat_match(host: str, data_dir: Path) -> bool:
    table = data_dir / "url_threat_intel.csv"
    if not table.is_file():
        return False
    with table.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            listed = (row.get("host") or row.get("domain") or "").strip().lower()
            if listed and listed == host:
                return True
    return False


class UrlDetector:
    name = "url"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._model: Any | None = None
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        path = self.settings.model_dir / "url_model.joblib"
        meta_path = self.settings.model_dir / "model_metadata.json"
        checksum = None
        if meta_path.is_file():
            meta = load_json(meta_path).get("url", {})
            if meta.get("status") == "trained":
                checksum = meta.get("sha256")
        if path.is_file():
            try:
                self._model = load_trusted_joblib(
                    path, model_dir=self.settings.model_dir, expected_sha256=checksum
                )
            except Exception:
                self._model = None
        self._loaded = True

    def analyze(self, url: str, *, redirect_count: int | None = None) -> DetectorResult:
        parsed = parse_url_safely(
            url,
            max_length=self.settings.max_url_length,
            allow_private=self.settings.allow_private_url_analysis,
        )
        if not self._loaded:
            self.load()
        feats = url_features(url.strip(), parsed, redirect_count)
        label, score, evidence = fallback_from_features(feats)
        if local_threat_match(parsed["host"], self.settings.data_dir):
            score = min(0.97, score + 0.25)
            evidence.append("local_threat_intel_match")
            label = "malicious" if score >= 0.7 else label
        used_fallback = True
        version = "fallback-rules-1.0"
        probability = score
        if self._model is not None:
            try:
                row = [[feats[k] for k in URL_FEATURE_ORDER]]
                proba = float(self._model.predict_proba(row)[0].max())
                pred = str(self._model.predict(row)[0])
                label = pred
                model_risk = (1.0 - proba) if label == "benign" else max(proba, 0.5)
                score = round(min(0.99, 0.5 * score + 0.5 * model_risk), 4)
                probability = round(proba, 4)
                used_fallback = False
                version = "url-trained"
                evidence.append("local_classifier_used")
            except Exception:
                used_fallback = True
        action = (
            "Do not open this URL. Type a known official address instead of tapping the link."
            if score >= 0.45
            else "No fetch was performed. Open only if you typed this address yourself."
        )
        return DetectorResult(
            detector=self.name,
            label=label,
            probability=probability,
            risk_score=score,
            evidence=evidence,
            recommended_action=action,
            model_version=version,
            used_fallback=used_fallback,
        )


@lru_cache(maxsize=1)
def get_url_detector() -> UrlDetector:
    return UrlDetector()
