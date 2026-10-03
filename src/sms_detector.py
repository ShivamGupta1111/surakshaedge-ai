"""SMS / chat scam detector with a trained model and deterministic fallback."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from src.config import Settings, get_settings
from src.exceptions import ValidationFailed
from src.schemas import DetectorResult
from src.security import load_json, load_trusted_joblib, redact_text

URGENT = ("urgent", "immediately", "act now", "final notice", "suspend", "blocked", "expire")
FINANCIAL = ("bank", "refund", "transfer", "payment", "invoice", "wire", "upi", "wallet", "kyc")
CREDENTIALS = ("password", "otp", "pin", "cvv", "otp is", "verify account", "login details")
REWARD = ("lottery", "winner", "prize", "gift card", "congratulations", "claim now", "free reward")
IMPERSONATION = ("it department", "microsoft", "google", "amazon", "income tax", "customs", "ceo")
SHORT_LINK = ("bit.ly", "tinyurl", "t.co", "goo.gl", "cutt.ly")

OBFUSCATION_RE = re.compile(r"[^\w\s]{3,}|[A-Za-z]\s{1}[A-Za-z]\s{1}[A-Za-z]")
URL_RE = re.compile(r"https?://\S+|www\.\S+", re.I)
PHONE_RE = re.compile(r"(?:\+?\d[\d\-\s]{8,}\d)")


@dataclass
class SmsFeatures:
    urgent: int
    financial: int
    credentials: int
    reward: int
    impersonation: int
    short_link: int
    url_count: int
    phone_count: int
    exclamations: int
    obfuscation: int
    length: int


def normalize_message(text: str) -> str:
    collapsed = re.sub(r"\s+", " ", text.strip())
    return collapsed


def extract_features(text: str) -> SmsFeatures:
    lowered = text.lower()
    return SmsFeatures(
        urgent=sum(1 for t in URGENT if t in lowered),
        financial=sum(1 for t in FINANCIAL if t in lowered),
        credentials=sum(1 for t in CREDENTIALS if t in lowered),
        reward=sum(1 for t in REWARD if t in lowered),
        impersonation=sum(1 for t in IMPERSONATION if t in lowered),
        short_link=sum(1 for t in SHORT_LINK if t in lowered),
        url_count=len(URL_RE.findall(text)),
        phone_count=len(PHONE_RE.findall(text)),
        exclamations=text.count("!") + text.count("₹") + text.count("$"),
        obfuscation=1 if OBFUSCATION_RE.search(text) else 0,
        length=len(text),
    )


def fallback_score(features: SmsFeatures) -> tuple[str, float, list[str]]:
    evidence: list[str] = []
    score = 0.08
    if features.urgent:
        score += min(0.18, 0.09 * features.urgent)
        evidence.append("urgent_language")
    if features.financial:
        score += min(0.2, 0.08 * features.financial)
        evidence.append("financial_request")
    if features.credentials:
        score += min(0.28, 0.14 * features.credentials)
        evidence.append("credential_or_otp_request")
    if features.reward:
        score += min(0.22, 0.1 * features.reward)
        evidence.append("reward_or_lottery_claim")
    if features.impersonation:
        score += min(0.2, 0.1 * features.impersonation)
        evidence.append("possible_impersonation")
    if features.short_link or features.url_count:
        score += 0.12 if features.short_link else 0.06
        evidence.append("embedded_or_shortened_link")
    if features.phone_count:
        score += 0.05
        evidence.append("phone_number_pattern")
    if features.exclamations >= 3:
        score += 0.05
        evidence.append("excessive_punctuation")
    if features.obfuscation:
        score += 0.06
        evidence.append("obfuscated_text")
    score = min(0.97, score)
    if features.credentials and (features.financial or features.urgent):
        label = "phishing"
    elif features.reward or (features.financial and features.urgent):
        label = "scam"
    elif score >= 0.45:
        label = "spam"
    else:
        label = "legitimate"
        score = min(score, 0.28)
        if not evidence:
            evidence.append("no_high_risk_indicators")
    return label, round(score, 4), evidence


def _action_for(label: str) -> str:
    if label == "legitimate":
        return "No blocking action. Keep the message if it is expected."
    if label == "phishing":
        return "Do not open links or share passwords, OTPs, or PINs. Delete after confirming it is unsolicited."
    if label == "scam":
        return "Do not send money or personal details. Verify using an official channel you already trust."
    return "Treat as unsolicited. Avoid links and reply-to numbers you do not know."


class SmsDetector:
    """Combines a local classifier with transparent lexical rules."""

    name = "sms"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._model: Any | None = None
        self._loaded = False

    def _model_path(self) -> Path:
        return self.settings.model_dir / "sms_model.joblib"

    def _metadata(self) -> dict[str, Any]:
        meta_path = self.settings.model_dir / "model_metadata.json"
        if not meta_path.is_file():
            return {}
        try:
            return load_json(meta_path)
        except Exception:
            return {}

    def load(self) -> None:
        if self._loaded:
            return
        path = self._model_path()
        meta = self._metadata().get("sms", {})
        checksum = meta.get("sha256") if meta.get("status") == "trained" else None
        if path.is_file():
            try:
                self._model = load_trusted_joblib(
                    path, model_dir=self.settings.model_dir, expected_sha256=checksum
                )
            except Exception:
                self._model = None
        self._loaded = True

    def analyze(self, message: str) -> DetectorResult:
        if not message or not message.strip():
            raise ValidationFailed("Message must not be empty")
        if len(message) > self.settings.max_message_length:
            raise ValidationFailed("Message exceeds the configured maximum length")
        if not self._loaded:
            if self.settings.lazy_load_models:
                self.load()
            else:
                self.load()
        text = normalize_message(message)
        features = extract_features(text)
        label, score, evidence = fallback_score(features)
        used_fallback = True
        version = "fallback-rules-1.0"
        probability = score
        if self._model is not None:
            try:
                proba = float(self._model.predict_proba([text])[0].max())
                pred = str(self._model.predict([text])[0])
                if pred in {"spam", "scam", "phishing", "legitimate"}:
                    label = pred
                model_risk = (1.0 - proba) if label == "legitimate" else max(proba, 0.5)
                score = round(min(0.99, 0.5 * score + 0.5 * model_risk), 4)
                probability = round(proba, 4)
                used_fallback = False
                version = str(self._metadata().get("sms", {}).get("model_version", "sms-trained"))
                evidence.append("local_classifier_used")
            except Exception:
                used_fallback = True
        return DetectorResult(
            detector=self.name,
            label=label,
            probability=probability,
            risk_score=score,
            evidence=[redact_text(item, max_len=80) for item in evidence],
            recommended_action=_action_for(label),
            model_version=version,
            used_fallback=used_fallback,
        )


@lru_cache(maxsize=1)
def get_sms_detector() -> SmsDetector:
    return SmsDetector()
