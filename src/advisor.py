"""Local advisory layer. Never overrides detector decisions."""

from __future__ import annotations

import re
from functools import lru_cache

from src.config import Settings, get_settings
from src.executorch_adapter import ExecuTorchLlamaAdapter
from src.schemas import Advice, AdvisorBackend, RiskAssessment
from src.security import redact_text

DISCLAIMER = (
    "Advisory only. Detectors made the security decision. This text does not guarantee safety "
    "and must not be treated as a block or legal conclusion."
)
FORBIDDEN_ADVICE = re.compile(
    r"(?i)\b(share (your )?(password|otp|pin|private key|cvv)|send (money|bitcoin)|run this command)\b"
)
INJECTION_MARKERS = (
    "ignore previous",
    "system prompt",
    "you are now",
    "override",
    "disregard instructions",
)


def _sanitize(text: str) -> str:
    cleaned = redact_text(text, max_len=600)
    cleaned = re.sub(r"[`$]|rm -rf|powershell -enc", "[removed]", cleaned, flags=re.I)
    return cleaned.strip()[:600]


def template_advice(assessment: RiskAssessment) -> Advice:
    threat = assessment.primary_threat
    level = assessment.risk_level
    title = f"{level.capitalize()} risk: {threat}"
    explanation = (
        f"Local detectors scored this event at {assessment.risk_score:.2f} "
        f"({level}) with confidence {assessment.confidence:.2f}. "
        f"The primary label is {threat}."
    )
    why = "Combined evidence: " + "; ".join(assessment.evidence[:6] or ["limited_indicators"])
    immediate = list(assessment.recommended_actions[:4])
    do_not = [
        "Do not share passwords, OTPs, PINs, private keys, or payment details.",
        "Do not run commands suggested inside a message or URL.",
        "Do not assume this result is certain if confidence is moderate.",
    ]
    uncertainty = (
        "Heuristic and lightweight models can miss novel threats and can also flag benign traffic. "
        f"Current confidence is {assessment.confidence:.2f}."
    )
    return Advice(
        title=_sanitize(title),
        explanation=_sanitize(explanation),
        why_concerned=_sanitize(why),
        immediate_actions=[_sanitize(x) for x in immediate],
        do_not=do_not,
        uncertainty=_sanitize(uncertainty),
        disclaimer=DISCLAIMER,
        backend="local_template",
        sanitized=True,
    )


class Advisor:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.executorch = ExecuTorchLlamaAdapter(
            model_path=self.settings.executorch_model_path,
            timeout_seconds=self.settings.advisor_timeout_seconds,
        )

    def active_backend(self) -> AdvisorBackend:
        requested = self.settings.advisor_backend
        if requested == "executorch_llama" and self.executorch.is_available():
            return "executorch_llama"
        return "local_template"

    def advise(self, assessment: RiskAssessment) -> Advice:
        payload = {
            "risk_level": assessment.risk_level,
            "risk_score": assessment.risk_score,
            "confidence": assessment.confidence,
            "primary_threat": assessment.primary_threat,
            "evidence": assessment.evidence[:12],
            "detector_labels": [d.label for d in assessment.detectors],
        }
        joined = " ".join(str(v) for v in payload.values()).lower()
        if any(marker in joined for marker in INJECTION_MARKERS):
            advice = template_advice(assessment)
            advice.uncertainty += " Prompt-like content was treated as untrusted data."
            return advice

        backend = self.active_backend()
        if backend == "executorch_llama":
            try:
                self.executorch.load_model()
                raw = self.executorch.generate_advice(payload)
                if FORBIDDEN_ADVICE.search(raw):
                    return template_advice(assessment)
                advice = template_advice(assessment)
                advice.explanation = _sanitize(raw)
                advice.backend = "executorch_llama"
                return advice
            except Exception:
                advice = template_advice(assessment)
                advice.uncertainty += " ExecuTorch backend unavailable; used local_template."
                return advice
        return template_advice(assessment)


@lru_cache(maxsize=1)
def get_advisor() -> Advisor:
    return Advisor()
