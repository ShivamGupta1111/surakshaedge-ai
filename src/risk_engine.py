"""Deterministic fusion of detector scores.

Default weights (documented):
- SMS: 0.30
- URL: 0.30
- network: 0.25
- malware: 0.15

A single weak signal cannot produce `critical`. Confidence is tracked separately
from severity.
"""

from __future__ import annotations

from datetime import datetime, timezone

from src.config import Settings, get_settings
from src.schemas import DetectorResult, RiskAssessment


WEIGHTS = {
    "sms": "risk_weight_sms",
    "url": "risk_weight_url",
    "network": "risk_weight_network",
    "malware": "risk_weight_malware",
}


def _level(score: float, settings: Settings) -> str:
    if score <= settings.risk_low_max:
        return "low"
    if score <= settings.risk_medium_max:
        return "medium"
    if score <= settings.risk_high_max:
        return "high"
    return "critical"


def combine(results: list[DetectorResult], settings: Settings | None = None) -> RiskAssessment:
    settings = settings or get_settings()
    if not results:
        now = datetime.now(timezone.utc)
        return RiskAssessment(
            risk_level="low",
            risk_score=0.0,
            confidence=0.0,
            primary_threat="none",
            detectors=[],
            evidence=["no_detectors_ran"],
            recommended_actions=["Provide at least one supported input."],
            score_explanation="No detector results were supplied.",
            created_at=now,
        )

    weight_map = {name: float(getattr(settings, attr)) for name, attr in WEIGHTS.items()}
    used = [r for r in results if r.detector in weight_map]
    total_w = sum(weight_map[r.detector] for r in used) or 1.0
    fused = sum(weight_map[r.detector] * r.risk_score for r in used) / total_w
    strongest = max(used, key=lambda r: r.risk_score)
    evidence_count = sum(len(r.evidence) for r in used)
    max_individual = strongest.risk_score

    capped_reason = ""
    if max_individual < 0.5:
        fused = min(fused, settings.weak_signal_cap)
        capped_reason = " Weak-signal cap applied because no detector exceeded 0.50."
    if len(used) == 1 and evidence_count < 2:
        fused = min(fused, settings.single_weak_evidence_cap)
        capped_reason += " Single-detector weak-evidence cap applied."

    fused = round(min(0.99, fused), 4)
    level = _level(fused, settings)
    if level == "critical" and (len(used) == 1 and max_individual < 0.92):
        fused = min(fused, settings.risk_high_max)
        level = "high"
        capped_reason += " Critical requires a very strong single score or multiple detectors."

    fallback_ratio = sum(1 for r in used if r.used_fallback) / len(used)
    confidence = round(max(0.15, min(0.95, 0.9 - 0.25 * fallback_ratio + 0.05 * min(4, evidence_count))), 4)

    evidence: list[str] = []
    for result in used:
        evidence.extend(f"{result.detector}:{item}" for item in result.evidence[:4])

    actions: list[str] = []
    for result in used:
        if result.risk_score >= 0.4 and result.recommended_action not in actions:
            actions.append(result.recommended_action)
    if not actions:
        actions.append("No immediate enforcement. Continue using official channels.")
    actions.append("This system does not block traffic, delete files, or send messages automatically.")

    explanation = (
        f"Weighted fusion used detectors {[r.detector for r in used]} "
        f"with weights {[round(weight_map[r.detector] / total_w, 3) for r in used]}. "
        f"Fused score={fused}, strongest={strongest.detector}:{max_individual}."
        f"{capped_reason}"
    )
    now = datetime.now(timezone.utc)
    return RiskAssessment(
        risk_level=level,  # type: ignore[arg-type]
        risk_score=fused,
        confidence=confidence,
        primary_threat=f"{strongest.detector}:{strongest.label}",
        detectors=results,
        evidence=evidence[:24],
        recommended_actions=actions[:8],
        score_explanation=explanation,
        created_at=now,
    )
