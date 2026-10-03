"""Network-flow anomaly detector using local models or transparent thresholds.

This module does not capture packets. An optional capture adapter can be
wired later (Scapy/libpcap) outside the API process.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from src.config import Settings, get_settings
from src.schemas import DetectorResult, NetworkFlowRequest
from src.security import load_json, load_trusted_joblib

RARE_PORTS = {4444, 5555, 6666, 12345, 31337, 4443}
HIGH_RISK_PROTO = {"icmp"}


NETWORK_FEATURE_ORDER = [
    "duration",
    "protocol",
    "src_port",
    "dst_port",
    "fwd_packets",
    "bwd_packets",
    "bytes_transferred",
    "packet_rate",
    "failed_count",
    "repeated_dst",
    "conn_freq",
    "syn_count",
    "rst_count",
]


def flow_vector(flow: NetworkFlowRequest) -> list[float]:
    proto = flow.protocol.lower().strip()
    proto_id = {"tcp": 6.0, "udp": 17.0, "icmp": 1.0}.get(proto, 0.0)
    return [
        float(flow.duration),
        proto_id,
        float(flow.src_port),
        float(flow.dst_port),
        float(flow.fwd_packets),
        float(flow.bwd_packets),
        float(flow.bytes_transferred),
        float(flow.packet_rate),
        float(flow.failed_count),
        float(flow.repeated_dst),
        float(flow.conn_freq),
        float(flow.syn_count or 0),
        float(flow.rst_count or 0),
    ]


def fallback_flow(flow: NetworkFlowRequest) -> tuple[str, float, list[str]]:
    evidence: list[str] = []
    score = 0.05
    if flow.failed_count >= 8:
        score += 0.22
        evidence.append("many_failed_connections")
    elif flow.failed_count >= 3:
        score += 0.1
        evidence.append("some_failed_connections")
    if flow.packet_rate > 2000:
        score += 0.2
        evidence.append("very_high_packet_rate")
    elif flow.packet_rate > 400:
        score += 0.08
        evidence.append("elevated_packet_rate")
    if flow.dst_port in RARE_PORTS or flow.src_port in RARE_PORTS:
        score += 0.18
        evidence.append("uncommon_service_port")
    if flow.repeated_dst >= 20:
        score += 0.16
        evidence.append("repeated_destination_scanning")
    if flow.conn_freq >= 50:
        score += 0.12
        evidence.append("high_connection_frequency")
    if flow.bytes_transferred > 50_000_000 and flow.duration < 2:
        score += 0.15
        evidence.append("large_burst_transfer")
    if flow.protocol.lower() in HIGH_RISK_PROTO and flow.packet_rate > 100:
        score += 0.08
        evidence.append("noisy_icmp_pattern")
    if (flow.syn_count or 0) >= 30 and (flow.bwd_packets == 0):
        score += 0.2
        evidence.append("syn_without_response")
    score = min(0.96, score)
    if score >= 0.72:
        label = "likely_intrusion"
    elif score >= 0.4:
        label = "suspicious"
    else:
        label = "normal"
        if not evidence:
            evidence.append("flow_within_benign_thresholds")
    return label, round(score, 4), evidence


class NetworkDetector:
    name = "network"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._model: Any | None = None
        self._loaded = False

    def load(self) -> None:
        if self._loaded:
            return
        path = self.settings.model_dir / "network_model.joblib"
        checksum = None
        meta_file = self.settings.model_dir / "model_metadata.json"
        if meta_file.is_file():
            meta = load_json(meta_file).get("network", {})
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

    def analyze(self, flow: NetworkFlowRequest) -> DetectorResult:
        if not self._loaded:
            self.load()
        label, score, evidence = fallback_flow(flow)
        used_fallback = True
        version = "fallback-rules-1.0"
        probability = score
        if self._model is not None:
            try:
                row = [flow_vector(flow)]
                pred = str(self._model.predict(row)[0])
                if hasattr(self._model, "predict_proba"):
                    probability = round(float(self._model.predict_proba(row)[0].max()), 4)
                else:
                    probability = score
                label = pred
                model_risk = (1.0 - probability) if label == "normal" else max(probability, 0.5)
                score = round(min(0.99, 0.5 * score + 0.5 * model_risk), 4)
                used_fallback = False
                version = "network-trained"
                evidence.append("local_classifier_used")
            except Exception:
                used_fallback = True
        if label == "normal":
            action = "No enforcement. Continue monitoring if this host is sensitive."
        elif label == "suspicious":
            action = "Review the destination and rate. Do not auto-block from this advisory."
        else:
            action = "Investigate the host and isolate only if your own policy says to. This API will not block traffic."
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


class PacketCaptureAdapter:
    """Boundary for optional Scapy/libpcap capture. Disabled inside the API."""

    def is_enabled(self) -> bool:
        return False

    def start(self) -> None:
        raise RuntimeError("Packet capture is not enabled in the API process")


@lru_cache(maxsize=1)
def get_network_detector() -> NetworkDetector:
    return NetworkDetector()
