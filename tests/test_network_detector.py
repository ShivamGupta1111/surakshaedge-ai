from src.network_detector import NetworkDetector
from src.schemas import NetworkFlowRequest


def test_normal_flow() -> None:
    flow = NetworkFlowRequest(
        duration=1.0,
        protocol="tcp",
        src_port=54321,
        dst_port=443,
        fwd_packets=8,
        bwd_packets=10,
        bytes_transferred=2000,
        packet_rate=15,
        failed_count=0,
        repeated_dst=1,
        conn_freq=2,
    )
    result = NetworkDetector().analyze(flow)
    assert result.label == "normal"
    assert result.risk_score < 0.4


def test_suspicious_scan_flow() -> None:
    flow = NetworkFlowRequest(
        duration=0.1,
        protocol="tcp",
        src_port=1234,
        dst_port=4444,
        fwd_packets=40,
        bwd_packets=0,
        packet_rate=2500,
        failed_count=12,
        repeated_dst=25,
        conn_freq=60,
        syn_count=40,
    )
    result = NetworkDetector().analyze(flow)
    assert result.label in {"suspicious", "likely_intrusion"}
    assert result.risk_score >= 0.5
