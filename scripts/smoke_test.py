"""End-to-end smoke test against the in-process API."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi.testclient import TestClient

from src.api import app


def main() -> int:
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200, health.text
    assert health.json()["status"] == "ok"

    msg = client.post(
        "/api/v1/analyze/message",
        json={"message": "URGENT: bank account suspended. Send OTP and password now http://bit.ly/x"},
    )
    assert msg.status_code == 200, msg.text
    body = msg.json()
    assert body["advice"]["backend"] in {"local_template", "executorch_llama"}
    assert body["alert_id"]
    assert body["detectors"][0]["label"] != "legitimate"

    url = client.post(
        "/api/v1/analyze/url",
        json={"url": "http://secure-login-verify-account.xyz/wallet"},
    )
    assert url.status_code == 200, url.text
    assert url.json()["risk_score"] >= 0.25

    flow = client.post(
        "/api/v1/analyze/network-flow",
        json={
            "duration": 0.2,
            "protocol": "tcp",
            "src_port": 1234,
            "dst_port": 4444,
            "fwd_packets": 50,
            "bwd_packets": 0,
            "packet_rate": 3000,
            "failed_count": 12,
            "repeated_dst": 30,
            "conn_freq": 80,
            "syn_count": 40,
        },
    )
    assert flow.status_code == 200, flow.text
    assert flow.json()["detectors"][0]["label"] in {"suspicious", "likely_intrusion"}

    alerts = client.get("/api/v1/alerts")
    assert alerts.status_code == 200
    assert len(alerts.json()["alerts"]) >= 3
    print("smoke_test: ok")
    print("advisor_backend:", body["advice"]["backend"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
