from fastapi.testclient import TestClient

from src.api import app

client = TestClient(app)


def test_end_to_end_pipeline() -> None:
    message = client.post(
        "/api/v1/analyze/message",
        json={"message": "Final notice: transfer money to this wallet and send OTP"},
    )
    url = client.post(
        "/api/v1/analyze/url",
        json={"url": "http://update-billing-secure.xyz/password"},
    )
    flow = client.post(
        "/api/v1/analyze/network-flow",
        json={
            "protocol": "tcp",
            "dst_port": 443,
            "fwd_packets": 4,
            "bwd_packets": 4,
            "duration": 1,
        },
    )
    tel = client.post(
        "/api/v1/analyze/telemetry",
        json={"failed_authentication_count": 2},
    )
    assert {message.status_code, url.status_code, flow.status_code, tel.status_code} == {200}
    for body in (message.json(), url.json(), flow.json(), tel.json()):
        assert "risk_level" in body
        assert body["advice"]["disclaimer"]
        assert body["created_at"].endswith("+00:00") or "T" in body["created_at"]
    metrics = client.get("/api/v1/metrics")
    assert metrics.status_code == 200
    ready = client.get("/ready")
    assert ready.status_code == 200
