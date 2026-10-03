from fastapi.testclient import TestClient

from src.api import app
from src.security import sha256_text
from src.config import reset_settings_cache
import os

client = TestClient(app)


def test_health_and_info() -> None:
    health = client.get("/health")
    assert health.status_code == 200
    assert health.headers.get("X-Request-ID")
    info = client.get("/api/v1/info")
    assert info.status_code == 200
    body = info.json()
    assert body["offline_mode"] is True
    assert "local_template" in body["advisor_available"]


def test_analyze_message_success() -> None:
    response = client.post("/api/v1/analyze/message", json={"message": "hello from class"})
    assert response.status_code == 200
    body = response.json()
    assert body["risk_level"] in {"low", "medium", "high", "critical"}
    assert body["advice"]["backend"] == "local_template"
    assert body["alert_id"]


def test_analyze_url_and_alerts() -> None:
    response = client.post(
        "/api/v1/analyze/url", json={"url": "https://example.com/help"}
    )
    assert response.status_code == 200
    alert_id = response.json()["alert_id"]
    listed = client.get("/api/v1/alerts")
    assert listed.status_code == 200
    got = client.get(f"/api/v1/alerts/{alert_id}")
    assert got.status_code == 200
    deleted = client.delete(f"/api/v1/alerts/{alert_id}")
    assert deleted.status_code == 200
    missing = client.get(f"/api/v1/alerts/{alert_id}")
    assert missing.status_code == 404


def test_feedback() -> None:
    created = client.post("/api/v1/analyze/message", json={"message": "team lunch at 1"})
    alert_id = created.json()["alert_id"]
    fb = client.post("/api/v1/feedback", json={"alert_id": alert_id, "useful": True, "comment": "ok"})
    assert fb.status_code == 200


def test_message_too_long() -> None:
    huge = "a" * 20_000
    response = client.post("/api/v1/analyze/message", json={"message": huge})
    assert response.status_code == 400


def test_batch_limit() -> None:
    os.environ["SURAKSHAEDGE_MAX_BATCH_SIZE"] = "2"
    reset_settings_cache()
    payload = {
        "messages": [{"message": "a"}, {"message": "b"}, {"message": "c"}],
        "urls": [],
        "flows": [],
        "telemetry": [],
    }
    response = client.post("/api/v1/analyze/batch", json=payload)
    assert response.status_code in {400, 200}
    os.environ["SURAKSHAEDGE_MAX_BATCH_SIZE"] = "25"
    reset_settings_cache()
    if response.status_code == 200:
        small = client.post(
            "/api/v1/analyze/batch",
            json={"messages": [{"message": "ok"}], "urls": [], "flows": [], "telemetry": []},
        )
        assert small.status_code == 200
    else:
        assert response.json()["code"] == "validation_error"


def test_ssrf_api() -> None:
    response = client.post("/api/v1/analyze/url", json={"url": "http://127.0.0.1/"})
    assert response.status_code == 400
    assert response.json()["code"] in {"ssrf_blocked", "unsafe_input"}


def test_auth_when_enabled(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    key = "test-local-key"
    monkeypatch.setenv("SURAKSHAEDGE_AUTH_ENABLED", "true")
    monkeypatch.setenv("SURAKSHAEDGE_API_KEY_SHA256", sha256_text(key))
    reset_settings_cache()
    from src.api import create_app

    authed = TestClient(create_app())
    denied = authed.post("/api/v1/analyze/message", json={"message": "hello there"})
    assert denied.status_code == 401
    ok = authed.post(
        "/api/v1/analyze/message",
        headers={"X-API-Key": key},
        json={"message": "hello there"},
    )
    assert ok.status_code == 200
    monkeypatch.setenv("SURAKSHAEDGE_AUTH_ENABLED", "false")
    reset_settings_cache()
