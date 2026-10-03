import logging
from pathlib import Path

import pytest

from src.exceptions import UnsafeInputError
from src.logging_config import configure_logging, get_logger
from src.security import load_trusted_joblib, redact_text, safe_join
from src.sms_detector import SmsDetector
from src.storage import Storage


def test_redact_phone_and_secret() -> None:
    text = "password=hunter2 call +1-202-555-0100"
    out = redact_text(text)
    assert "hunter2" not in out
    assert "202-555-0100" not in out


def test_path_traversal_blocked(tmp_path: Path) -> None:
    with pytest.raises(UnsafeInputError):
        safe_join(tmp_path, "..", "etc", "passwd")


def test_untrusted_model_path(tmp_path: Path) -> None:
    outside = tmp_path / "outside.joblib"
    outside.write_bytes(b"not-a-model")
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    with pytest.raises(UnsafeInputError):
        load_trusted_joblib(outside, model_dir=model_dir)


def test_logs_do_not_contain_raw_message(caplog: pytest.LogCaptureFixture) -> None:
    configure_logging("INFO")
    secret = "UNIQUE_RAW_SMS_CONTENT_XYZOTP999"
    with caplog.at_level(logging.INFO, logger="surakshaedge"):
        logger = get_logger("test")
        logger.info("analyzed message_len=%s hash_prefix=%s", len(secret), "abc")
        SmsDetector().analyze(f"hello {secret}")
    combined = " ".join(r.message for r in caplog.records)
    assert secret not in combined


def test_storage_does_not_keep_raw_sms(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    from src.config import Settings
    from src.risk_engine import combine

    db = tmp_path / "db.sqlite3"
    settings = Settings(database_path=db)
    store = Storage(settings)
    raw = "UNIQUE_DB_SECRET_OTP_VALUE"
    result = SmsDetector().analyze(f"Urgent bank password {raw}")
    assessment = combine([result], settings)
    store.save_assessment(assessment, detector_type="sms", content_hash="abc")
    assert store.contains_raw(raw) is False
    blob = db.read_text(encoding="utf-8", errors="ignore")
    assert raw not in blob
