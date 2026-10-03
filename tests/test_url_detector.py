import pytest

from src.exceptions import UnsafeInputError, ValidationFailed
from src.url_detector import UrlDetector


def test_benign_url() -> None:
    result = UrlDetector().analyze("https://example.com/docs/help")
    assert result.label == "benign"
    assert result.risk_score < 0.45


def test_suspicious_login_url() -> None:
    result = UrlDetector().analyze("http://secure-login-verify-account.xyz/wallet")
    assert result.label in {"suspicious", "phishing_suspected", "malicious"}
    assert result.risk_score >= 0.4


def test_malformed_scheme() -> None:
    with pytest.raises(ValidationFailed):
        UrlDetector().analyze("javascript:alert(1)")


def test_whitespace_url() -> None:
    with pytest.raises(ValidationFailed):
        UrlDetector().analyze("https://example.com/has space")


def test_ssrf_loopback_blocked() -> None:
    with pytest.raises(UnsafeInputError):
        UrlDetector().analyze("http://127.0.0.1/admin")


def test_ssrf_metadata_blocked() -> None:
    with pytest.raises(UnsafeInputError):
        UrlDetector().analyze("http://169.254.169.254/latest/meta-data")


def test_ssrf_private_blocked() -> None:
    with pytest.raises(UnsafeInputError):
        UrlDetector().analyze("http://10.0.0.5/internal")
