from src.sms_detector import SmsDetector


def test_valid_legitimate_message() -> None:
    result = SmsDetector().analyze("See you at the library at 5pm.")
    assert result.label == "legitimate"
    assert result.risk_score < 0.4
    assert result.detector == "sms"


def test_scam_lottery_message() -> None:
    result = SmsDetector().analyze(
        "Congratulations you won a lottery prize. Claim now or lose it. Pay processing fee!!!"
    )
    assert result.label in {"scam", "spam", "phishing"}
    assert result.risk_score >= 0.4
    assert "reward_or_lottery_claim" in result.evidence


def test_phishing_otp_message() -> None:
    result = SmsDetector().analyze(
        "URGENT: your bank account will be suspended. Confirm password and OTP immediately."
    )
    assert result.label == "phishing"
    assert "credential_or_otp_request" in result.evidence


def test_empty_message_rejected() -> None:
    import pytest

    from src.exceptions import ValidationFailed

    with pytest.raises(ValidationFailed):
        SmsDetector().analyze("   ")
