from src.advisor import Advisor, template_advice
from src.executorch_adapter import ExecuTorchLlamaAdapter
from src.risk_engine import combine
from src.sms_detector import SmsDetector


def test_executorch_disabled() -> None:
    adapter = ExecuTorchLlamaAdapter(model_path="")
    assert adapter.is_available() is False
    meta = adapter.metadata()
    assert meta["available"] is False


def test_template_never_asks_for_secrets() -> None:
    result = SmsDetector().analyze("Please send the quarterly report tomorrow.")
    assessment = combine([result])
    advice = template_advice(assessment)
    text = advice.model_dump_json().lower()
    assert "otp" in text or "password" in text
    assert "send me your password" not in text
    assert Advisor().active_backend() == "local_template"
