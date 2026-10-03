"""Liveness and readiness helpers."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from src.advisor import get_advisor
from src.config import get_settings
from src.executorch_adapter import ExecuTorchLlamaAdapter
from src.schemas import HealthResponse, InfoResponse
from src import __version__


def health() -> HealthResponse:
    settings = get_settings()
    advisor = get_advisor()
    return HealthResponse(
        status="ok",
        offline_mode=settings.offline_mode,
        advisor_backend=advisor.active_backend(),
        time_utc=datetime.now(timezone.utc).isoformat(),
    )


def ready() -> dict[str, object]:
    settings = get_settings()
    db_ok = True
    try:
        settings.database_path.parent.mkdir(parents=True, exist_ok=True)
        settings.model_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        db_ok = False
    return {"ready": db_ok, "database_parent_writable": db_ok}


def info(loaded_models: dict[str, str]) -> InfoResponse:
    settings = get_settings()
    adapter = ExecuTorchLlamaAdapter(settings.executorch_model_path)
    return InfoResponse(
        name="SurakshaEdge AI",
        version=__version__,
        offline_mode=settings.offline_mode,
        memory_safe_mode=settings.memory_safe_mode,
        advisor_backend=get_advisor().active_backend(),
        advisor_available={
            "local_template": True,
            "executorch_llama": adapter.is_available(),
        },
        loaded_models=loaded_models,
        host=settings.host,
        env=settings.env,
    )


def model_status() -> dict[str, str]:
    settings = get_settings()
    names = {
        "sms": "sms_model.joblib",
        "url": "url_model.joblib",
        "network": "network_model.joblib",
    }
    out: dict[str, str] = {}
    for key, filename in names.items():
        path = Path(settings.model_dir) / filename
        out[key] = "present" if path.is_file() else "missing_using_fallback"
    out["malware"] = "heuristic"
    return out
