"""Pytest shared environment. Uses a temp SQLite file and high rate limits."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TMP = Path(tempfile.mkdtemp(prefix="surakshaedge-test-"))
os.environ.setdefault("SURAKSHAEDGE_ENV", "test")
os.environ["SURAKSHAEDGE_DATABASE_PATH"] = str(TMP / "test.sqlite3")
os.environ["SURAKSHAEDGE_MODEL_DIR"] = str(ROOT / "models")
os.environ["SURAKSHAEDGE_DATA_DIR"] = str(ROOT / "data")
os.environ["SURAKSHAEDGE_AUTH_ENABLED"] = "false"
os.environ["SURAKSHAEDGE_RATE_LIMIT_PER_MINUTE"] = "500"
os.environ["SURAKSHAEDGE_STORE_RAW_CONTENT"] = "false"
os.environ["SURAKSHAEDGE_ALLOW_PRIVATE_URL_ANALYSIS"] = "false"
os.environ["SURAKSHAEDGE_ADVISOR_BACKEND"] = "local_template"

from src.config import reset_settings_cache  # noqa: E402
from src.sms_detector import get_sms_detector  # noqa: E402
from src.storage import reset_storage_cache  # noqa: E402
from src.url_detector import get_url_detector  # noqa: E402

reset_settings_cache()
reset_storage_cache()
get_sms_detector.cache_clear()
get_url_detector.cache_clear()
