"""Structured logging without raw user content or secrets."""

from __future__ import annotations

import logging
import sys
from typing import Any

from src.config import get_settings
from src.security import redact_text

_CONFIGURED = False


class RedactingFilter(logging.Filter):
    """Scrub likely secrets from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = "-"
        try:
            formatted = record.getMessage()
        except Exception:
            formatted = str(record.msg)
        record.msg = redact_text(formatted)
        record.args = ()
        return True


def configure_logging(level: str | None = None) -> None:
    global _CONFIGURED
    settings = get_settings()
    log_level = (level or settings.log_level).upper()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s request_id=%(request_id)s %(message)s")
    )
    handler.addFilter(RedactingFilter())

    root = logging.getLogger("surakshaedge")
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(log_level)
    root.propagate = False
    _CONFIGURED = True


class RequestIdAdapter(logging.LoggerAdapter):
    def process(self, msg: str, kwargs: Any) -> tuple[str, Any]:
        extra = kwargs.setdefault("extra", {})
        extra.setdefault("request_id", self.extra.get("request_id", "-"))
        return msg, kwargs


def get_logger(name: str, request_id: str = "-") -> logging.LoggerAdapter:
    if not _CONFIGURED:
        configure_logging()
    logger = logging.getLogger(f"surakshaedge.{name}")
    if not logger.handlers:
        logger.parent = logging.getLogger("surakshaedge")
        logger.propagate = True
    return RequestIdAdapter(logger, {"request_id": request_id})
