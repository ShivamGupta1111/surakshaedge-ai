"""FastAPI application: local-only analysis API."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from threading import Lock
from typing import Any

from fastapi import Depends, FastAPI, Header, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from src.advisor import get_advisor
from src.config import PROJECT_ROOT, get_settings
from src.exceptions import AuthError, RateLimitError, SurakshaEdgeError, ValidationFailed
from src.health import health, info, model_status, ready
from src.logging_config import configure_logging, get_logger
from src.malware_detector import get_malware_detector
from src.metrics import METRICS
from src.network_detector import get_network_detector
from src.risk_engine import combine
from src.schemas import (
    AnalyzeMessageRequest,
    AnalyzeUrlRequest,
    BatchAnalyzeRequest,
    FeedbackRequest,
    NetworkFlowRequest,
    RiskAssessment,
    TelemetryRequest,
)
from src.security import content_hash, verify_api_key
from src.sms_detector import get_sms_detector
from src.storage import get_storage
from src.url_detector import get_url_detector

configure_logging()
_RATE_LOCK = Lock()
_RATE_HITS: dict[str, deque[float]] = defaultdict(deque)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "local"


def check_rate_limit(request: Request) -> None:
    settings = get_settings()
    now = time.time()
    key = _client_key(request)
    with _RATE_LOCK:
        bucket = _RATE_HITS[key]
        while bucket and now - bucket[0] > 60:
            bucket.popleft()
        if len(bucket) >= settings.rate_limit_per_minute:
            raise RateLimitError()
        bucket.append(now)


def check_auth(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> None:
    settings = get_settings()
    if not settings.auth_enabled:
        return
    if not verify_api_key(x_api_key, settings.api_key_sha256):
        raise AuthError("Invalid or missing API key")


def persist(assessment: RiskAssessment, detector_type: str, raw: str | None) -> RiskAssessment:
    hashed = content_hash(raw) if raw else None
    storage = get_storage()
    storage.purge_expired()
    alert_id = storage.save_assessment(
        assessment, detector_type=detector_type, content_hash=hashed
    )
    assessment.alert_id = alert_id
    assessment.content_hash = hashed
    return assessment


def with_advice(assessment: RiskAssessment) -> RiskAssessment:
    advice = get_advisor().advise(assessment)
    assessment.advice = advice
    assessment.advisor_backend = advice.backend
    return assessment


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(
        title="SurakshaEdge AI",
        version="0.1.0",
        description="Local privacy-preserving threat detection backend",
    )
    if settings.cors_origin_list:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origin_list,
            allow_methods=["GET", "POST", "DELETE"],
            allow_headers=["*"],
        )

    @application.middleware("http")
    async def request_context(request: Request, call_next):  # type: ignore[no-untyped-def]
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        logger = get_logger("api", request_id)
        try:
            check_rate_limit(request)
            response = await call_next(request)
        except SurakshaEdgeError as exc:
            METRICS.inc("errors")
            logger.warning("error code=%s", exc.code)
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "error": exc.message,
                    "code": exc.code,
                    "request_id": request_id,
                },
                headers={"X-Request-ID": request_id},
            )
        elapsed = (time.perf_counter() - started) * 1000
        METRICS.observe(request.url.path, elapsed)
        METRICS.inc("requests")
        logger.info("path=%s status=%s latency_ms=%.1f", request.url.path, response.status_code, elapsed)
        response.headers["X-Request-ID"] = request_id
        return response

    static_dir = PROJECT_ROOT / "static"
    if static_dir.is_dir():
        application.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

        @application.get("/", include_in_schema=False)
        def index() -> Any:
            return FileResponse(static_dir / "index.html")

    @application.get("/health")
    def health_endpoint() -> Any:
        return health()

    @application.get("/ready")
    def ready_endpoint() -> Any:
        payload = ready()
        status = 200 if payload["ready"] else 503
        return JSONResponse(payload, status_code=status)

    @application.get("/api/v1/info")
    def info_endpoint() -> Any:
        return info(model_status())

    @application.get("/api/v1/dashboard")
    def dashboard(auth: None = Depends(check_auth)) -> Any:
        alerts = get_storage().list_alerts(limit=20)
        return {
            "title": "SurakshaEdge local dashboard",
            "models": model_status(),
            "recent_alerts": [item.model_dump() for item in alerts],
        }

    @application.post("/api/v1/analyze/message")
    def analyze_message(
        body: AnalyzeMessageRequest,
        request: Request,
        auth: None = Depends(check_auth),
    ) -> Any:
        settings = get_settings()
        if len(body.message) > settings.max_message_length:
            raise ValidationFailed("Message exceeds the configured maximum length")
        result = get_sms_detector().analyze(body.message)
        assessment = with_advice(combine([result]))
        persist(assessment, "sms", body.message if settings.store_raw_content else body.message)
        # hash is stored; raw is not written to sqlite unless store_raw_content (still hashed only)
        assessment.request_id = getattr(request.state, "request_id", None)
        return assessment

    @application.post("/api/v1/analyze/url")
    def analyze_url(
        body: AnalyzeUrlRequest,
        request: Request,
        auth: None = Depends(check_auth),
    ) -> Any:
        result = get_url_detector().analyze(body.url, redirect_count=body.redirect_count)
        assessment = with_advice(combine([result]))
        persist(assessment, "url", body.url)
        assessment.request_id = getattr(request.state, "request_id", None)
        return assessment

    @application.post("/api/v1/analyze/network-flow")
    def analyze_flow(
        body: NetworkFlowRequest,
        request: Request,
        auth: None = Depends(check_auth),
    ) -> Any:
        result = get_network_detector().analyze(body)
        assessment = with_advice(combine([result]))
        persist(assessment, "network", None)
        assessment.request_id = getattr(request.state, "request_id", None)
        return assessment

    @application.post("/api/v1/analyze/telemetry")
    def analyze_telemetry(
        body: TelemetryRequest,
        request: Request,
        auth: None = Depends(check_auth),
    ) -> Any:
        result = get_malware_detector().analyze(body)
        assessment = with_advice(combine([result]))
        persist(assessment, "malware", None)
        assessment.request_id = getattr(request.state, "request_id", None)
        return assessment

    @application.post("/api/v1/analyze/batch")
    def analyze_batch(body: BatchAnalyzeRequest, auth: None = Depends(check_auth)) -> Any:
        settings = get_settings()
        total = len(body.messages) + len(body.urls) + len(body.flows) + len(body.telemetry)
        if total == 0:
            raise ValidationFailed("Batch is empty")
        if total > settings.max_batch_size:
            raise ValidationFailed(f"Batch exceeds max size of {settings.max_batch_size}")
        items: list[RiskAssessment] = []
        for msg in body.messages:
            items.append(with_advice(combine([get_sms_detector().analyze(msg.message)])))
        for url in body.urls:
            items.append(with_advice(combine([get_url_detector().analyze(url.url)])))
        for flow in body.flows:
            items.append(with_advice(combine([get_network_detector().analyze(flow)])))
        for tel in body.telemetry:
            items.append(with_advice(combine([get_malware_detector().analyze(tel)])))
        for item, kind in zip(
            items,
            ["sms"] * len(body.messages)
            + ["url"] * len(body.urls)
            + ["network"] * len(body.flows)
            + ["malware"] * len(body.telemetry),
        ):
            persist(item, kind, None)
        return {"count": len(items), "results": items}

    @application.get("/api/v1/alerts")
    def list_alerts(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
        auth: None = Depends(check_auth),
    ) -> Any:
        return {"alerts": get_storage().list_alerts(limit=limit, offset=offset)}

    @application.get("/api/v1/alerts/{alert_id}")
    def get_alert(alert_id: str, auth: None = Depends(check_auth)) -> Any:
        return get_storage().get(alert_id)

    @application.delete("/api/v1/alerts/{alert_id}")
    def delete_alert(alert_id: str, auth: None = Depends(check_auth)) -> Any:
        get_storage().delete(alert_id)
        return {"deleted": alert_id}

    @application.post("/api/v1/feedback")
    def feedback(body: FeedbackRequest, auth: None = Depends(check_auth)) -> Any:
        get_storage().set_feedback(body.alert_id, body.useful, body.comment)
        return {"ok": True}

    @application.get("/api/v1/metrics")
    def metrics(auth: None = Depends(check_auth)) -> Any:
        return METRICS.snapshot()

    return application


app = create_app()
