"""Entry point: API server and small local CLI."""

from __future__ import annotations

import argparse
import json
import sys

import uvicorn

from src.config import get_settings
from src.logging_config import configure_logging
from src.malware_detector import MalwareDetector
from src.network_detector import NetworkDetector
from src.risk_engine import combine
from src.advisor import Advisor
from src.schemas import NetworkFlowRequest, TelemetryRequest
from src.sms_detector import SmsDetector
from src.url_detector import UrlDetector


def _print(assessment) -> None:  # type: ignore[no-untyped-def]
    print(json.dumps(json.loads(assessment.model_dump_json()), indent=2))


def run_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="SurakshaEdge AI local CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)
    msg = sub.add_parser("analyze-message")
    msg.add_argument("text")
    url = sub.add_parser("analyze-url")
    url.add_argument("url")
    sub.add_parser("analyze-flow-demo")
    args = parser.parse_args(argv)
    advisor = Advisor()
    if args.cmd == "analyze-message":
        result = SmsDetector().analyze(args.text)
        assessment = combine([result])
        assessment.advice = advisor.advise(assessment)
        _print(assessment)
        return 0
    if args.cmd == "analyze-url":
        result = UrlDetector().analyze(args.url)
        assessment = combine([result])
        assessment.advice = advisor.advise(assessment)
        _print(assessment)
        return 0
    if args.cmd == "analyze-flow-demo":
        flow = NetworkFlowRequest(dst_port=80, protocol="tcp", duration=1, fwd_packets=4, bwd_packets=4)
        result = NetworkDetector().analyze(flow)
        assessment = combine([result])
        assessment.advice = advisor.advise(assessment)
        _print(assessment)
        return 0
    _ = TelemetryRequest
    _ = MalwareDetector
    return 1


def serve() -> None:
    configure_logging()
    settings = get_settings()
    uvicorn.run(
        "src.api:app",
        host=settings.host,
        port=settings.port,
        reload=False,
        log_level=settings.log_level.lower(),
    )


def main() -> None:
    if len(sys.argv) > 1:
        raise SystemExit(run_cli(sys.argv[1:]))
    serve()


if __name__ == "__main__":
    main()
