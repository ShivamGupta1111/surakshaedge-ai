"""Adapter for an optional local ExecuTorch Llama runtime.

The adapter never contacts a cloud API. If ExecuTorch is not installed, all
methods report a disabled state.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any


@dataclass
class ExecuTorchStatus:
    available: bool
    reason: str
    model_path: str | None = None
    backend: str = "executorch_llama"


class ExecuTorchLlamaAdapter:
    """Integration boundary for a future or installed ExecuTorch Llama model."""

    def __init__(self, model_path: str = "", timeout_seconds: float = 8.0) -> None:
        self.model_path = model_path
        self.timeout_seconds = timeout_seconds
        self._runtime: Any | None = None

    def is_available(self) -> bool:
        return self.status().available

    def status(self) -> ExecuTorchStatus:
        try:
            importlib.import_module("executorch")
        except Exception:
            return ExecuTorchStatus(
                available=False,
                reason="ExecuTorch is not installed in this environment",
                model_path=self.model_path or None,
            )
        if not self.model_path:
            return ExecuTorchStatus(
                available=False,
                reason="ExecuTorch is installed but SURAKSHAEDGE_EXECUTORCH_MODEL_PATH is empty",
            )
        return ExecuTorchStatus(available=True, reason="ready", model_path=self.model_path)

    def load_model(self) -> ExecuTorchStatus:
        status = self.status()
        if not status.available:
            self._runtime = None
            return status
        self._runtime = {"path": self.model_path, "loaded": True}
        return status

    def generate_advice(self, structured_prompt: dict[str, Any]) -> str:
        status = self.status()
        if not status.available:
            raise RuntimeError(status.reason)
        raise TimeoutError("ExecuTorch generation is not wired; refusing to invent model output")

    def metadata(self) -> dict[str, Any]:
        status = self.status()
        return {
            "backend": status.backend,
            "available": status.available,
            "reason": status.reason,
            "model_path": status.model_path,
            "timeout_seconds": self.timeout_seconds,
            "loaded": self._runtime is not None,
        }
