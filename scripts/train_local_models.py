"""Thin wrapper so `python scripts/train_local_models.py` matches the documented layout."""

from __future__ import annotations

import runpy
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
runpy.run_path(str(ROOT / "train_models.py"), run_name="__main__")
