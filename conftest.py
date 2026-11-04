"""Pytest bootstrap: put the repo root on sys.path.

NOTE: only pytest loads this file. A bare `python tests/test_x.py` does NOT
read conftest.py (sys.path[0] is tests/), so for direct runs use
`pip install -e .` (see pyproject.toml) or `python -m pytest`.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
