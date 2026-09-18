"""Pytest fixtures for the Woo-Lam live range.

Fixtures live in the uniquely-named ``woo_lam_testkit`` module; this file only
re-exports them so pytest registers them for the test package.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from woo_lam_testkit import expected_flag, start_target  # noqa: E402,F401