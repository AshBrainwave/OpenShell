# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Root conftest for Python tests.

Pre-register openshell as a namespace package so subpackage tests (e.g.,
the prover) can run without the full Rust build that generates proto stubs.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

if "openshell" not in sys.modules:
    _pkg = types.ModuleType("openshell")
    _pkg.__path__ = [str(Path(__file__).resolve().parent / "openshell")]
    _pkg.__package__ = "openshell"
    sys.modules["openshell"] = _pkg
