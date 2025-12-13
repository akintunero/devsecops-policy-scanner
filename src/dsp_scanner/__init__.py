"""DSP Scanner - Advanced DevSecOps Policy Scanner.

Keep this module import-light.

Tests and downstream consumers often import submodules like `dsp_scanner.core.results`.
Python always executes `dsp_scanner/__init__.py` first, so importing heavyweight modules
(or optional dependencies) here can break unrelated functionality.
"""

from __future__ import annotations

from typing import Any

__version__ = "0.1.0"
__author__ = "DSP Scanner Team"

__all__ = ["Scanner", "ScanResult", "Policy", "__version__"]


def __getattr__(name: str) -> Any:
    # Lazy re-exports for convenience without import-time side effects.
    if name == "Scanner":
        from dsp_scanner.core.scanner import Scanner

        return Scanner
    if name == "ScanResult":
        from dsp_scanner.core.results import ScanResult

        return ScanResult
    if name == "Policy":
        from dsp_scanner.core.policy import Policy

        return Policy
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
