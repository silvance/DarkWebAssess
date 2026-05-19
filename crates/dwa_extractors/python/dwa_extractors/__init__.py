"""Fast observable extractors for DarkWebAssess.

The actual implementation lives in the compiled `_native` Rust extension.
This wrapper exists so type-stubs / docstrings can live in pure Python
and so the package is importable even before the native extension loads
(it'll raise a clear ImportError instead of an opaque one).
"""
from ._native import extract_observables, version

__all__ = ["extract_observables", "version"]
