"""Pytest configuration shared across the test suite."""
import sys
import zipfile


def pytest_configure(config):
    """Suppress a CPython 3.13 GC finalizer regression.

    In CPython 3.13, ``ZipFile.__del__`` can fire after its underlying
    ``fp`` has already been finalised during interpreter shutdown, producing
    a spurious ``ValueError: I/O operation on closed file`` on stderr that
    causes the process to exit with code 1 even when all tests pass.

    The custom ``sys.unraisablehook`` installed here discards that specific
    error and delegates everything else to Python's default handler.
    """
    _original_hook = sys.unraisablehook

    def _unraisable_filter(unraisable):
        if (
            isinstance(unraisable.exc_value, ValueError)
            and unraisable.object is not None
            and getattr(unraisable.object, "__qualname__", "").startswith("ZipFile.")
        ):
            return  # swallow the CPython 3.13 GC ordering artefact
        _original_hook(unraisable)

    sys.unraisablehook = _unraisable_filter
