"""Minimal Mirat runtime error reporter for Python (stdlib only).

Usage:
    from mirat_sdk import init
    init("https://monitor.example/api/events/PROJECT_KEY", environment="production")
"""
from __future__ import annotations
import json
import logging
import sys
import threading
import traceback
import urllib.request
from datetime import datetime, timezone

_DSN = ""
_ENVIRONMENT = "production"
_RELEASE = ""
_INSTALLED = False


def _post(event):
    if not _DSN:
        return
    try:
        body = json.dumps(event, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(_DSN, data=body, headers={"Content-Type": "text/plain; charset=utf-8"}, method="POST")
        with urllib.request.urlopen(request, timeout=2) as response:
            response.read(128)
    except Exception:
        # Monitoring must never replace or mask the application's original error.
        pass


def capture_exception(error, *, level="error", tags=None, extra=None):
    """Send an exception event asynchronously; safe to call from application code."""
    try:
        trace = "".join(traceback.format_exception(type(error), error, error.__traceback__))
        tb = error.__traceback__
        while tb and tb.tb_next:
            tb = tb.tb_next
        culprit = f"{tb.tb_frame.f_code.co_filename}:{tb.tb_lineno}" if tb else ""
        event = {
            "type": type(error).__name__, "message": str(error)[:1000], "stacktrace": trace[-12000:],
            "culprit": culprit, "level": level, "environment": _ENVIRONMENT, "release": _RELEASE,
            "timestamp": datetime.now(timezone.utc).isoformat(), "tags": tags or {}, "extra": extra or {},
        }
        threading.Thread(target=_post, args=(event,), daemon=True, name="mirat-error-report").start()
    except Exception:
        pass


def _sys_exception_hook(exc_type, value, tb):
    try:
        capture_exception(value)
    finally:
        _previous_sys_hook(exc_type, value, tb)


def _thread_exception_hook(args):
    try:
        capture_exception(args.exc_value, extra={"thread": getattr(args.thread, "name", "")})
    finally:
        _previous_thread_hook(args)


_previous_sys_hook = sys.excepthook
_previous_thread_hook = getattr(threading, "excepthook", None)


class _MiratLogHandler(logging.Handler):
    def emit(self, record):
        if record.exc_info and record.exc_info[1]:
            capture_exception(record.exc_info[1], level="error", extra={"logger": record.name})


def init(dsn, *, environment="production", release="", capture_logs=False):
    """Install process/thread uncaught-exception hooks. Call once at app startup."""
    global _DSN, _ENVIRONMENT, _RELEASE, _INSTALLED, _previous_sys_hook, _previous_thread_hook
    _DSN, _ENVIRONMENT, _RELEASE = str(dsn), str(environment), str(release)
    if _INSTALLED:
        return
    _previous_sys_hook = sys.excepthook
    sys.excepthook = _sys_exception_hook
    if hasattr(threading, "excepthook"):
        _previous_thread_hook = threading.excepthook
        threading.excepthook = _thread_exception_hook
    if capture_logs:
        logging.getLogger().addHandler(_MiratLogHandler())
    _INSTALLED = True
