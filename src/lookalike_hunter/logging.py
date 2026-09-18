"""Structured logging setup (structlog, JSON by default)."""

from __future__ import annotations

import logging
import sys

import structlog


class _StderrLogger:
    """Writes to whatever ``sys.stderr`` is *now*: never holds a stale stream."""

    def msg(self, message: str) -> None:
        print(message, file=sys.stderr, flush=True)

    debug = info = warning = warn = error = critical = exception = fatal = log = msg


def _stderr_logger_factory(*_args: object) -> _StderrLogger:
    return _StderrLogger()


def configure_logging(level: str = "INFO", json: bool = True) -> None:
    renderer: structlog.types.Processor = (
        structlog.processors.JSONRenderer() if json else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        logger_factory=_stderr_logger_factory,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
