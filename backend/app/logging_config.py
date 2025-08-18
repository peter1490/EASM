from __future__ import annotations

import json
import logging
import logging.config
import os
import sys
import time
from contextvars import ContextVar
from typing import Any, Dict, Optional


# Context variable for propagating request IDs across the async call stack
request_id_ctx_var: ContextVar[Optional[str]] = ContextVar("request_id", default=None)


def bind_request_id(request_id: Optional[str]) -> None:
    """Bind a request id to the current async context for logging enrichment."""
    request_id_ctx_var.set(request_id)


class JsonFormatter(logging.Formatter):
    """JSON formatter that includes common fields and any extra attributes."""

    # Known LogRecord attributes to avoid duplicating in extras
    _std_attrs = {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
    }

    def format(self, record: logging.LogRecord) -> str:
        base: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Enrich with request id from extra or contextvar if present
        request_id = getattr(record, "request_id", None) or request_id_ctx_var.get()
        if request_id:
            base["request_id"] = request_id

        # Include exception text if present
        if record.exc_info:
            base["exc_info"] = self.formatException(record.exc_info)

        # Include selected origin hints
        base["module"] = record.module
        base["line"] = record.lineno

        # Attach any additional fields passed via logger.extra
        for key, value in record.__dict__.items():
            if key.startswith("_"):
                continue
            if key in self._std_attrs:
                continue
            if key in base:
                continue
            base[key] = value

        def _make_jsonable(obj: Any) -> Any:
            # Fast-path primitives
            if obj is None or isinstance(obj, (str, int, float, bool)):
                return obj
            # Convert sets to sorted lists for stability
            if isinstance(obj, set):
                try:
                    return sorted(list(obj))
                except Exception:
                    return list(obj)
            # Recurse containers
            if isinstance(obj, (list, tuple)):
                return [_make_jsonable(x) for x in obj]
            if isinstance(obj, dict):
                return {str(k): _make_jsonable(v) for k, v in obj.items()}
            # Fallback to string representation
            try:
                json.dumps(obj)
                return obj
            except Exception:
                return str(obj)

        return json.dumps(_make_jsonable(base), ensure_ascii=False)


def _build_dict_config(level: str, log_format: str) -> Dict[str, Any]:
    return {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "plain": {
                "format": "%(asctime)s %(levelname)s %(name)s - %(message)s",
                "datefmt": "%Y-%m-%dT%H:%M:%S%z",
            },
            "json": {
                "()": "app.logging_config.JsonFormatter",
            },
        },
        "handlers": {
            "default": {
                "class": "logging.StreamHandler",
                "stream": "ext://sys.stderr",
                "formatter": "json" if log_format == "json" else "plain",
            }
        },
        "loggers": {
            # Application code
            "": {"handlers": ["default"], "level": level, "propagate": False},
            # Uvicorn loggers
            "uvicorn": {"handlers": ["default"], "level": level, "propagate": False},
            "uvicorn.error": {"handlers": ["default"], "level": level, "propagate": False},
            "uvicorn.access": {"handlers": ["default"], "level": level, "propagate": False},
            # SQL logging (opt-in via env)
            "sqlalchemy.engine": {"level": os.getenv("SQL_LOG_LEVEL", "WARNING").upper()},
        },
    }


def setup_logging(level: Optional[str] = None, fmt: Optional[str] = None) -> None:
    """Configure root logging for the application.

    Controlled by environment variables:
      - LOG_LEVEL (default: INFO)
      - LOG_FORMAT (json|plain, default: plain)
    """
    log_level = (level or os.getenv("LOG_LEVEL", "INFO")).upper()
    log_format = (fmt or os.getenv("LOG_FORMAT", "plain")).lower()
    if log_format not in {"json", "plain"}:
        log_format = "plain"

    try:
        logging.config.dictConfig(_build_dict_config(log_level, log_format))
    except Exception:
        # Fallback minimal configuration if dictConfig fails
        logging.basicConfig(stream=sys.stderr, level=log_level, format="%(asctime)s %(levelname)s %(name)s - %(message)s")


