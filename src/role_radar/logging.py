"""Logging estructurado: structlog con renderer JSON a stdout."""

from typing import cast

import structlog

from role_radar.config import Settings


def configure_logging(settings: Settings) -> None:
    """Configura structlog: JSON a stdout, con nivel, timestamp ISO y evento."""
    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(settings.log_level),
    )


def get_logger() -> structlog.BoundLogger:
    """Acceso estándar a un logger ya configurado."""
    return cast(structlog.BoundLogger, structlog.get_logger())
