"""Data models for Traxerax Lite."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass(slots=True)
class Event:
    """Normalized security event."""

    timestamp: datetime
    source: str
    event_type: str
    raw: str
    username: Optional[str] = None
    src_ip: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    hostname: Optional[str] = None
    process: Optional[str] = None