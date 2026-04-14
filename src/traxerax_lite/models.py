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
    action: Optional[str] = None
    jail: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    normalized_path: Optional[str] = None
    query_string: Optional[str] = None
    referrer: Optional[str] = None
    user_agent: Optional[str] = None
    match_reason: Optional[str] = None
    bytes_sent: Optional[int] = None
    status_code: Optional[int] = None


@dataclass(slots=True)
class Finding:
    """Detection finding generated from one or more events."""

    finding_type: str
    severity: str
    message: str
    src_ip: Optional[str]
    timestamp: datetime


@dataclass(slots=True)
class EnforcementAction:
    """Normalized enforcement action emitted by security controls."""

    timestamp: datetime
    raw: str
    src_ip: Optional[str]
    action: str
    service: Optional[str] = None
    process: Optional[str] = None
    jail: Optional[str] = None
