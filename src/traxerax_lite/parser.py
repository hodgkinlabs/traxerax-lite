"""Parsers for supported log sources."""

import re
from datetime import datetime
from typing import Optional

from traxerax_lite.models import Event

FAILED_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+"
    r"Failed password for(?: invalid user)?\s+"
    r"(?P<user>\S+)\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)

SUCCESS_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<proc>[\w\-/]+)(?:\[\d+\])?:\s+"
    r"Accepted \S+ for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)


def parse_auth_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    """Parse a single auth log line."""
    line = line.strip()
    if not line:
        return None

    year = year or datetime.now().year

    match = FAILED_PATTERN.match(line)
    if match:
        return _build_event(match, line, "ssh_failed_login", year)

    match = SUCCESS_PATTERN.match(line)
    if match:
        return _build_event(match, line, "ssh_success_login", year)

    return None


def _build_event(
    match: re.Match[str],
    raw: str,
    event_type: str,
    year: int,
) -> Event:
    """Build Event object."""
    ts = datetime.strptime(
        f"{year} {match.group('ts')}",
        "%Y %b %d %H:%M:%S",
    )

    return Event(
        timestamp=ts,
        source="auth",
        event_type=event_type,
        raw=raw,
        username=match.group("user"),
        src_ip=match.group("ip"),
        port=int(match.group("port")),
        service="ssh",
        hostname=match.group("host"),
        process=match.group("proc"),
    )