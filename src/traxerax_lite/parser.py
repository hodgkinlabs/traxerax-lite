"""Parsers for supported log sources."""

import re
from datetime import datetime
from typing import Iterable, Optional
from urllib.parse import urlsplit

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

FAIL2BAN_PATTERN = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+"
    r"fail2ban\.(?P<jail>[\w\-]+)\s+"
    r"\[\d+\]:\s+"
    r"(?:NOTICE|INFO)\s+"
    r"\[(?P<service>[\w\-]+)\]\s+"
    r"(?P<action>Ban|Unban)\s+"
    r"(?P<ip>\S+)"
)

NGINX_ACCESS_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[^"]+"\s+'
    r'(?P<status>\d{3})\s+\S+'
)


def parse_auth_line(line: str, year: Optional[int] = None) -> Optional[Event]:
    """Parse a single auth log line."""
    stripped = line.strip()
    if not stripped:
        return None

    parsed_year = year or datetime.now().year

    match = FAILED_PATTERN.match(stripped)
    if match:
        user = match.group("user")
        event_type = "ssh_failed_login"
        if user == "root":
            event_type = "ssh_root_login_attempt"

        return _build_auth_event(match, stripped, event_type, parsed_year)

    match = SUCCESS_PATTERN.match(stripped)
    if match:
        return _build_auth_event(
            match,
            stripped,
            "ssh_success_login",
            parsed_year,
        )

    return None


def parse_fail2ban_line(line: str) -> Optional[Event]:
    """Parse a single fail2ban log line."""
    stripped = line.strip()
    if not stripped:
        return None

    match = FAIL2BAN_PATTERN.match(stripped)
    if not match:
        return None

    timestamp = datetime.strptime(
        match.group("ts"),
        "%Y-%m-%d %H:%M:%S",
    )

    action = match.group("action").lower()
    event_type = f"fail2ban_{action}"

    return Event(
        timestamp=timestamp,
        source="fail2ban",
        event_type=event_type,
        raw=stripped,
        src_ip=match.group("ip"),
        service=match.group("service"),
        process="fail2ban",
        action=action,
        jail=match.group("jail"),
    )


def is_suspicious_path(path: str, suspicious_paths: Iterable[str]) -> bool:
    """Return True if path matches configured suspicious targets."""
    normalized = urlsplit(path).path.rstrip("/") or "/"
    return normalized in suspicious_paths


def parse_nginx_access_line(
    line: str,
    suspicious_paths: Iterable[str],
) -> Optional[Event]:
    """Parse a single nginx access log line."""
    stripped = line.strip()
    if not stripped:
        return None

    match = NGINX_ACCESS_PATTERN.match(stripped)
    if not match:
        return None

    timestamp = datetime.strptime(
        match.group("ts"),
        "%d/%b/%Y:%H:%M:%S %z",
    )

    path = match.group("path")
    event_type = "nginx_request"
    if is_suspicious_path(path, suspicious_paths):
        event_type = "nginx_suspicious_request"

    return Event(
        timestamp=timestamp,
        source="nginx",
        event_type=event_type,
        raw=stripped,
        src_ip=match.group("ip"),
        service="nginx",
        process="nginx",
        method=match.group("method"),
        path=path,
        status_code=int(match.group("status")),
    )


def _build_auth_event(
    match: re.Match[str],
    raw: str,
    event_type: str,
    year: int,
) -> Event:
    """Build Event object from auth log regex match."""
    timestamp = datetime.strptime(
        f"{year} {match.group('ts')}",
        "%Y %b %d %H:%M:%S",
    )

    return Event(
        timestamp=timestamp,
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