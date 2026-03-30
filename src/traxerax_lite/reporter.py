"""Formatting helpers for terminal output."""

from traxerax_lite.models import Event, Finding


def format_event(event: Event) -> str:
    """Return a concise terminal-friendly event string."""
    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    ip = event.src_ip or "-"
    user = event.username or "-"
    host = event.hostname or "-"
    process = event.process or "-"
    service = event.service or "-"
    action = event.action or "-"
    jail = event.jail or "-"

    return (
        f"[EVENT] {timestamp} "
        f"source={event.source} "
        f"type={event.event_type} "
        f"ip={ip} "
        f"user={user} "
        f"host={host} "
        f"process={process} "
        f"service={service} "
        f"action={action} "
        f"jail={jail}"
    )


def format_finding(finding: Finding) -> str:
    """Return a concise terminal-friendly finding string."""
    timestamp = finding.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    ip = finding.src_ip or "-"

    return (
        f"[FINDING][{finding.severity.upper()}] {timestamp} "
        f"type={finding.finding_type} "
        f"ip={ip} "
        f"message={finding.message}"
    )