"""Formatting helpers for terminal output."""

import json
from traxerax_lite.models import EnforcementAction, Event, Finding


def format_event(event: Event) -> str:
    """Return a concise terminal-friendly event string."""
    timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S%z")
    ip = event.src_ip or "-"
    user = event.username or "-"
    host = event.hostname or "-"
    process = event.process or "-"
    service = event.service or "-"
    action = event.action or "-"
    jail = event.jail or "-"
    method = event.method or "-"
    path = event.path or "-"
    status_code = event.status_code if event.status_code is not None else "-"

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
        f"jail={jail} "
        f"method={method} "
        f"path={path} "
        f"status={status_code}"
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


def format_enforcement_action(action: EnforcementAction) -> str:
    """Return a concise terminal-friendly enforcement string."""
    timestamp = action.timestamp.strftime("%Y-%m-%d %H:%M:%S%z")
    ip = action.src_ip or "-"
    service = action.service or "-"
    process = action.process or "-"
    jail = action.jail or "-"

    return (
        f"[ENFORCEMENT] {timestamp} "
        f"action={action.action} "
        f"ip={ip} "
        f"service={service} "
        f"process={process} "
        f"jail={jail}"
    )


def json_format_event(event: Event) -> str:
    """Return JSON representation of an event."""
    data = {
        "type": "event",
        "timestamp": event.timestamp.isoformat(),
        "source": event.source,
        "event_type": event.event_type,
        "raw": event.raw,
        "username": event.username,
        "src_ip": event.src_ip,
        "port": event.port,
        "service": event.service,
        "hostname": event.hostname,
        "process": event.process,
        "action": event.action,
        "jail": event.jail,
        "method": event.method,
        "path": event.path,
        "status_code": event.status_code,
    }
    return json.dumps(data)


def json_format_finding(finding: Finding) -> str:
    """Return JSON representation of a finding."""
    data = {
        "type": "finding",
        "timestamp": finding.timestamp.isoformat(),
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "message": finding.message,
        "src_ip": finding.src_ip,
    }
    return json.dumps(data)


def json_format_enforcement_action(action: EnforcementAction) -> str:
    """Return JSON representation of an enforcement action."""
    data = {
        "type": "enforcement",
        "timestamp": action.timestamp.isoformat(),
        "raw": action.raw,
        "src_ip": action.src_ip,
        "action": action.action,
        "service": action.service,
        "process": action.process,
        "jail": action.jail,
    }
    return json.dumps(data)
