"""Tests for detection and correlation logic."""

from datetime import datetime

from traxerax_lite.detector import DetectionState, process_event
from traxerax_lite.models import Event


def make_event(
    event_type: str,
    src_ip: str,
    timestamp: datetime,
    username: str | None = None,
    source: str = "auth",
    service: str = "ssh",
    action: str | None = None,
    jail: str | None = None,
    method: str | None = None,
    path: str | None = None,
    status_code: int | None = None,
) -> Event:
    """Build a minimal Event for detector tests."""
    return Event(
        timestamp=timestamp,
        source=source,
        event_type=event_type,
        raw="test raw line",
        username=username,
        src_ip=src_ip,
        port=22 if source == "auth" else None,
        service=service,
        hostname="debian" if source in {"auth", "mail"} else None,
        process="sshd" if source == "auth" else source,
        action=action,
        jail=jail,
        method=method,
        path=path,
        status_code=status_code,
    )


def test_repeated_failed_login_triggers_once_at_threshold() -> None:
    """Repeated SSH failed login finding should trigger once per IP."""
    state = DetectionState()
    ip = "185.10.10.1"

    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 1), "admin"),
        state,
    )
    process_event(
        make_event("ssh_root_login_attempt", ip, datetime(2026, 3, 25, 10, 0, 2), "root"),
        state,
    )
    findings = process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 3), "test"),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "repeated_failed_login" in finding_types


def test_suspicious_nginx_request_generates_finding() -> None:
    """Suspicious nginx probe should create a finding."""
    state = DetectionState()
    findings = process_event(
        make_event(
            "nginx_suspicious_request",
            "185.10.10.1",
            datetime(2026, 3, 25, 10, 0, 4),
            source="nginx",
            service="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "suspicious_web_probe" in finding_types


def test_repeated_mail_auth_failures_generate_finding() -> None:
    """Repeated mail auth failures should trigger once per IP."""
    state = DetectionState()
    ip = "198.51.100.20"

    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 40),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )
    process_event(
        make_event(
            "postfix_sasl_auth_failed",
            ip,
            datetime(2026, 3, 25, 10, 11, 50),
            source="mail",
            service="smtp",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 12, 0),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "repeated_mail_auth_failures" in finding_types


def test_mail_success_after_failures_generates_finding() -> None:
    """Mail success after failures should trigger high-severity finding."""
    state = DetectionState()
    ip = "198.51.100.20"

    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 40),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "dovecot_success_login",
            ip,
            datetime(2026, 3, 25, 10, 30, 0),
            "mailuser",
            source="mail",
            service="imap",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "mail_success_after_failures" in finding_types


def test_ip_banned_after_mail_activity_generates_finding() -> None:
    """Ban after mail auth activity should generate correlation finding."""
    state = DetectionState()
    ip = "198.51.100.20"

    process_event(
        make_event(
            "postfix_sasl_auth_failed",
            ip,
            datetime(2026, 3, 25, 10, 11, 50),
            source="mail",
            service="smtp",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "fail2ban_ban",
            ip,
            datetime(2026, 3, 25, 10, 12, 30),
            source="fail2ban",
            service="postfix-sasl",
            action="ban",
            jail="actions",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "ip_banned_after_mail_activity" in finding_types