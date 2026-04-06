"""Tests for detection and correlation logic."""

from datetime import datetime

from traxerax_lite.detector import (
    DetectionState,
    process_enforcement_action,
    process_event,
)
from traxerax_lite.models import EnforcementAction, Event


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


def make_enforcement_action(
    src_ip: str,
    timestamp: datetime,
    action: str = "ban",
    service: str = "sshd",
    jail: str | None = None,
) -> EnforcementAction:
    """Build a minimal EnforcementAction for detector tests."""
    return EnforcementAction(
        timestamp=timestamp,
        raw="test enforcement line",
        src_ip=src_ip,
        action=action,
        service=service,
        process="fail2ban",
        jail=jail,
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


def test_repeated_http_errors_generate_finding() -> None:
    """Repeated configured HTTP error responses should trigger a finding."""
    state = DetectionState(http_error_statuses={400, 404, 500}, http_error_threshold=3)
    ip = "185.10.10.1"

    for second in range(1, 3):
        process_event(
            make_event(
                "nginx_request",
                ip,
                datetime(2026, 3, 25, 10, 0, second),
                source="nginx",
                service="nginx",
                method="GET",
                path="/missing",
                status_code=404,
            ),
            state,
        )

    findings = process_event(
        make_event(
            "nginx_request",
            ip,
            datetime(2026, 3, 25, 10, 0, 3),
            source="nginx",
            service="nginx",
            method="GET",
            path="/missing",
            status_code=404,
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "repeated_http_error_responses" in finding_types


def test_repeated_failed_login_respects_custom_threshold() -> None:
    """SSH failure threshold should be configurable."""
    state = DetectionState(auth_failed_login_threshold=2)
    ip = "185.10.10.1"

    process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 1), "admin"),
        state,
    )
    findings = process_event(
        make_event("ssh_failed_login", ip, datetime(2026, 3, 25, 10, 0, 2), "test"),
        state,
    )

    assert any(
        finding.finding_type == "repeated_failed_login"
        for finding in findings
    )


def test_rule_can_be_disabled_in_detection_state() -> None:
    """Disabled rules should suppress their findings."""
    state = DetectionState(
        enabled_rules={"suspicious_web_probe": False},
    )

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
    assert "suspicious_web_probe" not in finding_types


def test_rule_severity_can_be_overridden() -> None:
    """Custom severity overrides should be used in generated findings."""
    state = DetectionState(
        finding_severities={"root_login_attempt": "critical"},
    )

    findings = process_event(
        make_event(
            "ssh_root_login_attempt",
            "185.10.10.1",
            datetime(2026, 3, 25, 10, 0, 2),
            "root",
        ),
        state,
    )

    root_findings = [
        finding for finding in findings
        if finding.finding_type == "root_login_attempt"
    ]
    assert root_findings
    assert root_findings[0].severity == "critical"


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


def test_mail_password_spray_attempt_generates_finding() -> None:
    """Distinct failed usernames from one IP should trigger spray detection."""
    state = DetectionState(mail_unique_username_threshold=3)
    ip = "198.51.100.20"

    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 40),
            "alice",
            source="mail",
            service="imap",
        ),
        state,
    )
    process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 11, 50),
            "bob",
            source="mail",
            service="imap",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "dovecot_failed_login",
            ip,
            datetime(2026, 3, 25, 10, 12, 0),
            "carol",
            source="mail",
            service="pop3",
        ),
        state,
    )

    spray_findings = [
        finding for finding in findings
        if finding.finding_type == "mail_password_spray_attempt"
    ]
    assert spray_findings
    assert spray_findings[0].severity == "high"


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
    findings = process_enforcement_action(
        make_enforcement_action(
            ip,
            datetime(2026, 3, 25, 10, 12, 30),
            service="postfix-sasl",
            action="ban",
            jail="actions",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "ip_banned_after_mail_activity" in finding_types


def test_ip_banned_after_web_activity_generates_finding() -> None:
    """Ban after prior nginx activity should correlate without auth events."""
    state = DetectionState(http_error_statuses={404}, http_error_threshold=3)
    ip = "185.10.10.1"

    process_event(
        make_event(
            "nginx_request",
            ip,
            datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            service="nginx",
            method="GET",
            path="/missing",
            status_code=404,
        ),
        state,
    )
    findings = process_enforcement_action(
        make_enforcement_action(
            ip,
            datetime(2026, 3, 25, 10, 1, 1),
            service="nginx-badbots",
            action="ban",
            jail="actions",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "ip_banned_after_web_activity" in finding_types


def test_web_probe_followed_by_fail2ban_ban_requires_temporal_order() -> None:
    """Web probe to ban finding should not fire when the ban came first."""
    state = DetectionState(http_error_statuses={404}, http_error_threshold=3)
    ip = "185.10.10.1"

    process_enforcement_action(
        make_enforcement_action(
            ip,
            datetime(2026, 3, 25, 10, 0, 1),
            service="nginx-badbots",
            action="ban",
            jail="actions",
        ),
        state,
    )
    findings = process_event(
        make_event(
            "nginx_suspicious_request",
            ip,
            datetime(2026, 3, 25, 10, 0, 2),
            source="nginx",
            service="nginx",
            method="GET",
            path="/xmlrpc.php",
            status_code=404,
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "web_probe_followed_by_fail2ban_ban" not in finding_types
