"""Tests for detection and correlation logic."""

from datetime import datetime

from traxerax_lite.detector import DetectionState, process_event
from traxerax_lite.models import Event


def make_event(
    event_type: str,
    src_ip: str,
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
        timestamp=datetime(2026, 3, 25, 10, 0, 0),
        source=source,
        event_type=event_type,
        raw="test raw line",
        username=username,
        src_ip=src_ip,
        port=22 if source == "auth" else None,
        service=service,
        hostname="debian" if source == "auth" else None,
        process="sshd" if source == "auth" else source,
        action=action,
        jail=jail,
        method=method,
        path=path,
        status_code=status_code,
    )


def test_root_login_attempt_generates_finding() -> None:
    """A root login attempt should create a root-specific finding."""
    state = DetectionState()
    event = make_event(
        event_type="ssh_root_login_attempt",
        src_ip="185.10.10.1",
        username="root",
    )

    findings = process_event(event, state)

    assert len(findings) == 1
    assert findings[0].finding_type == "root_login_attempt"


def test_repeated_failed_login_triggers_once_at_threshold() -> None:
    """Repeated failed login finding should trigger once per IP."""
    state = DetectionState()
    ip = "185.10.10.1"

    findings1 = process_event(make_event("ssh_failed_login", ip, "admin"), state)
    findings2 = process_event(
        make_event("ssh_root_login_attempt", ip, "root"),
        state,
    )
    findings3 = process_event(make_event("ssh_failed_login", ip, "test"), state)
    findings4 = process_event(make_event("ssh_failed_login", ip, "guest"), state)

    assert findings1 == []
    assert len(findings2) == 1
    assert findings2[0].finding_type == "root_login_attempt"
    assert len(findings3) == 1
    assert findings3[0].finding_type == "repeated_failed_login"
    assert findings4 == []


def test_success_after_failures_generates_finding() -> None:
    """A success after prior failures from same IP should trigger."""
    state = DetectionState()
    ip = "203.0.113.77"

    process_event(make_event("ssh_failed_login", ip, "user1"), state)
    findings = process_event(make_event("ssh_success_login", ip, "user1"), state)

    assert len(findings) == 1
    assert findings[0].finding_type == "success_after_failures"


def test_suspicious_nginx_request_generates_finding() -> None:
    """Suspicious nginx probe should create a finding."""
    state = DetectionState()
    findings = process_event(
        make_event(
            event_type="nginx_suspicious_request",
            src_ip="185.10.10.1",
            source="nginx",
            service="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
        state,
    )

    assert len(findings) == 1
    assert findings[0].finding_type == "suspicious_web_probe"


def test_web_probe_followed_by_auth_activity_generates_finding() -> None:
    """Suspicious web probe plus auth activity should correlate."""
    state = DetectionState()
    ip = "185.10.10.1"

    process_event(
        make_event(
            event_type="nginx_suspicious_request",
            src_ip=ip,
            source="nginx",
            service="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
        state,
    )
    findings = process_event(
        make_event("ssh_failed_login", ip, "admin"),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "web_probe_followed_by_auth_activity" in finding_types


def test_web_probe_followed_by_fail2ban_ban_generates_finding() -> None:
    """Suspicious web probe plus later ban should correlate."""
    state = DetectionState()
    ip = "185.10.10.1"

    process_event(
        make_event(
            event_type="nginx_suspicious_request",
            src_ip=ip,
            source="nginx",
            service="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
        state,
    )
    findings = process_event(
        make_event(
            event_type="fail2ban_ban",
            src_ip=ip,
            source="fail2ban",
            service="sshd",
            action="ban",
            jail="actions",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "web_probe_followed_by_fail2ban_ban" in finding_types


def test_multi_source_ip_activity_generates_finding() -> None:
    """IP seen in nginx, auth, and fail2ban should trigger high finding."""
    state = DetectionState()
    ip = "185.10.10.1"

    process_event(
        make_event(
            event_type="nginx_suspicious_request",
            src_ip=ip,
            source="nginx",
            service="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
        state,
    )
    process_event(make_event("ssh_failed_login", ip, "admin"), state)
    findings = process_event(
        make_event(
            event_type="fail2ban_ban",
            src_ip=ip,
            source="fail2ban",
            service="sshd",
            action="ban",
            jail="actions",
        ),
        state,
    )

    finding_types = {finding.finding_type for finding in findings}
    assert "multi_source_ip_activity" in finding_types