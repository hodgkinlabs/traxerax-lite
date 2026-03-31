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
    assert findings[0].src_ip == "185.10.10.1"


def test_repeated_failed_login_triggers_once_at_threshold() -> None:
    """Repeated failed login finding should trigger once per IP."""
    state = DetectionState()
    ip = "185.10.10.1"

    event1 = make_event("ssh_failed_login", ip, "admin")
    event2 = make_event("ssh_root_login_attempt", ip, "root")
    event3 = make_event("ssh_failed_login", ip, "test")
    event4 = make_event("ssh_failed_login", ip, "guest")

    findings1 = process_event(event1, state)
    findings2 = process_event(event2, state)
    findings3 = process_event(event3, state)
    findings4 = process_event(event4, state)

    assert len(findings1) == 0

    assert len(findings2) == 1
    assert findings2[0].finding_type == "root_login_attempt"

    assert len(findings3) == 1
    assert findings3[0].finding_type == "repeated_failed_login"

    assert len(findings4) == 0


def test_success_after_failures_generates_finding() -> None:
    """A success after prior failures from same IP should trigger."""
    state = DetectionState()
    ip = "203.0.113.77"

    failure_event = make_event("ssh_failed_login", ip, "user1")
    success_event = make_event("ssh_success_login", ip, "user1")

    process_event(failure_event, state)
    findings = process_event(success_event, state)

    assert len(findings) == 1
    assert findings[0].finding_type == "success_after_failures"
    assert findings[0].severity == "high"
    assert findings[0].src_ip == ip


def test_success_without_failures_generates_no_finding() -> None:
    """A clean success with no prior failures should not trigger."""
    state = DetectionState()
    event = make_event("ssh_success_login", "198.51.100.20", "user1")

    findings = process_event(event, state)

    assert findings == []


def test_fail2ban_ban_after_auth_activity_generates_finding() -> None:
    """A fail2ban ban after auth activity should generate correlation."""
    state = DetectionState()
    ip = "185.10.10.1"

    auth_event = make_event("ssh_failed_login", ip, "admin")
    ban_event = make_event(
        event_type="fail2ban_ban",
        src_ip=ip,
        source="fail2ban",
        service="sshd",
        action="ban",
        jail="actions",
    )

    process_event(auth_event, state)
    findings = process_event(ban_event, state)

    assert len(findings) == 1
    assert findings[0].finding_type == "ip_banned_after_auth_activity"
    assert findings[0].severity == "medium"
    assert findings[0].src_ip == ip


def test_fail2ban_ban_without_auth_activity_generates_no_finding() -> None:
    """A ban with no prior auth activity should not create correlation."""
    state = DetectionState()

    ban_event = make_event(
        event_type="fail2ban_ban",
        src_ip="198.51.100.20",
        source="fail2ban",
        service="sshd",
        action="ban",
        jail="actions",
    )

    findings = process_event(ban_event, state)

    assert findings == []


def test_fail2ban_ban_correlation_triggers_once_per_ip() -> None:
    """Correlation finding should only trigger once for a banned IP."""
    state = DetectionState()
    ip = "185.10.10.1"

    auth_event = make_event("ssh_failed_login", ip, "admin")
    ban_event_1 = make_event(
        event_type="fail2ban_ban",
        src_ip=ip,
        source="fail2ban",
        service="sshd",
        action="ban",
        jail="actions",
    )
    ban_event_2 = make_event(
        event_type="fail2ban_ban",
        src_ip=ip,
        source="fail2ban",
        service="sshd",
        action="ban",
        jail="actions",
    )

    process_event(auth_event, state)
    findings_1 = process_event(ban_event_1, state)
    findings_2 = process_event(ban_event_2, state)

    assert len(findings_1) == 1
    assert findings_1[0].finding_type == "ip_banned_after_auth_activity"
    assert findings_2 == []


def test_suspicious_nginx_request_generates_finding() -> None:
    """Suspicious nginx probe should create a finding."""
    state = DetectionState()
    event = make_event(
        event_type="nginx_suspicious_request",
        src_ip="185.10.10.1",
        source="nginx",
        service="nginx",
        method="GET",
        path="/wp-login.php",
        status_code=404,
    )

    findings = process_event(event, state)

    assert len(findings) == 1
    assert findings[0].finding_type == "suspicious_web_probe"
    assert findings[0].src_ip == "185.10.10.1"


def test_suspicious_nginx_probe_triggers_once_per_ip() -> None:
    """Suspicious web probe finding should only trigger once per IP."""
    state = DetectionState()
    event1 = make_event(
        event_type="nginx_suspicious_request",
        src_ip="185.10.10.1",
        source="nginx",
        service="nginx",
        method="GET",
        path="/wp-login.php",
        status_code=404,
    )
    event2 = make_event(
        event_type="nginx_suspicious_request",
        src_ip="185.10.10.1",
        source="nginx",
        service="nginx",
        method="GET",
        path="/xmlrpc.php",
        status_code=404,
    )

    findings1 = process_event(event1, state)
    findings2 = process_event(event2, state)

    assert len(findings1) == 1
    assert findings1[0].finding_type == "suspicious_web_probe"
    assert findings2 == []