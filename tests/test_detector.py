"""Tests for detection logic."""

from traxerax_lite.detector import DetectionState, process_event
from traxerax_lite.models import Event

from datetime import datetime


def make_event(
    event_type: str,
    src_ip: str,
    username: str,
) -> Event:
    """Build a minimal Event for detector tests."""
    return Event(
        timestamp=datetime(2026, 3, 25, 10, 0, 0),
        source="auth",
        event_type=event_type,
        raw="test raw line",
        username=username,
        src_ip=src_ip,
        port=22,
        service="ssh",
        hostname="debian",
        process="sshd",
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