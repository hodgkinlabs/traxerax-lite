"""Tests for terminal output formatting."""

from datetime import datetime

from traxerax_lite.models import Event, Finding
from traxerax_lite.reporter import format_event, format_finding


def test_format_event_includes_core_fields() -> None:
    """Formatted event output should include key event details."""
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="auth",
        event_type="ssh_success_login",
        raw="test raw line",
        username="user1",
        src_ip="203.0.113.77",
        port=50001,
        service="ssh",
        hostname="debian",
        process="sshd",
    )

    output = format_event(event)

    assert "[EVENT]" in output
    assert "2026-03-25 10:01:20" in output
    assert "source=auth" in output
    assert "type=ssh_success_login" in output
    assert "ip=203.0.113.77" in output
    assert "user=user1" in output
    assert "host=debian" in output
    assert "process=sshd" in output
    assert "service=ssh" in output
    assert "action=-" in output
    assert "jail=-" in output


def test_format_event_uses_dash_for_missing_optional_fields() -> None:
    """Formatted event output should use dashes for missing values."""
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
        source="auth",
        event_type="ssh_failed_login",
        raw="test raw line",
        username=None,
        src_ip=None,
        port=None,
        service=None,
        hostname=None,
        process=None,
        action=None,
        jail=None,
    )

    output = format_event(event)

    assert "[EVENT]" in output
    assert "ip=-" in output
    assert "user=-" in output
    assert "host=-" in output
    assert "process=-" in output
    assert "service=-" in output
    assert "action=-" in output
    assert "jail=-" in output


def test_format_fail2ban_event_includes_action_and_jail() -> None:
    """Formatted fail2ban events should show action and jail values."""
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 0, 8),
        source="fail2ban",
        event_type="fail2ban_ban",
        raw="test raw line",
        src_ip="185.10.10.1",
        service="sshd",
        process="fail2ban",
        action="ban",
        jail="actions",
    )

    output = format_event(event)

    assert "source=fail2ban" in output
    assert "type=fail2ban_ban" in output
    assert "service=sshd" in output
    assert "action=ban" in output
    assert "jail=actions" in output


def test_format_finding_includes_core_fields() -> None:
    """Formatted finding output should include key finding details."""
    finding = Finding(
        finding_type="success_after_failures",
        severity="high",
        message=(
            "Successful SSH login after prior failures from "
            "203.0.113.77 (1 failures before success)"
        ),
        src_ip="203.0.113.77",
        timestamp=datetime(2026, 3, 25, 10, 1, 20),
    )

    output = format_finding(finding)

    assert "[FINDING][HIGH]" in output
    assert "2026-03-25 10:01:20" in output
    assert "type=success_after_failures" in output
    assert "ip=203.0.113.77" in output
    assert (
        "message=Successful SSH login after prior failures from "
        "203.0.113.77 (1 failures before success)"
    ) in output


def test_format_finding_uses_dash_for_missing_ip() -> None:
    """Formatted finding output should use dash when IP is missing."""
    finding = Finding(
        finding_type="root_login_attempt",
        severity="medium",
        message="Root login attempt detected from unknown source",
        src_ip=None,
        timestamp=datetime(2026, 3, 25, 10, 0, 5),
    )

    output = format_finding(finding)

    assert "[FINDING][MEDIUM]" in output
    assert "ip=-" in output