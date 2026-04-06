"""Tests for terminal output formatting."""

from datetime import datetime

from traxerax_lite.models import EnforcementAction, Event, Finding
from traxerax_lite.reporter import (
    format_enforcement_action,
    format_event,
    format_finding,
)


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
    assert "source=auth" in output
    assert "type=ssh_success_login" in output
    assert "ip=203.0.113.77" in output
    assert "user=user1" in output
    assert "host=debian" in output
    assert "process=sshd" in output
    assert "service=ssh" in output
    assert "action=-" in output
    assert "jail=-" in output
    assert "method=-" in output
    assert "path=-" in output
    assert "status=-" in output


def test_format_enforcement_action_includes_action_and_jail() -> None:
    """Formatted enforcement output should show action and jail values."""
    action = EnforcementAction(
        timestamp=datetime(2026, 3, 25, 10, 0, 8),
        raw="test raw line",
        src_ip="185.10.10.1",
        service="sshd",
        process="fail2ban",
        action="ban",
        jail="actions",
    )

    output = format_enforcement_action(action)

    assert "[ENFORCEMENT]" in output
    assert "service=sshd" in output
    assert "action=ban" in output
    assert "jail=actions" in output


def test_format_nginx_event_includes_method_path_and_status() -> None:
    """Formatted nginx events should show method, path, and status."""
    event = Event(
        timestamp=datetime(2026, 3, 25, 10, 0, 4),
        source="nginx",
        event_type="nginx_suspicious_request",
        raw="test nginx line",
        src_ip="185.10.10.1",
        service="nginx",
        process="nginx",
        method="GET",
        path="/wp-login.php",
        status_code=404,
    )

    output = format_event(event)

    assert "source=nginx" in output
    assert "type=nginx_suspicious_request" in output
    assert "method=GET" in output
    assert "path=/wp-login.php" in output
    assert "status=404" in output


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
    assert "type=success_after_failures" in output
    assert "ip=203.0.113.77" in output
    assert (
        "message=Successful SSH login after prior failures from "
        "203.0.113.77 (1 failures before success)"
    ) in output
