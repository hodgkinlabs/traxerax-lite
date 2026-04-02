"""Tests for report generation from SQLite data."""

from datetime import datetime

from traxerax_lite.models import Event, Finding
from traxerax_lite.report_queries import build_ip_report, build_summary_report
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_event,
    insert_finding,
)


def test_build_summary_report_includes_persistence_sections() -> None:
    """Summary report should include new persistence-oriented sections."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    events = [
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="probe1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 1, 1),
            source="auth",
            event_type="ssh_root_login_attempt",
            raw="auth1",
            src_ip="185.10.10.1",
            username="root",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 2, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth2",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 3, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 4, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban2",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    ]
    for event in events:
        insert_event(connection, event)

    insert_finding(
        connection,
        Finding(
            finding_type="multi_source_ip_activity",
            severity="high",
            message="Appeared across three sources",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 3, 1),
        ),
    )

    report = build_summary_report(connection)

    assert "[REPORT] summary" in report
    assert "repeat_banned_ips:" in report
    assert "returned_after_ban_ips:" in report
    assert "persistent_multi_source_ips:" in report
    assert "root_attempt_ips_with_repeat_activity:" in report
    assert "185.10.10.1" in report

    connection.close()


def test_build_ip_report_includes_persistence_flags() -> None:
    """IP report should include persistence flags and related counts."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    events = [
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 1, 1),
            source="auth",
            event_type="ssh_root_login_attempt",
            raw="auth2",
            src_ip="185.10.10.1",
            username="root",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 2, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="auth3",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 3, 1),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 4, 1),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="probe1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
    ]
    for event in events:
        insert_event(connection, event)

    insert_finding(
        connection,
        Finding(
            finding_type="root_login_attempt",
            severity="medium",
            message="Root login attempt",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 1, 1),
        ),
    )

    report = build_ip_report(connection, "185.10.10.1")

    assert "[REPORT] ip=185.10.10.1" in report
    assert "persistence_flags:" in report
    assert "source_count: 3" in report
    assert "ban_count: 1" in report
    assert "root_attempt_count: 1" in report
    assert "auth_event_count: 3" in report
    assert "repeat_banned: no" in report
    assert "returned_after_ban: yes" in report
    assert "persistent_multi_source: yes" in report
    assert "root_attempt_from_repeat_ip: yes" in report

    connection.close()