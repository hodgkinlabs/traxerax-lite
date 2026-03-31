"""Tests for report generation from SQLite data."""

from datetime import datetime

from traxerax_lite.models import Event, Finding
from traxerax_lite.report_queries import build_summary_report
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_event,
    insert_finding,
)


def test_build_summary_report_includes_core_sections() -> None:
    """Summary report should include expected sections and values."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_failed_login",
            raw="raw1",
            src_ip="185.10.10.1",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 8),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="raw2",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="ip_banned_after_auth_activity",
            severity="medium",
            message="Correlation finding",
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 8),
        ),
    )

    report = build_summary_report(connection)

    assert "[REPORT] summary" in report
    assert "event_counts_by_type:" in report
    assert "finding_counts_by_type:" in report
    assert "top_event_source_ips:" in report
    assert "top_finding_source_ips:" in report
    assert "ssh_failed_login: 1" in report
    assert "fail2ban_ban: 1" in report
    assert "ip_banned_after_auth_activity: 1" in report
    assert "185.10.10.1: 2" in report or "185.10.10.1: 1" in report

    connection.close()