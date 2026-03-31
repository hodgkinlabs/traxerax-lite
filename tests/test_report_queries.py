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


def test_build_summary_report_includes_core_sections() -> None:
    """Summary report should include expected sections and values."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 1),
            source="auth",
            event_type="ssh_root_login_attempt",
            raw="root-attempt",
            src_ip="185.10.10.1",
            username="root",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 2),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban-event",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 4),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="nginx-event",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
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
    assert "cross_source_ips:" in report
    assert "root_attempts_followed_by_ban:" in report
    assert "top_ips_by_finding_count:" in report
    assert "nginx_suspicious_request: 1" in report
    assert "185.10.10.1" in report

    connection.close()


def test_build_ip_report_includes_nginx_timeline_fields() -> None:
    """IP report should include nginx timeline fields when present."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 4),
            source="nginx",
            event_type="nginx_suspicious_request",
            raw="nginx-event",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/wp-login.php",
            status_code=404,
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="suspicious_web_probe",
            severity="medium",
            message=(
                "Suspicious web probe detected from "
                "185.10.10.1 path=/wp-login.php"
            ),
            src_ip="185.10.10.1",
            timestamp=datetime(2026, 3, 25, 10, 0, 4),
        ),
    )

    report = build_ip_report(connection, "185.10.10.1")

    assert "[REPORT] ip=185.10.10.1" in report
    assert "source=nginx type=nginx_suspicious_request" in report
    assert "method=GET" in report
    assert "path=/wp-login.php" in report
    assert "status=404" in report
    assert "MEDIUM suspicious_web_probe" in report

    connection.close()