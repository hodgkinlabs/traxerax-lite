"""Tests for report generation from SQLite data."""

from datetime import datetime

from traxerax_lite.config import ReportSettings
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
            event_type="fail2ban_unban",
            raw="unban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="unban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 5, 1),
            source="nginx",
            event_type="nginx_request",
            raw="return1",
            src_ip="185.10.10.1",
            service="nginx",
            process="nginx",
            method="GET",
            path="/404",
            status_code=404,
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 6, 1),
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
    assert "reporting_window:" in report
    assert "bottom_line_assessment:" in report
    assert "top_risky_source_ips:" in report
    assert "incident_queue:" in report
    assert "top_noisy_source_ips:" in report
    assert "repeat_banned_ips:" in report
    assert "returned_after_ban_ips:" in report
    assert "persistent_multi_source_ips:" in report
    assert "root_attempt_ips_with_repeat_activity:" in report
    assert "185.10.10.1" in report
    assert "returns=1" in report
    assert "first_return_after=" in report

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
            source="fail2ban",
            event_type="fail2ban_unban",
            raw="unban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="unban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 5, 1),
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
    assert "incident_groups:" in report
    assert "active_window:" in report
    assert "source_count: 2" in report
    assert "ban_count: 1" in report
    assert "root_attempt_count: 1" in report
    assert "auth_event_count: 3" in report
    assert "post_ban_return_count: 1" in report
    assert "repeat_banned: no" in report
    assert "returned_after_ban: yes" in report
    assert "persistent_multi_source: yes" in report
    assert "root_attempt_from_repeat_ip: yes" in report
    assert "nginx_error_status_counts:" in report
    assert "404: 1" in report

    connection.close()


def test_build_summary_report_respects_configurable_limits_and_cutoffs() -> None:
    """Summary report should use configurable ranking and persistence settings."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    dataset = [
        ("203.0.113.10", 1, False),
        ("203.0.113.11", 2, False),
        ("203.0.113.12", 3, True),
    ]
    for index, (src_ip, auth_count, include_return) in enumerate(dataset, start=1):
        for event_number in range(auth_count):
            insert_event(
                connection,
                Event(
                    timestamp=datetime(2026, 3, 25, 10, index, event_number),
                    source="auth",
                    event_type="ssh_failed_login",
                    raw=f"auth-{src_ip}-{event_number}",
                    src_ip=src_ip,
                    service="ssh",
                    process="sshd",
                ),
            )

        insert_event(
            connection,
            Event(
                timestamp=datetime(2026, 3, 25, 10, index, 10),
                source="nginx",
                event_type="nginx_suspicious_request",
                raw=f"probe-{src_ip}",
                src_ip=src_ip,
                service="nginx",
                process="nginx",
                method="GET",
                path="/wp-login.php",
                status_code=404,
            ),
        )
        insert_event(
            connection,
            Event(
                timestamp=datetime(2026, 3, 25, 10, index, 20),
                source="fail2ban",
                event_type="fail2ban_ban",
                raw=f"ban-{src_ip}",
                src_ip=src_ip,
                service="sshd",
                process="fail2ban",
                action="ban",
                jail="actions",
            ),
        )
        if include_return:
            insert_event(
                connection,
                Event(
                    timestamp=datetime(2026, 3, 25, 10, index, 30),
                    source="fail2ban",
                    event_type="fail2ban_unban",
                    raw=f"unban-{src_ip}",
                    src_ip=src_ip,
                    service="sshd",
                    process="fail2ban",
                    action="unban",
                    jail="actions",
                ),
            )
            insert_event(
                connection,
                Event(
                    timestamp=datetime(2026, 3, 25, 10, index, 40),
                    source="nginx",
                    event_type="nginx_request",
                    raw=f"return-{src_ip}",
                    src_ip=src_ip,
                    service="nginx",
                    process="nginx",
                    method="GET",
                    path="/404",
                    status_code=404,
                ),
            )

        for finding_number in range(index):
            insert_finding(
                connection,
                Finding(
                    finding_type="multi_source_ip_activity",
                    severity="high",
                    message=(
                        f"Multi-source activity for {src_ip} "
                        f"#{finding_number}"
                    ),
                    src_ip=src_ip,
                    timestamp=datetime(2026, 3, 25, 10, index, 50 + finding_number),
                ),
            )

    report = build_summary_report(
        connection,
        ReportSettings(
            top_noisy_source_ips_limit=2,
            top_risky_source_ips_limit=2,
            persistent_multi_source_min_total_events=5,
            root_attempt_repeat_min_auth_events=3,
            returned_after_ban_min_returns=2,
        ),
    )

    top_noisy_section = report.split("top_noisy_source_ips:\n", 1)[1].split(
        "\n\nauth_ips_with_enforcement:",
        1,
    )[0]

    assert "203.0.113.10" not in top_noisy_section
    assert "203.0.113.11: events=3" in top_noisy_section
    assert "203.0.113.12: events=5" in top_noisy_section
    assert "returned_after_ban_ips:\n  - none" in report
    assert "persistent_multi_source_ips:" in report
    assert "203.0.113.12: events=5 sources=2" in report
    assert "203.0.113.11: events=3 sources=2" not in report

    connection.close()


def test_build_summary_report_prioritizes_incidents_from_configured_weights() -> None:
    """Incident scoring should reorder summary priorities based on config."""
    connection = get_connection(":memory:")
    initialize_database(connection)

    risky_ip = "203.0.113.10"
    noisy_ip = "203.0.113.11"

    for second in range(3):
        insert_event(
            connection,
            Event(
                timestamp=datetime(2026, 3, 25, 10, 0, second),
                source="auth",
                event_type="ssh_failed_login",
                raw=f"auth-risk-{second}",
                src_ip=risky_ip,
                service="ssh",
                process="sshd",
            ),
        )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 10),
            source="auth",
            event_type="ssh_root_login_attempt",
            raw="root-risk",
            src_ip=risky_ip,
            username="root",
            service="ssh",
            process="sshd",
        ),
    )
    insert_event(
        connection,
        Event(
            timestamp=datetime(2026, 3, 25, 10, 0, 20),
            source="fail2ban",
            event_type="fail2ban_ban",
            raw="ban-risk",
            src_ip=risky_ip,
            service="sshd",
            process="fail2ban",
            action="ban",
            jail="actions",
        ),
    )
    insert_finding(
        connection,
        Finding(
            finding_type="success_after_failures",
            severity="high",
            message="High severity auth compromise signal",
            src_ip=risky_ip,
            timestamp=datetime(2026, 3, 25, 10, 0, 30),
        ),
    )

    for second in range(8):
        insert_event(
            connection,
            Event(
                timestamp=datetime(2026, 3, 25, 11, 0, second),
                source="nginx",
                event_type="nginx_request",
                raw=f"nginx-noisy-{second}",
                src_ip=noisy_ip,
                service="nginx",
                process="nginx",
                method="GET",
                path="/missing",
                status_code=404,
            ),
        )
    insert_finding(
        connection,
        Finding(
            finding_type="repeated_http_error_responses",
            severity="low",
            message="Low severity noisy scanning",
            src_ip=noisy_ip,
            timestamp=datetime(2026, 3, 25, 11, 0, 20),
        ),
    )

    report = build_summary_report(
        connection,
        ReportSettings(
            top_risky_source_ips_limit=2,
            priority_weight_total_events=0,
            priority_weight_ban_count=1,
            priority_weight_root_attempt_repeat_ip=5,
            priority_severity_weights={
                "low": 1,
                "medium": 2,
                "high": 6,
                "critical": 10,
            },
        ),
    )

    priority_section = report.split("top_risky_source_ips:\n", 1)[1].split(
        "\n\ntop_noisy_source_ips:",
        1,
    )[0]
    priority_lines = [
        line.strip()
        for line in priority_section.splitlines()
        if line.strip().startswith("- ")
    ]

    assert priority_lines
    assert risky_ip in priority_lines[0]
    assert "score=" in priority_lines[0]
    assert "highx1" in priority_lines[0]
    assert "bans=1" in priority_lines[0]

    connection.close()


def test_build_summary_report_can_disable_priority_incidents_section() -> None:
    """Priority incidents section should be suppressible from config."""
    connection = get_connection(":memory:")
    initialize_database(connection)

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

    report = build_summary_report(
        connection,
        ReportSettings(priority_incidents_enabled=False),
    )

    assert "top_risky_source_ips:\n  - none" in report

    connection.close()


def test_build_ip_report_respects_configurable_persistence_flags() -> None:
    """IP report flags should reflect report-specific config thresholds."""
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
            source="fail2ban",
            event_type="fail2ban_unban",
            raw="unban1",
            src_ip="185.10.10.1",
            service="sshd",
            process="fail2ban",
            action="unban",
            jail="actions",
        ),
        Event(
            timestamp=datetime(2026, 3, 25, 10, 5, 1),
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

    report = build_ip_report(
        connection,
        "185.10.10.1",
        ReportSettings(
            repeat_banned_min_bans=1,
            persistent_multi_source_min_total_events=10,
            root_attempt_repeat_min_auth_events=4,
            returned_after_ban_min_returns=2,
        ),
    )

    assert "repeat_banned: yes" in report
    assert "returned_after_ban: no" in report
    assert "persistent_multi_source: no" in report
    assert "root_attempt_from_repeat_ip: no" in report

    connection.close()
