"""Integration tests for main functionality."""

import tempfile
from datetime import datetime
from pathlib import Path

from traxerax_lite.config import load_config, load_report_settings
from traxerax_lite.models import Event
from traxerax_lite.main import main
from traxerax_lite.report_queries import build_ip_report
from traxerax_lite.storage import get_connection, initialize_database, insert_event


def test_main_processing_with_sample_logs(capsys):
    """Test end-to-end processing with sample logs."""
    # Create temporary files
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"

        # Create minimal config
        config_path.write_text("""
nginx:
  suspicious_paths:
    - "/wp-login.php"
""")

        # Use sample auth log
        sample_auth = Path("sample_logs/auth.log.sample")

        # Mock command line args
        import sys
        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config", str(config_path),
                "--db-path", str(db_path),
                "--auth-log", str(sample_auth),
                "--json"
            ]
            main()
        finally:
            sys.argv = original_argv

        # Check database has data
        conn = get_connection(str(db_path))
        events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        conn.close()

        assert events > 0
        assert findings >= 0  # May be 0 depending on sample data


def test_main_processes_sources_in_timestamp_order() -> None:
    """Cross-source detections should use event timestamps, not file order."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"
        fail2ban_log = Path(tmpdir) / "fail2ban.log"
        nginx_log = Path(tmpdir) / "nginx.log"

        config_path.write_text(
            """
nginx:
  suspicious_paths:
    - "/xmlrpc.php"
"""
        )
        fail2ban_log.write_text(
            "2026-03-25 10:00:01,000 fail2ban.actions        [3001]: NOTICE  [nginx-badbots] Ban 185.10.10.1\n"
        )
        nginx_log.write_text(
            '185.10.10.1 - - [25/Mar/2026:10:00:02 -0700] "GET /xmlrpc.php HTTP/1.1" 404 144 "-" "Mozilla/5.0"\n'
        )

        import sys

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config",
                str(config_path),
                "--db-path",
                str(db_path),
                "--fail2ban-log",
                str(fail2ban_log),
                "--nginx-log",
                str(nginx_log),
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        findings = conn.execute(
            """
            SELECT finding_type
            FROM findings
            ORDER BY timestamp ASC, id ASC
            """
        ).fetchall()
        conn.close()

        finding_types = {row[0] for row in findings}
        assert "web_probe_followed_by_fail2ban_ban" not in finding_types


def test_main_uses_detection_thresholds_and_severities_from_config() -> None:
    """Configured detection settings should affect persisted findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"
        auth_log = Path(tmpdir) / "auth.log"

        config_path.write_text(
            """
detection:
  thresholds:
    auth_failed_login: 2
  severities:
    repeated_failed_login: low
nginx:
  suspicious_paths:
    - "/wp-login.php"
"""
        )
        auth_log.write_text(
            "\n".join(
                [
                    (
                        "Mar 25 10:00:01 debian sshd[2001]: Failed password for "
                        "invalid user admin from 185.10.10.1 port 40001 ssh2"
                    ),
                    (
                        "Mar 25 10:00:02 debian sshd[2002]: Failed password for "
                        "invalid user test from 185.10.10.1 port 40002 ssh2"
                    ),
                ]
            )
            + "\n"
        )

        import sys

        original_argv = sys.argv
        try:
            sys.argv = [
                "main.py",
                "--config",
                str(config_path),
                "--db-path",
                str(db_path),
                "--auth-log",
                str(auth_log),
                "--year",
                "2026",
            ]
            main()
        finally:
            sys.argv = original_argv

        conn = get_connection(str(db_path))
        finding = conn.execute(
            """
            SELECT finding_type, severity
            FROM findings
            WHERE finding_type = 'repeated_failed_login'
            """
        ).fetchone()
        conn.close()

        assert finding is not None
        assert finding[1] == "low"


def test_reporting_settings_loaded_from_config_affect_ip_report() -> None:
    """Loaded reporting settings should affect generated IP report output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        config_path = Path(tmpdir) / "config.yaml"

        config_path.write_text(
            """
reporting:
  persistence:
    repeat_banned_min_bans: 1
nginx:
  suspicious_paths:
    - "/wp-login.php"
"""
        )

        conn = get_connection(str(db_path))
        initialize_database(conn)
        insert_event(
            conn,
            Event(
                timestamp=datetime(2026, 3, 25, 10, 0, 1),
                source="auth",
                event_type="ssh_failed_login",
                raw="auth1",
                src_ip="185.10.10.1",
                service="ssh",
                process="sshd",
            ),
        )
        insert_event(
            conn,
            Event(
                timestamp=datetime(2026, 3, 25, 10, 1, 1),
                source="fail2ban",
                event_type="fail2ban_ban",
                raw="ban1",
                src_ip="185.10.10.1",
                service="sshd",
                process="fail2ban",
                action="ban",
                jail="actions",
            ),
        )
        conn.close()

        settings = load_report_settings(load_config(str(config_path)))

        conn = get_connection(str(db_path))
        report = build_ip_report(conn, "185.10.10.1", settings)
        conn.close()

        assert "repeat_banned: yes" in report
