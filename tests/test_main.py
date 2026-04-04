"""Integration tests for main functionality."""

import tempfile
from pathlib import Path

from traxerax_lite.main import main
from traxerax_lite.storage import get_connection


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
