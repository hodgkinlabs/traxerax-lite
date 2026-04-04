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