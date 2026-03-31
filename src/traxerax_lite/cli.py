"""CLI interface."""

import argparse


def build_parser() -> argparse.ArgumentParser:
    """Build and return CLI parser."""
    parser = argparse.ArgumentParser(
        description="Replay security logs and generate reports",
    )

    parser.add_argument(
        "--auth-log",
        help="Path to auth log file",
    )

    parser.add_argument(
        "--fail2ban-log",
        help="Path to fail2ban log file",
    )

    parser.add_argument(
        "--nginx-log",
        help="Path to nginx access log file",
    )

    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Optional year override for syslog-style timestamps",
    )

    parser.add_argument(
        "--report",
        choices=["summary", "ip"],
        help="Generate a report from stored SQLite data",
    )

    parser.add_argument(
        "--ip",
        help="Source IP for per-IP investigation report",
    )

    parser.add_argument(
        "--db-path",
        default="data/output/traxerax_lite.db",
        help="Path to SQLite database file",
    )

    return parser