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
        "--mail-log",
        help="Path to mail auth log file",
    )

    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Optional year override for syslog-style timestamps",
    )

    parser.add_argument(
        "--report",
        choices=["summary", "ip", "hunt"],
        help="Generate a report from stored SQLite data",
    )

    parser.add_argument(
        "--ip",
        help="Source IP for per-IP investigation report",
    )

    parser.add_argument(
        "--hunt-preset",
        choices=[
            "new-ips",
            "cross-source",
            "post-ban-returners",
            "auth-success-after-failures",
            "sprayed-users",
            "suspicious-paths",
        ],
        help="Preset report for threat-hunting workflows",
    )

    parser.add_argument(
        "--config",
        default="config/default.yaml",
        help="Path to configuration file",
    )

    parser.add_argument(
        "--db-path",
        default="data/output/traxerax_lite.db",
        help="Path to SQLite database file",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Output in JSON format",
    )

    return parser
