"""CLI interface."""

import argparse


def build_parser() -> argparse.ArgumentParser:
    """Build and return CLI parser."""
    parser = argparse.ArgumentParser(
        description="Replay security logs and parse events",
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
        "--year",
        type=int,
        default=None,
        help="Optional year override for syslog-style timestamps",
    )

    return parser