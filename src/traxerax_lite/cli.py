"""CLI interface."""

import argparse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Replay auth logs and parse events"
    )

    parser.add_argument(
        "--auth-log",
        required=True,
        help="Path to auth log file",
    )

    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Optional year override",
    )

    return parser