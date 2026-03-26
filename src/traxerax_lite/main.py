"""Main entry point."""

from traxerax_lite.cli import build_parser
from traxerax_lite.collector import read_lines
from traxerax_lite.detector import DetectionState, process_event
from traxerax_lite.parser import parse_auth_line


def main() -> None:
    """Run the application."""
    parser = build_parser()
    args = parser.parse_args()

    state = DetectionState()
    parsed_count = 0
    finding_count = 0

    for line in read_lines(args.auth_log):
        event = parse_auth_line(line, year=args.year)
        if event is None:
            continue

        parsed_count += 1
        print(f"EVENT: {event}")

        findings = process_event(event, state)
        for finding in findings:
            finding_count += 1
            print(f"FINDING: {finding}")

    print(f"\nParsed {parsed_count} events.")
    print(f"Generated {finding_count} findings.")


if __name__ == "__main__":
    main()