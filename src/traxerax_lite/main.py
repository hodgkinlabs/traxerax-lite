"""Main entry point."""

from traxerax_lite.cli import build_parser
from traxerax_lite.collector import read_lines
from traxerax_lite.detector import DetectionState, process_event
from traxerax_lite.parser import parse_auth_line
from traxerax_lite.reporter import format_event, format_finding
from traxerax_lite.storage import (
    get_connection,
    initialize_database,
    insert_event,
    insert_finding,
)


def main() -> None:
    """Run the application."""
    parser = build_parser()
    args = parser.parse_args()

    state = DetectionState()
    parsed_count = 0
    finding_count = 0

    connection = get_connection()
    initialize_database(connection)

    try:
        for line in read_lines(args.auth_log):
            event = parse_auth_line(line, year=args.year)
            if event is None:
                continue

            parsed_count += 1
            print(format_event(event))
            insert_event(connection, event)

            findings = process_event(event, state)
            for finding in findings:
                finding_count += 1
                print(format_finding(finding))
                insert_finding(connection, finding)

        print("\n[SUMMARY]")
        print(f"parsed_events={parsed_count}")
        print(f"generated_findings={finding_count}")
        print("database=data/output/traxerax_lite.db")
    finally:
        connection.close()


if __name__ == "__main__":
    main()