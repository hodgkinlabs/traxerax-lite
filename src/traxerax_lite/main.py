"""Main entry point."""

from traxerax_lite.cli import build_parser
from traxerax_lite.collector import read_lines
from traxerax_lite.parser import parse_auth_line


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    count = 0

    for line in read_lines(args.auth_log):
        event = parse_auth_line(line, year=args.year)
        if not event:
            continue

        count += 1
        print(event)

    print(f"\nParsed {count} events.")


if __name__ == "__main__":
    main()