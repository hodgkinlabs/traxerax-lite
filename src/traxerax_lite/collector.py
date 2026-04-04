"""Log collection utilities."""

from pathlib import Path
from typing import Iterator


def read_lines(path: str) -> Iterator[str]:
    """Yield lines from file."""
    file_path = Path(path)

    try:
        with file_path.open("r", encoding="utf-8") as f:
            for line in f:
                yield line.rstrip("\n")
    except FileNotFoundError:
        raise FileNotFoundError(f"Log file not found: {path}")
    except PermissionError:
        raise PermissionError(f"Permission denied reading log file: {path}")
    except OSError as e:
        raise OSError(f"Error reading log file {path}: {e}")