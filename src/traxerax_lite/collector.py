"""Log collection utilities."""

from pathlib import Path
from typing import Iterator


def read_lines(path: str) -> Iterator[str]:
    """Yield lines from file."""
    file_path = Path(path)

    with file_path.open("r", encoding="utf-8") as f:
        for line in f:
            yield line.rstrip("\n")