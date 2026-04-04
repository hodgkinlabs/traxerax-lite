"""Configuration loading."""

import yaml
from pathlib import Path
from typing import Any


DEFAULT_CONFIG_PATH = "config/default.yaml"


def load_config(path: str = DEFAULT_CONFIG_PATH) -> dict[str, Any]:
    """Load YAML config file."""
    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config not found: {path}")

    with config_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)