"""Small JSON persistence helper for file-backed adapters.

Repositories use this helper to load/write JSON atomically without duplicating
file handling code in every adapter.
"""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any


class JsonFileStore:
    """Small JSON helper for MVP file-backed repositories.

    Example:
        store = JsonFileStore("data/runtime/profiles.json", {"profiles": {}})
    """

    def __init__(self, path: str | Path, default_data: Any) -> None:
        self._path = Path(path)
        self._default_data = default_data
        self._ensure_exists()

    def read(self) -> Any:
        self._ensure_exists()
        with self._path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def write(self, data: Any) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._path.with_suffix(f"{self._path.suffix}.tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        temp_path.replace(self._path)

    def _ensure_exists(self) -> None:
        """Create a missing JSON file with its repository default shape."""
        if self._path.exists():
            return
        self.write(deepcopy(self._default_data))
