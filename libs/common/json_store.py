"""Small JSON persistence helper for file-backed adapters.

Repositories use this helper to load/write JSON atomically without duplicating
file handling code in every adapter.
"""

from __future__ import annotations

import json
import tempfile
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
        """Read the current JSON payload, creating the default file if missing.

        Example:
            JsonFileStore("bindings.json", {"records": []}).read() -> {"records": []}
        """
        self._ensure_exists()
        with self._path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def write(self, data: Any) -> None:
        """Atomically replace the JSON file with a readable payload.

        Example:
            write({"records": []}) creates a temporary file, chmods it 0644, then renames it over the target so readers never see partial JSON.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, raw_temp_path = tempfile.mkstemp(
            dir=self._path.parent,
            prefix=f".{self._path.name}.",
            suffix=".tmp",
            text=True,
        )
        temp_path = Path(raw_temp_path)
        try:
            with open(fd, "w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2, sort_keys=True)
                handle.write("\n")
            temp_path.chmod(0o644)
            temp_path.replace(self._path)
        finally:
            temp_path.unlink(missing_ok=True)

    def _ensure_exists(self) -> None:
        """Create a missing JSON file with its repository default shape."""
        if self._path.exists():
            return
        self.write(deepcopy(self._default_data))
