from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any


class JsonFileStore:
    """Small JSON helper for MVP file-backed repositories."""

    def __init__(self, path: str | Path, default_data: Any) -> None:
        self._path = Path(path)
        self._default_data = default_data

    def read(self) -> Any:
        if not self._path.exists():
            return deepcopy(self._default_data)
        with self._path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    def write(self, data: Any) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = self._path.with_suffix(f"{self._path.suffix}.tmp")
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2, sort_keys=True)
            handle.write("\n")
        temp_path.replace(self._path)
