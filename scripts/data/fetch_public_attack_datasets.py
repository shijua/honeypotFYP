#!/usr/bin/env python3
"""Download the CasinoLimit ATT&CK-labelled dataset files for validation work.

These are validation datasets only; the runtime prior is built from the local
Enterprise ATT&CK STIX bundle.

Example:
    python scripts/data/fetch_public_attack_datasets.py
"""

from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Iterable


ZENODO_CASINOLIMIT_API = "https://zenodo.org/api/records/17256954"
DEFAULT_CASINOLIMIT_FILES = ("syslogs_labels.zip", "output.zip")


def main() -> int:
    """Fetch selected public dataset files and print a JSON summary."""
    parser = argparse.ArgumentParser(description="Fetch public ATT&CK-labelled dataset slices into vendor/datasets.")
    parser.add_argument("--output-root", default="vendor/datasets", help="Root directory for ignored raw datasets.")
    parser.add_argument(
        "--dataset",
        action="append",
        choices=("casinolimit",),
        help="Dataset to fetch. Defaults to casinolimit.",
    )
    parser.add_argument(
        "--casinolimit-file",
        action="append",
        dest="casinolimit_files",
        help="CasinoLimit Zenodo filename to fetch. Defaults to syslogs_labels.zip and output.zip.",
    )
    parser.add_argument("--force", action="store_true", help="Redownload files that already exist.")
    parser.add_argument("--dry-run", action="store_true", help="Print planned downloads without writing files.")
    args = parser.parse_args()

    selected_datasets = tuple(args.dataset or ("casinolimit",))
    root = Path(args.output_root)
    downloads: list[dict[str, object]] = []
    if "casinolimit" in selected_datasets:
        downloads.extend(
            casinolimit_downloads(
                root / "casinolimit",
                filenames=tuple(args.casinolimit_files or DEFAULT_CASINOLIMIT_FILES),
            )
        )
    completed = []
    for item in downloads:
        url = str(item["url"])
        output_path = Path(str(item["path"]))
        if args.dry_run:
            completed.append({**item, "status": "planned"})
            continue
        if item.get("manual_only"):
            completed.append({**item, "status": "manual-only"})
            continue
        if output_path.exists() and not args.force:
            completed.append({**item, "status": "exists", "bytes": output_path.stat().st_size})
            continue
        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            download_file(url, output_path)
        except (OSError, urllib.error.URLError) as exc:
            completed.append({**item, "status": "failed", "error": str(exc)})
            continue
        completed.append({**item, "status": "downloaded", "bytes": output_path.stat().st_size})

    print(json.dumps({"schema_version": "v1", "download_count": len(completed), "downloads": completed}, indent=2, sort_keys=True))
    return 0


def casinolimit_downloads(output_dir: Path, *, filenames: Iterable[str]) -> list[dict[str, str]]:
    """Return CasinoLimit Zenodo downloads for the requested filenames.

    Example:
        Input:
            output_dir=Path("vendor/datasets/casinolimit")
            filenames=("syslogs_labels.zip",)
        Output:
            [{"dataset": "casinolimit", "url": "https://zenodo.org/api/...", "path": ".../syslogs_labels.zip"}]
    """
    record = json.loads(read_url(ZENODO_CASINOLIMIT_API))
    by_name = {item["key"]: item for item in record.get("files", []) if isinstance(item, dict) and "key" in item}
    downloads: list[dict[str, str]] = []
    for filename in filenames:
        item = by_name.get(filename)
        if not item:
            raise RuntimeError(f"CasinoLimit file not found in Zenodo record: {filename}")
        downloads.append(
            {
                "dataset": "casinolimit",
                "url": item["links"]["self"],
                "path": str(output_dir / filename),
            }
        )
    return downloads


def read_url(url: str) -> str:
    """Read a small text response from a public dataset endpoint."""
    request = urllib.request.Request(url, headers={"User-Agent": "honeynet-dataset-fetcher/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8", errors="replace")


def download_file(url: str, output_path: Path) -> None:
    """Stream one public dataset file to disk without loading it all into memory."""
    request = urllib.request.Request(url, headers={"User-Agent": "honeynet-dataset-fetcher/1.0"})
    with urllib.request.urlopen(request, timeout=120) as response, output_path.open("wb") as handle:
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk:
                break
            handle.write(chunk)


if __name__ == "__main__":
    raise SystemExit(main())
