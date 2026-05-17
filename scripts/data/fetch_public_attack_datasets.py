#!/usr/bin/env python3
"""Download small public ATT&CK-labelled dataset slices for transition-prior builds.

The default profile fetches data that is big enough to exercise the real pipeline
but small enough for a laptop/VM workflow: UWF-ZeekData24 CSV tactic slices and
CasinoLimit label metadata. Mordor/OTRF can fetch every zip declared by dataset
metadata, including Host, Network, and Cloud entries. PWNJUTSU is dry-run/index
only until labelled ordered traces are confirmed. Large raw PCAP/parquet/syslog
archives remain manual unless they are explicitly listed in metadata.

Example:
    python scripts/data/fetch_public_attack_datasets.py
"""

from __future__ import annotations

import argparse
import html.parser
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

import yaml


UWF_BASE_URL = "https://datasets.uwf.edu/data/UWF-ZeekData24/csv"
ZENODO_CASINOLIMIT_API = "https://zenodo.org/api/records/17256954"
MORDOR_GITHUB_TREE_API = "https://api.github.com/repos/OTRF/Security-Datasets/git/trees/master?recursive=1"
MORDOR_RAW_PREFIX = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/"
PWNJUTSU_DATASET_INDEX = "https://pwnjutsu.irisa.fr/dataset/"
DEFAULT_UWF_TACTICS = (
    "Credential_Access",
    "Defense_Evasion",
    "Exfiltration",
    "Initial_Access",
    "Persistence",
    "Privilege_Escalation",
    "Reconnaissance",
)
DEFAULT_CASINOLIMIT_FILES = ("syslogs_labels.zip", "output.zip")
DEFAULT_MORDOR_SECTIONS = ("compound", "atomic")
HREF_RE = re.compile(r'href="([^"]+\.csv)"')


def main() -> int:
    """Fetch selected public dataset files and print a JSON summary."""
    parser = argparse.ArgumentParser(description="Fetch public ATT&CK-labelled dataset slices into vendor/datasets.")
    parser.add_argument("--output-root", default="vendor/datasets", help="Root directory for ignored raw datasets.")
    parser.add_argument(
        "--dataset",
        action="append",
        choices=("uwf-zeekdata24", "casinolimit", "mordor", "pwnjutsu"),
        help="Dataset to fetch. Repeat to fetch several. Defaults to both small profiles.",
    )
    parser.add_argument(
        "--uwf-tactic",
        action="append",
        dest="uwf_tactics",
        help="UWF tactic directory to fetch, e.g. Reconnaissance. Repeat to limit the default list.",
    )
    parser.add_argument(
        "--casinolimit-file",
        action="append",
        dest="casinolimit_files",
        help="CasinoLimit Zenodo filename to fetch. Defaults to syslogs_labels.zip and output.zip.",
    )
    parser.add_argument(
        "--mordor-section",
        action="append",
        dest="mordor_sections",
        choices=("atomic", "compound"),
        help="Mordor section to fetch. Defaults to compound plus atomic metadata and declared zip entries.",
    )
    parser.add_argument(
        "--mordor-limit",
        type=int,
        default=20,
        help="Maximum Mordor metadata records to plan/download. Use 0 for all discovered metadata records.",
    )
    parser.add_argument(
        "--mordor-file-type",
        choices=("all", "host"),
        default="all",
        help="Mordor zip filter. all downloads every metadata-declared zip; host keeps only Host zip entries.",
    )
    parser.add_argument(
        "--pwnjutsu-section",
        action="append",
        dest="pwnjutsu_sections",
        default=None,
        help="PWNJUTSU index section to inspect during dry-run, e.g. system, network, reference.",
    )
    parser.add_argument("--force", action="store_true", help="Redownload files that already exist.")
    parser.add_argument("--dry-run", action="store_true", help="Print planned downloads without writing files.")
    args = parser.parse_args()

    selected_datasets = tuple(args.dataset or ("uwf-zeekdata24", "casinolimit"))
    root = Path(args.output_root)
    downloads: list[dict[str, object]] = []
    if "uwf-zeekdata24" in selected_datasets:
        downloads.extend(
            uwf_downloads(
                root / "uwf-zeekdata24",
                tactics=tuple(args.uwf_tactics or DEFAULT_UWF_TACTICS),
            )
        )
    if "casinolimit" in selected_datasets:
        downloads.extend(
            casinolimit_downloads(
                root / "casinolimit",
                filenames=tuple(args.casinolimit_files or DEFAULT_CASINOLIMIT_FILES),
            )
        )
    if "mordor" in selected_datasets:
        downloads.extend(
            mordor_downloads(
                root / "mordor",
                sections=tuple(args.mordor_sections or DEFAULT_MORDOR_SECTIONS),
                limit=args.mordor_limit,
                file_type=args.mordor_file_type,
            )
        )
    if "pwnjutsu" in selected_datasets:
        downloads.extend(
            pwnjutsu_index_items(
                root / "pwnjutsu",
                sections=tuple(args.pwnjutsu_sections or ()),
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


def uwf_downloads(output_dir: Path, *, tactics: Iterable[str]) -> list[dict[str, str]]:
    """Return concrete UWF CSV downloads by scraping each tactic directory.

    Example:
        Input:
            output_dir=Path("vendor/datasets/uwf-zeekdata24")
            tactics=("Reconnaissance",)
        Output:
            [{"dataset": "uwf-zeekdata24", "url": ".../Reconnaissance/file.csv", "path": ".../file.csv"}]
    """
    downloads: list[dict[str, str]] = []
    for tactic in tactics:
        index_url = f"{UWF_BASE_URL}/{tactic}/"
        index_html = read_url(index_url)
        matches = HREF_RE.findall(index_html)
        if not matches:
            raise RuntimeError(f"No UWF CSV file found at {index_url}")
        for filename in matches:
            downloads.append(
                {
                    "dataset": "uwf-zeekdata24",
                    "url": f"{index_url}{filename}",
                    "path": str(output_dir / tactic / filename),
                }
            )
    return downloads


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


def mordor_downloads(output_dir: Path, *, sections: Iterable[str], limit: int, file_type: str = "all") -> list[dict[str, object]]:
    """Return Mordor/OTRF metadata plus selected metadata-declared zip downloads.

    Example:
        Input:
            output_dir=Path("vendor/datasets/mordor")
            sections=("compound",)
            limit=1
            file_type="all"
        Output:
            [{"dataset": "mordor", "role": "metadata", ...}, {"dataset": "mordor", "role": "network_zip", ...}]
    """
    file_type_filter = file_type
    if file_type_filter not in {"all", "host"}:
        raise ValueError("file_type must be all or host")
    tree = json.loads(read_url(MORDOR_GITHUB_TREE_API))
    paths = [
        item["path"]
        for item in tree.get("tree", [])
        if isinstance(item, dict)
        and item.get("type") == "blob"
        and isinstance(item.get("path"), str)
        and item["path"].endswith((".yaml", ".yml"))
    ]
    section_order = tuple(dict.fromkeys(sections))
    metadata_paths: list[str] = []
    for section in section_order:
        prefix = f"datasets/{section}/_metadata/"
        metadata_paths.extend(path for path in sorted(paths) if path.startswith(prefix))

    downloads: list[dict[str, object]] = []
    selected = 0
    for metadata_path in metadata_paths:
        metadata_url = f"{MORDOR_RAW_PREFIX}{metadata_path}"
        metadata = _safe_yaml(read_url(metadata_url))
        if not isinstance(metadata, dict):
            continue
        dataset_id = str(metadata.get("id") or Path(metadata_path).stem)
        local_dir = output_dir / _mordor_section_from_path(metadata_path) / dataset_id
        downloads.append(
            {
                "dataset": "mordor",
                "role": "metadata",
                "dataset_id": dataset_id,
                "url": metadata_url,
                "path": str(local_dir / "metadata.yaml"),
            }
        )
        selected += 1
        for file_item in metadata.get("files") or ():
            if not isinstance(file_item, dict):
                continue
            link = str(file_item.get("link") or "")
            entry_type = str(file_item.get("type") or "")
            normalized_type = entry_type.lower() or "unknown"
            if not link.lower().endswith(".zip"):
                continue
            if file_type_filter != "all" and normalized_type != file_type_filter:
                continue
            downloads.append(
                {
                    "dataset": "mordor",
                    "role": f"{normalized_type}_zip",
                    "dataset_id": dataset_id,
                    "file_type": normalized_type,
                    "url": link,
                    "path": str(local_dir / Path(urllib.parse.urlparse(link).path).name),
                }
            )
        if limit > 0 and selected >= limit:
            break
    if not downloads:
        raise RuntimeError("No Mordor metadata downloads found from OTRF/Security-Datasets")
    return downloads


def pwnjutsu_index_items(output_dir: Path, *, sections: Iterable[str]) -> list[dict[str, object]]:
    """Return PWNJUTSU index entries without downloading large archives.

    Example:
        Input:
            output_dir=Path("vendor/datasets/pwnjutsu")
            sections=("system",)
        Output:
            [{"dataset": "pwnjutsu", "role": "index", "manual_only": True, ...}]
    """
    section_filter = {section.strip("/") for section in sections if section.strip("/")}
    root_links = _index_links(PWNJUTSU_DATASET_INDEX)
    planned: list[dict[str, object]] = []
    for href in root_links:
        label = href.rstrip("/").split("/")[-1]
        if section_filter and label not in section_filter:
            continue
        section_url = urllib.parse.urljoin(PWNJUTSU_DATASET_INDEX, href)
        planned.append(
            {
                "dataset": "pwnjutsu",
                "role": "index",
                "manual_only": True,
                "url": section_url,
                "path": str(output_dir / label / "INDEX.url"),
                "note": "metadata/index only; raw PWNJUTSU archives are not downloaded automatically",
            }
        )
        for child in _index_links(section_url)[:50]:
            child_url = urllib.parse.urljoin(section_url, child)
            planned.append(
                {
                    "dataset": "pwnjutsu",
                    "role": "index-entry",
                    "manual_only": True,
                    "url": child_url,
                    "path": str(output_dir / label / urllib.parse.unquote(child.rstrip("/")).replace("/", "_")),
                    "note": "inspect manually before adding labelled traces to training",
                }
            )
    if not planned:
        raise RuntimeError(f"No PWNJUTSU index entries found at {PWNJUTSU_DATASET_INDEX}")
    return planned


def read_url(url: str) -> str:
    """Read a small text response from a public dataset endpoint."""
    request = urllib.request.Request(url, headers={"User-Agent": "honeynet-dataset-fetcher/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8", errors="replace")


def _safe_yaml(text: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError:
        return None


def _mordor_section_from_path(metadata_path: str) -> str:
    parts = metadata_path.split("/")
    return parts[1] if len(parts) > 2 else "unknown"


def _index_links(url: str) -> list[str]:
    parser = _HrefParser()
    parser.feed(read_url(url))
    return [
        href
        for href in parser.hrefs
        if href and not href.startswith(("#", "?")) and href not in {"../", "/"}
    ]


class _HrefParser(html.parser.HTMLParser):
    """Minimal directory-index link parser used for PWNJUTSU dry-run planning."""

    def __init__(self) -> None:
        super().__init__()
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.hrefs.append(value)


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
