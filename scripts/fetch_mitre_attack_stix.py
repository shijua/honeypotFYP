from __future__ import annotations

import argparse
from pathlib import Path
from urllib.request import urlopen

from libs.common.config import RuntimeConfig


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch the official MITRE ATT&CK enterprise STIX bundle.",
    )
    config = RuntimeConfig()
    parser.add_argument(
        "--url",
        default=config.mitre_attack_stix_url,
        help="Source URL for the ATT&CK STIX bundle.",
    )
    parser.add_argument(
        "--output",
        default=config.mitre_attack_stix_path,
        help="Local path for the downloaded STIX bundle.",
    )
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with urlopen(args.url, timeout=120) as response:
        payload = response.read()
    output_path.write_bytes(payload)
    print(f"Wrote {len(payload)} bytes to {output_path}")


if __name__ == "__main__":
    main()
