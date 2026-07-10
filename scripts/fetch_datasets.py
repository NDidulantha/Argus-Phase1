"""Download attack datasets to a PERSISTENT dir (~/argus-datasets), so a
reboot (which clears /tmp) never loses them again.

Verified OTRF Security-Datasets URLs are baked in; add your own to
EXTRA_URLS or pass --url. Idempotent: skips files already present.

Usage:
  uv run python scripts/fetch_datasets.py                 # fetch defaults
  uv run python scripts/fetch_datasets.py --url <zip-url> # add one
"""

import argparse
import os
import sys
import urllib.request
from pathlib import Path

BASE = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows"

# name -> repo path (verified to resolve). Add more as you find them on
# github.com/OTRF/Security-Datasets.
DATASETS = {
    "mimikatz": f"{BASE}/credential_access/host/empire_mimikatz_logonpasswords.zip",
    "psexec": f"{BASE}/lateral_movement/host/empire_psexec_dcerpc_tcp_svcctl.zip",
    "net_localgroup_admins": (
        f"{BASE}/discovery/host/empire_shell_net_localgroup_administrators.zip"
    ),
    "vbs_launcher": f"{BASE}/execution/host/empire_launcher_vbs.zip",
}

DEST = Path(os.path.expanduser("~/argus-datasets"))


def download(name: str, url: str) -> None:
    DEST.mkdir(parents=True, exist_ok=True)
    target = DEST / f"{name}.zip"
    if target.exists() and target.stat().st_size > 0:
        print(f"  skip {name} (already present)")
        return
    print(f"  fetching {name} ...", flush=True)
    req = urllib.request.Request(url, headers={"User-Agent": "argus-dataset-fetch"})
    try:
        with urllib.request.urlopen(req) as r:  # noqa: S310 - trusted host
            target.write_bytes(r.read())
        print(f"    -> {target} ({target.stat().st_size} bytes)")
    except Exception as e:  # noqa: BLE001
        print(f"    FAILED {name}: {e}", file=sys.stderr)


# EVTX-Attack-Samples: the whole repo as one zip (hundreds of .evtx).
EVTX_SAMPLES_ZIP = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/archive/refs/heads/master.zip"


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", action="append", default=[], help="extra zip URL(s)")
    p.add_argument("--name", action="append", default=[], help="name(s) for --url")
    p.add_argument("--evtx-samples", action="store_true",
                   help="download the full EVTX-Attack-Samples repo (~hundreds of .evtx)")
    args = p.parse_args()

    if args.evtx_samples:
        download("evtx-attack-samples", EVTX_SAMPLES_ZIP)

    for name, url in DATASETS.items():
        download(name, url)
    for i, url in enumerate(args.url):
        name = args.name[i] if i < len(args.name) else Path(url).stem
        download(name, url)

    print(f"\ndatasets in {DEST}:")
    for f in sorted(DEST.glob("*.zip")):
        print(f"  {f.name}")
    print("\nreplay all with:")
    print("  make replay")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
