"""Convert .evtx files to events and replay them into ARGUS.

Handles a single .evtx, a directory of them, or a .zip of them
(EVTX-Attack-Samples ships as a repo zip full of .evtx). Uses the evtx
library to parse each record to JSON, then POSTs batches to /events with
source=evtx.

Usage:
  export ARGUS_TOKEN=...
  uv run python scripts/replay_evtx.py --path ~/argus-datasets/evtx-samples/
  uv run python scripts/replay_evtx.py --path ~/argus-datasets/one.evtx
"""

import argparse
import json
import os
import sys
import tempfile
import zipfile
from pathlib import Path

import requests
from evtx import PyEvtxParser

ARGUS_MAX_BATCH = 500


def evtx_records(path: Path):
    """Yield parsed record dicts from one .evtx file."""
    try:
        parser = PyEvtxParser(str(path))
        for record in parser.records_json():
            try:
                yield json.loads(record["data"])
            except (json.JSONDecodeError, KeyError):
                continue
    except Exception as e:  # noqa: BLE001
        print(f"  skip {path.name}: {e}", file=sys.stderr)


def iter_evtx_files(root: Path):
    if root.suffix.lower() == ".evtx":
        yield root
    elif root.suffix.lower() == ".zip":
        tmp = Path(tempfile.mkdtemp())
        with zipfile.ZipFile(root) as zf:
            zf.extractall(tmp)
        yield from tmp.rglob("*.evtx")
    elif root.is_dir():
        yield from root.rglob("*.evtx")


def ship(argus_url: str, token: str, batch: list[dict]) -> tuple[int, int]:
    resp = requests.post(
        f"{argus_url}/api/v1/events",
        json={"source": "evtx", "events": batch},
        headers={"Authorization": f"Bearer {token}"},
        timeout=60,
    )
    resp.raise_for_status()
    b = resp.json()
    return b["received"], b["normalized"]


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--path", required=True, type=Path)
    p.add_argument("--argus-url", default="http://localhost:8000")
    p.add_argument("--argus-token", default=os.environ.get("ARGUS_TOKEN"))
    args = p.parse_args()
    if not args.argus_token:
        print("error: set ARGUS_TOKEN or --argus-token", file=sys.stderr)
        return 1

    files = list(iter_evtx_files(args.path))
    print(f"found {len(files)} .evtx file(s)")
    total_recv = total_norm = 0
    batch: list[dict] = []

    def flush():
        nonlocal total_recv, total_norm, batch
        if not batch:
            return
        r, n = ship(args.argus_url, args.argus_token, batch)
        total_recv += r
        total_norm += n
        batch = []

    for i, f in enumerate(files, 1):
        count = 0
        for rec in evtx_records(f):
            batch.append(rec)
            count += 1
            if len(batch) >= ARGUS_MAX_BATCH:
                flush()
        flush()
        print(f"  [{i}/{len(files)}] {f.name}: {count} records "
              f"(running total normalized={total_norm})")

    print(f"\ndone: received={total_recv} normalized={total_norm}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
