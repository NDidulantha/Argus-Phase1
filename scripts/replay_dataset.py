#!/usr/bin/env python3
"""ARGUS dataset replayer.

Feeds public attack datasets (OTRF Security-Datasets / Mordor, or any
JSON/NDJSON event file) through POST /api/v1/events — simulating a real
connector delivering telemetry, without needing SOC access.

Accepts: .json (array), .ndjson/.jsonl (one event per line), or .zip
containing either (Security-Datasets ship as zipped NDJSON).

Usage:
  export ARGUS_TOKEN='<tenant ingest token>'
  python3 scripts/replay_dataset.py \
      --file apt29_evals_day1.zip \
      --source securitydatasets \
      --argus-url http://localhost:8000 \
      --limit 2000
"""

import argparse
import io
import json
import os
import sys
import time
import zipfile
from pathlib import Path

import requests


def iter_events(path: Path):
    """Yield event dicts from json / ndjson / zip-of-those."""
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as zf:
            for name in zf.namelist():
                if name.endswith((".json", ".ndjson", ".jsonl")):
                    with zf.open(name) as fh:
                        yield from _iter_stream(io.TextIOWrapper(fh, "utf-8", errors="replace"))
        return
    with open(path, encoding="utf-8", errors="replace") as fh:
        yield from _iter_stream(fh)


def _iter_stream(fh):
    first = fh.read(1)
    fh_content = first + fh.read()
    if first == "[":  # JSON array
        for event in json.loads(fh_content):
            if isinstance(event, dict):
                yield event
        return
    for line in fh_content.splitlines():  # NDJSON
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            yield event


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--file", required=True, type=Path)
    p.add_argument("--source", default="securitydatasets")
    p.add_argument("--argus-url", default="http://localhost:8000")
    p.add_argument("--argus-token", default=os.environ.get("ARGUS_TOKEN"))
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--limit", type=int, default=0, help="max events (0 = all)")
    p.add_argument("--delay", type=float, default=0.0, help="seconds between batches")
    args = p.parse_args()

    if not args.argus_token:
        print("error: set ARGUS_TOKEN or --argus-token", file=sys.stderr)
        return 1

    headers = {"Authorization": f"Bearer {args.argus_token}"}
    batch: list[dict] = []
    totals = {"sent": 0, "normalized": 0, "failed": 0}
    started = time.monotonic()

    def flush() -> None:
        if not batch:
            return
        resp = requests.post(
            f"{args.argus_url}/api/v1/events",
            json={"source": args.source, "events": batch},
            headers=headers,
            timeout=60,
        )
        resp.raise_for_status()
        body = resp.json()
        totals["sent"] += body["received"]
        totals["normalized"] += body["normalized"]
        totals["failed"] += body["failed"]
        print(
            f"  sent={totals['sent']} normalized={totals['normalized']} "
            f"failed={totals['failed']}",
            flush=True,
        )
        batch.clear()
        if args.delay:
            time.sleep(args.delay)

    for event in iter_events(args.file):
        batch.append(event)
        if len(batch) >= args.batch_size:
            flush()
        if args.limit and totals["sent"] + len(batch) >= args.limit:
            break
    flush()

    elapsed = time.monotonic() - started
    rate = totals["sent"] / elapsed if elapsed else 0
    print(f"done: {totals['sent']} events in {elapsed:.1f}s ({rate:.0f}/s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
