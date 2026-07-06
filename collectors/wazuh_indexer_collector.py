#!/usr/bin/env python3
"""ARGUS pull collector: Wazuh Indexer -> ARGUS ingestion API.

Reference implementation of the ARGUS pull-connector pattern:
  poll a vendor store since a checkpoint -> batch -> POST to ARGUS.

Design guarantees:
- Checkpointed: survives restarts; resumes exactly where it stopped.
- At-least-once delivery: the checkpoint only advances after ARGUS
  accepts the batch. Boundary duplicates are filtered via seen-id list.
- Standalone: stdlib + requests only. Deploy as a single file next to
  the Wazuh stack; no ARGUS code needed on the lab machine.

Usage (lab):
  export WAZUH_INDEXER_PASS='...'
  export ARGUS_TOKEN='...'
  python3 wazuh_indexer_collector.py \
      --indexer-url https://localhost:9200 --insecure \
      --argus-url http://<LAPTOP_LAN_IP>:8000 \
      --min-level 5 --once
"""

import argparse
import json
import os
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import requests

DEFAULT_CHECKPOINT = os.path.expanduser("~/.argus/wazuh_checkpoint.json")
ARGUS_MAX_BATCH = 1000  # server-side limit on POST /api/v1/events


def log(msg: str) -> None:
    print(f"{datetime.now(UTC).isoformat(timespec='seconds')} {msg}", flush=True)


def load_checkpoint(path: str, lookback_minutes: int) -> dict:
    p = Path(path)
    if p.exists():
        return json.loads(p.read_text())
    start = datetime.now(UTC) - timedelta(minutes=lookback_minutes)
    return {"last_ts": start.strftime("%Y-%m-%dT%H:%M:%S.000+0000"), "seen_ids": []}


def save_checkpoint(path: str, last_ts: str, seen_ids: list[str]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"last_ts": last_ts, "seen_ids": seen_ids}))


def fetch_alerts(args, last_ts: str, seen_ids: list[str]) -> list[dict]:
    """One page of alerts at/after the checkpoint, boundary dupes removed.

    gte + seen-id filtering (rather than gt) means alerts sharing the
    checkpoint's exact timestamp are never skipped.
    """
    query = {
        "size": args.batch_size,
        "sort": [{"timestamp": {"order": "asc"}}],
        "query": {
            "bool": {
                "filter": [
                    {"range": {"timestamp": {"gte": last_ts}}},
                    {"range": {"rule.level": {"gte": args.min_level}}},
                ]
            }
        },
    }
    resp = requests.post(
        f"{args.indexer_url}/wazuh-alerts-*/_search",
        json=query,
        auth=(args.indexer_user, args.indexer_pass),
        verify=not args.insecure,
        timeout=30,
    )
    resp.raise_for_status()
    hits = resp.json()["hits"]["hits"]
    return [h for h in hits if h["_id"] not in seen_ids]


def ship_to_argus(args, alerts: list[dict]) -> None:
    """POST alert _source docs to ARGUS in chunks. Raises on any failure
    so the caller does NOT advance the checkpoint (at-least-once)."""
    events = [h["_source"] for h in alerts]
    for i in range(0, len(events), ARGUS_MAX_BATCH):
        chunk = events[i : i + ARGUS_MAX_BATCH]
        resp = requests.post(
            f"{args.argus_url}/api/v1/events",
            json={"source": "wazuh", "events": chunk},
            headers={"Authorization": f"Bearer {args.argus_token}"},
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        log(f"shipped {body['received']} events ({body['normalized']} normalized)")


def run_cycle(args, ckpt: dict) -> dict:
    """Drain everything since the checkpoint (paging until empty)."""
    while True:
        fresh = fetch_alerts(args, ckpt["last_ts"], ckpt["seen_ids"])
        if not fresh:
            return ckpt
        ship_to_argus(args, fresh)
        last_ts = fresh[-1]["_source"]["timestamp"]
        seen = [h["_id"] for h in fresh if h["_source"]["timestamp"] == last_ts]
        # carry over prior boundary ids if the timestamp didn't move
        if last_ts == ckpt["last_ts"]:
            seen = list(set(seen) | set(ckpt["seen_ids"]))
        ckpt = {"last_ts": last_ts, "seen_ids": seen}
        save_checkpoint(args.checkpoint, **{"last_ts": last_ts, "seen_ids": seen})
        if len(fresh) < args.batch_size:
            return ckpt


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--indexer-url", required=True)
    p.add_argument("--indexer-user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    p.add_argument("--indexer-pass", default=os.environ.get("WAZUH_INDEXER_PASS"))
    p.add_argument("--argus-url", required=True)
    p.add_argument("--argus-token", default=os.environ.get("ARGUS_TOKEN"))
    p.add_argument("--min-level", type=int, default=5)
    p.add_argument("--poll-seconds", type=int, default=30)
    p.add_argument("--batch-size", type=int, default=500)
    p.add_argument("--lookback-minutes", type=int, default=15, help="first-run history window")
    p.add_argument("--checkpoint", default=DEFAULT_CHECKPOINT)
    p.add_argument("--insecure", action="store_true", help="skip TLS verify (lab self-signed)")
    p.add_argument("--once", action="store_true", help="one collection cycle, then exit")
    args = p.parse_args()

    if not args.indexer_pass:
        print("error: set WAZUH_INDEXER_PASS or --indexer-pass", file=sys.stderr)
        return 1
    if not args.argus_token:
        print("error: set ARGUS_TOKEN or --argus-token", file=sys.stderr)
        return 1
    if args.insecure:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        log("WARNING: TLS verification disabled (lab mode)")

    ckpt = load_checkpoint(args.checkpoint, args.lookback_minutes)
    log(f"starting from checkpoint {ckpt['last_ts']}")

    while True:
        try:
            ckpt = run_cycle(args, ckpt)
        except requests.RequestException as e:
            log(f"cycle failed, will retry: {e}")  # checkpoint NOT advanced
        if args.once:
            return 0
        time.sleep(args.poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
