"""Load the MITRE ATT&CK Enterprise catalog into ARGUS.

Downloads the official CTI bundle (or reads a local copy) and upserts
techniques into the global mitre_techniques table. Idempotent: safe to
re-run when ATT&CK releases a new version.

Usage:
  uv run python scripts/load_mitre_attack.py            # download latest
  uv run python scripts/load_mitre_attack.py --file /tmp/attack.json
"""

import argparse
import asyncio
import json
import time
import urllib.error
import urllib.request

from sqlalchemy.dialects.postgresql import insert as pg_insert

from argus.infrastructure.db.models import MitreTechnique
from argus.infrastructure.db.session import admin_session, dispose_engine

CTI_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
)


def parse_bundle(bundle: dict) -> list[dict]:
    techniques = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated") or obj.get("revoked"):
            continue
        ext = next(
            (
                r
                for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not ext or not ext.get("external_id"):
            continue
        tid = ext["external_id"]
        is_sub = obj.get("x_mitre_is_subtechnique", False)
        techniques.append(
            {
                "technique_id": tid,
                "name": obj.get("name", ""),
                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", [])],
                "description": (obj.get("description") or "")[:4000],
                "parent_id": tid.split(".")[0] if is_sub else None,
                "is_subtechnique": is_sub,
                "url": ext.get("url"),
            }
        )
    return techniques


async def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--file", help="local bundle json (else download)")
    args = p.parse_args()

    if args.file:
        bundle = json.load(open(args.file))
    else:
        print(f"downloading {CTI_URL} (47MB, be patient) ...", flush=True)
        req = urllib.request.Request(CTI_URL, headers={"User-Agent": "argus-mitre-loader"})
        bundle = None
        for attempt in range(1, 6):
            try:
                with urllib.request.urlopen(req) as r:  # noqa: S310 - trusted MITRE host
                    bundle = json.loads(r.read())
                break
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 5:
                    wait = attempt * 20
                    print(f"rate limited (429), retry {attempt}/5 in {wait}s ...", flush=True)
                    time.sleep(wait)
                else:
                    raise
        if bundle is None:
            print("download failed; try: curl -L -o /tmp/attack.json <url> then --file")
            return 1

    techniques = parse_bundle(bundle)
    print(f"parsed {len(techniques)} active techniques", flush=True)

    async with admin_session() as s:
        for t in techniques:
            stmt = pg_insert(MitreTechnique).values(**t)
            stmt = stmt.on_conflict_do_update(
                index_elements=[MitreTechnique.technique_id],
                set_={k: stmt.excluded[k] for k in t if k != "technique_id"},
            )
            await s.execute(stmt)
    await dispose_engine()
    print("loaded into mitre_techniques", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
