"""Collector logic tests with a stubbed HTTP layer: paging, checkpointing,
boundary dedup, and no-checkpoint-advance-on-failure."""

import importlib.util
import json
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location(
    "collector", Path(__file__).parents[1] / "collectors" / "wazuh_indexer_collector.py"
)
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class Args:
    indexer_url = "https://indexer:9200"
    indexer_user = "admin"
    indexer_pass = "x"
    argus_url = "http://argus:8000"
    argus_token = "tok"
    min_level = 5
    batch_size = 2
    checkpoint = None  # set per-test
    insecure = True


def _hit(_id: str, ts: str, level: int = 7) -> dict:
    return {"_id": _id, "_source": {"timestamp": ts, "rule": {"level": level}}}


class StubResponse:
    def __init__(self, payload, status=200):
        self._payload, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise collector.requests.HTTPError(f"{self.status_code}")

    def json(self):
        return self._payload


def test_cycle_pages_ships_and_checkpoints(tmp_path, monkeypatch):
    args = Args()
    args.checkpoint = str(tmp_path / "ckpt.json")
    pages = [
        [_hit("a", "T1"), _hit("b", "T2")],   # full page -> keep paging
        [_hit("b", "T2"), _hit("c", "T2")],   # boundary dup 'b' + new 'c'
        [],
    ]
    shipped = []

    def fake_post(url, **kw):
        if "_search" in url:
            hits = pages.pop(0)
            return StubResponse({"hits": {"hits": hits}})
        shipped.append(kw["json"]["events"])
        return StubResponse({"received": len(kw["json"]["events"]), "normalized": 0})

    monkeypatch.setattr(collector.requests, "post", fake_post)

    ckpt = collector.run_cycle(args, {"last_ts": "T0", "seen_ids": []})

    assert [len(batch) for batch in shipped] == [2, 1]  # 'b' deduped on page 2
    assert ckpt["last_ts"] == "T2"
    assert set(ckpt["seen_ids"]) == {"b", "c"}
    saved = json.loads((tmp_path / "ckpt.json").read_text())
    assert saved["last_ts"] == "T2"


def test_argus_failure_does_not_advance_checkpoint(tmp_path, monkeypatch):
    args = Args()
    args.checkpoint = str(tmp_path / "ckpt.json")

    def fake_post(url, **kw):
        if "_search" in url:
            return StubResponse({"hits": {"hits": [_hit("a", "T1")]}})
        return StubResponse({}, status=503)  # ARGUS down

    monkeypatch.setattr(collector.requests, "post", fake_post)

    with pytest.raises(collector.requests.HTTPError):
        collector.run_cycle(args, {"last_ts": "T0", "seen_ids": []})
    assert not (tmp_path / "ckpt.json").exists()  # nothing lost, retry next cycle
