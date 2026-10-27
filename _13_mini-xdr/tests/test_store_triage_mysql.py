"""트리아지 저장 — 실제 스키마에서 대상·카드 입력·판정 저장·지문 캐시·호출 집계·디바운스."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.correlator import correlate_once
from app.llm_triage import LLMResult
from app.normalizer import NormalizedEvent
from app.store import MySQLStore
from app.triage import LLMRoute, TriageConfig, run_triage
from tests._mysql import ROOT_PW
from tests.test_triage import FakeTriager, v

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 27, 1, 0, 0, tzinfo=timezone.utc)
NOW = T0 + timedelta(minutes=10)


@pytest.fixture
def store(fresh_db):
    s = MySQLStore(host="127.0.0.1", port=fresh_db["port"], user="root", password=ROOT_PW, database=fresh_db["name"])
    yield s
    s.close()


def q(store, sql, *args):
    with store._conn.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchall()


def seed(store):
    ip = "203.0.113.9"
    store.insert_events([
        NormalizedEvent(ts=T0, layer="app", source="board", event_type="web-scan", raw_ref="t1", src_ip=ip,
                        user_name="zz_alice"),
        NormalizedEvent(ts=T0 + timedelta(minutes=1), layer="network", source="suricata", event_type="ids-alert",
                        raw_ref="t2", src_ip=ip),
        NormalizedEvent(ts=T0 + timedelta(minutes=2), layer="behavior", source="anomaly", event_type="anomaly-events-z8",
                        raw_ref="t3", src_ip=ip),
    ])
    correlate_once(store, timedelta(minutes=10), NOW)
    with store._conn.cursor() as cur:
        cur.execute("INSERT INTO anomaly_scores (entity_type, entity, ts, score, features) VALUES ('ip', %s, %s, 8.7, %s)",
                    (ip, (T0 + timedelta(minutes=2)).replace(tzinfo=None),
                     json.dumps({"events": {"value": 160, "z": 8.71, "kind": "population", "center": 18, "scale": 16.3}})))


def test_candidates_and_card_inputs(store):
    seed(store)
    cands = store.triage_candidates(NOW - timedelta(hours=1), None)
    assert len(cands) == 1
    c = cands[0]
    assert c["layers"] == ["app", "behavior", "network"] and c["last_triaged_at"] is None and c["material_state"] is None
    assert store.triage_candidates(None, 5)[0]["id"] == c["id"]
    data = store.card_inputs(c["id"])
    assert sorted(s["sig"] for s in data["summary"]) == ["anomaly-events-z8", "ids-alert", "web-scan"]
    assert [e.event_type for e in data["events"]][0] == "web-scan" and data["users"] == ["zz_alice"]
    assert data["anomalies"][0]["features"]["events"]["z"] == 8.71 and "anomaly-events-z8" in data["signals"]


def test_run_triage_saves_decision_cache_and_call_then_debounces(store):
    seed(store)
    iid = store.triage_candidates(NOW - timedelta(hours=1), None)[0]["id"]
    route = LLMRoute(FakeTriager([("ok", {f"INC-{iid}": v(priority="P2", reason="ip_1 다계층 공격")})]),
                     "gemini-3.5-flash-lite")
    rep = run_triage(store, route, TriageConfig(), NOW)
    assert rep.gates == {"LLM": 1}
    src, gate, pri, reason, model = q(store, "SELECT source, gate, priority, reasoning_ko, model FROM triage_results")[0]
    assert (src, gate, pri, model) == ("llm", "LLM", "P2", "gemini-3.5-flash-lite") and "203.0.113.9" in reason
    cur, triaged, material = q(store, "SELECT current_priority, last_triaged_at, material_state FROM incidents")[0]
    assert cur == "P2" and triaged is not None and json.loads(material)["band"] == "z8"
    cached = q(store, "SELECT verdict, model FROM verdict_cache")[0]
    assert "203.0.113.9" not in cached[0] and cached[1] == "gemini-3.5-flash-lite"   # 캐시에는 가린 근거만
    call = q(store, "SELECT incidents_in_batch, input_tokens, output_tokens, cache_read_tokens, status, gate_reason "
                    "FROM llm_calls")[0]
    assert call == (1, 300, 60, 1800, "ok", "gray_zone")
    rep2 = run_triage(store, route, TriageConfig(), NOW + timedelta(minutes=1))
    assert rep2.skipped == {"unchanged": 1} and q(store, "SELECT COUNT(*) FROM triage_results")[0][0] == 1


def test_verdict_cache_expiry_and_hits(store):
    store.put_cached_verdict("f" * 64, {"priority": "P3"}, "m", NOW + timedelta(hours=1))
    assert store.get_cached_verdict("f" * 64, NOW)["priority"] == "P3"
    assert store.get_cached_verdict("f" * 64, NOW + timedelta(hours=2)) is None     # 만료
    store.hit_cached_verdict("f" * 64)
    assert q(store, "SELECT hits FROM verdict_cache")[0][0] == 1


def test_llm_usage_counts_and_breaker(store):
    for status in ("ok", "error", "error", "error"):
        store.record_llm_call(LLMResult("gemini", "m", status), 1, "gray_zone")
    store.record_llm_call(LLMResult("gemini", "m", "ok"), 1, "connection_test")         # 연결 테스트는 예산에서 제외
    u = store.llm_usage(datetime.now(timezone.utc))
    assert (u["day"], u["hour"], u["recent_errors"]) == (4, 4, 3)
