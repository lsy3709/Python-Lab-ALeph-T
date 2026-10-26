"""이상탐지 저장 — 실제 스키마에서 구간 조회(behavior 제외)·기준선 교체·이상 점수 이력·behavior 적재."""
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.anomaly import anomaly_events, build_baselines, bucketize, score_bucket
from app.correlator import correlate_once
from app.normalizer import NormalizedEvent
from app.store import MySQLStore, event_from_row
from tests._mysql import ROOT_PW

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 26, 5, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def store(fresh_db):
    s = MySQLStore(host="127.0.0.1", port=fresh_db["port"], user="root", password=ROOT_PW, database=fresh_db["name"])
    yield s
    s.close()


def q(store, sql, *args):
    with store._conn.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchall()


def ne(ref, minutes, ip, layer="app", event_type="web-scan"):
    return NormalizedEvent(ts=T0 + timedelta(minutes=minutes), layer=layer, source="board", event_type=event_type,
                           raw_ref=ref, src_ip=ip)


def test_fetch_between_excludes_behavior_and_end(store):
    store.insert_events([ne("a", 0, "203.0.113.1"), ne("b", 59, "203.0.113.1"), ne("c", 60, "203.0.113.1"),
                         ne("d", 10, "203.0.113.1", layer="behavior", event_type="anomaly-events-z5")])
    got = store.fetch_events_between(T0, T0 + timedelta(minutes=60))
    assert sorted(e.event_type for e in got) == ["web-scan", "web-scan"]  # 60분(끝)·behavior 제외


def history(store):
    rows = [ne(f"h{k}-{j}", j, f"198.51.100.{k}") for k in range(40) for j in range(10 + k % 5)]
    store.insert_events(rows)
    return [event_from_row(r) for r in q(store, "SELECT id, ts, layer, source, event_type, src_ip, user_name, asset, "
                                                "rule_id, level, mitre FROM events_norm")]


def test_save_baselines_replaces_table(store):
    bl = build_baselines(bucketize(history(store)).values())
    store.save_baselines(bl, T0)
    first = q(store, "SELECT COUNT(*) FROM baselines")[0][0]
    pop = q(store, "SELECT mean, std, n FROM baselines WHERE entity_type='ip' AND entity='*' AND feature='events'")[0]
    assert first == len(bl) and pop[0] == 12 and pop[2] == 40
    store.save_baselines({k: v for k, v in bl.items() if k[1] == "*"}, T0)  # 교체(지난 엔티티는 사라짐)
    assert q(store, "SELECT COUNT(*) FROM baselines")[0][0] == sum(1 for k in bl if k[1] == "*")


def test_behavior_event_and_score_history_then_correlated(store):
    bl = build_baselines(bucketize(history(store)).values())
    store.insert_events([ne(f"burst{j}", 70 + j % 30, "203.0.113.50") for j in range(200)])
    burst = [e for e in store.fetch_events_between(T0 + timedelta(hours=1), T0 + timedelta(hours=2))]
    s = score_bucket(next(iter(bucketize(burst).values())), bl, min_samples=30, threshold=3.0)
    assert store.insert_events(anomaly_events(s)) == 1
    assert store.insert_events(anomaly_events(s)) == 0     # 다시 채점해도 중복 없음
    store.insert_anomaly_score(s)
    entity, score, features = q(store, "SELECT entity, score, features FROM anomaly_scores")[0]
    feats = json.loads(features)
    assert entity == "203.0.113.50" and score > 50 and feats["events"]["kind"] == "population"
    assert feats["events"]["value"] == 200
    correlate_once(store, timedelta(minutes=10), T0 + timedelta(days=1))
    layers = q(store, "SELECT layers FROM incidents WHERE entity_key = 'ip:203.0.113.50'")[0][0]
    assert json.loads(layers) == ["app", "behavior"]       # behavior 가 같은 IP 인시던트에 붙음
