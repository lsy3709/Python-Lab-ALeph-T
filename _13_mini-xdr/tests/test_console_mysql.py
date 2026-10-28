"""콘솔 조회 — 실제 스키마에서 목록·상세·대시보드 집계를 읽고, 읽기 전용 세션이 쓰기를 거부하는지 확인한다."""
from datetime import date, datetime

import pymysql
import pytest

from app.console.queries import ConsoleQueries, connect_readonly
from app.correlator import correlate_once
from app.store import MySQLStore
from tests._mysql import ROOT_PW
from tests.test_store_correlation_mysql import FAR, W, seed

pytestmark = pytest.mark.integration


@pytest.fixture
def queries(fresh_db):
    kw = dict(host="127.0.0.1", port=fresh_db["port"], user="root", password=ROOT_PW, database=fresh_db["name"])
    store = MySQLStore(**kw)
    seed(store)  # IP A(app+network)·IP A 30분 뒤·IP B·asset:board-host(level 12)
    correlate_once(store, W, FAR)
    store.close()
    conn = connect_readonly(**kw)
    yield ConsoleQueries(conn)
    conn.close()


def test_list_orders_by_priority_and_filters(queries):
    rows, total = queries.list_incidents()
    assert total == 4 and rows[0]["current_priority"] == "P1" and rows[0]["entity_key"] == "asset:board-host"
    rows, total = queries.list_incidents(multi=True)
    assert total == 1 and rows[0]["layers"] == ["app", "network"]
    assert queries.list_incidents(priority="P1")[1] == 1
    assert queries.list_incidents(status="open")[1] == 0


def test_detail_queries(queries):
    iid = queries.list_incidents(multi=True)[0][0]["id"]
    inc = queries.get_incident(iid)
    assert inc["event_count"] == 2 and inc["layers"] == ["app", "network"]
    assert [s["sig"] for s in queries.signal_summary(iid)] == ["web-scan", "ids-alert"]
    assert [e.event_type for e in queries.incident_events(iid)] == ["web-scan", "ids-alert"]
    assert queries.users(iid) == []
    assert queries.get_incident(99999) is None
    s = queries.stats()
    assert (s["events"], s["incidents"], s["multi_layer"], s["backlog"]) == (5, 4, 1, 0)


def test_dashboard_queries(queries, fresh_db):
    since = datetime(2026, 10, 25, 15, 0)   # KST 10-26 00:00 — 시드 이벤트는 UTC 05:00~05:30(KST 14시대)
    daily = {(r["day"], r["layer"]): r["n"] for r in queries.daily_layer_counts(since)}
    assert daily == {(date(2026, 10, 26), "app"): 3, (date(2026, 10, 26), "network"): 1,
                     (date(2026, 10, 26), "host"): 1}
    assert queries.daily_layer_counts(datetime(2026, 10, 27, 0, 0)) == []        # 기간 밖
    pr = queries.priority_counts(since)
    assert sum(r["n"] for r in pr) == 4 and any(r["priority"] == "P1" for r in pr)
    top = queries.top_entities(since)
    assert (top[0]["entity_key"], top[0]["events"], top[0]["incidents"]) == ("ip:203.0.113.9", 3, 2)
    assert queries.gate_counts(since) == {}
    conn = pymysql.connect(host="127.0.0.1", port=fresh_db["port"], user="root", password=ROOT_PW,
                           database=fresh_db["name"], autocommit=True)
    with conn.cursor() as cur:
        cur.execute("INSERT INTO triage_results (incident_id, source, gate, priority, verdict, created_at) "
                    "SELECT MIN(id), 'cache', 'G3', 'P3', 'benign', '2026-10-26 06:00:00' FROM incidents")
    conn.close()
    assert queries.gate_counts(since) == {"G3": 1}


def test_anomaly_queries(fresh_db):
    from app.anomaly import build_baselines, bucketize, score_bucket
    from tests.test_store_anomaly_mysql import history
    kw = dict(host="127.0.0.1", port=fresh_db["port"], user="root", password=ROOT_PW, database=fresh_db["name"])
    store = MySQLStore(**kw)
    events = history(store)
    bl = build_baselines(bucketize(events).values())
    store.save_baselines(bl, events[0].ts)
    agg = next(iter(bucketize([e for e in events if e.src_ip == "198.51.100.0"]).values()))
    store.insert_anomaly_score(score_bucket(agg, bl, min_samples=30, threshold=3.0))
    store.close()
    conn = connect_readonly(**kw)
    try:
        q = ConsoleQueries(conn)
        rows = q.list_anomalies()
        assert rows[0]["entity"] == "198.51.100.0" and rows[0]["features"]["events"]["kind"] == "population"
        summary = q.baseline_summary(min_samples=30)
        assert any(p["feature"] == "events" and p["n"] == 40 for p in summary["population"])
        assert summary["individual"] == [] and summary["insufficient"] > 0   # IP 마다 표본 1개 → 개인 기준선 없음
    finally:
        conn.close()


def test_readonly_session_rejects_writes(queries):
    with pytest.raises(pymysql.err.MySQLError) as exc:
        with queries._conn.cursor() as cur:
            cur.execute("DELETE FROM incidents")
    assert exc.value.args[0] == 1792  # Cannot execute statement in a READ ONLY transaction
