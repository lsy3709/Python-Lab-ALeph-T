"""MySQL 상관 저장 — 일회용 컨테이너의 독립 DB 에서 인시던트·연결·진행 위치·롤백을 확인한다."""
import json
from datetime import datetime, timedelta, timezone

import pytest

import app.store as store_mod
from app.correlator import CURSOR_SOURCE, correlate_once
from app.normalizer import NormalizedEvent
from app.store import MySQLStore
from tests._mysql import ROOT_PW

pytestmark = pytest.mark.integration

T0 = datetime(2026, 10, 26, 5, 0, 0, tzinfo=timezone.utc)
W = timedelta(minutes=10)
FAR = T0 + timedelta(days=1)


@pytest.fixture
def store(fresh_db):
    s = MySQLStore(host="127.0.0.1", port=fresh_db["port"], user="root", password=ROOT_PW,
                   database=fresh_db["name"])
    yield s
    s.close()


def q(store, sql, *args):
    with store._conn.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchall()


def ne(ref, minutes, *, layer="app", source="board", event_type="web-scan", ip="203.0.113.9", asset=None,
       rule_id=None, level=None):
    return NormalizedEvent(ts=T0 + timedelta(minutes=minutes), layer=layer, source=source, event_type=event_type,
                           raw_ref=ref, src_ip=ip, asset=asset, rule_id=rule_id, level=level)


def seed(store):
    store.insert_events([
        ne("a1", 0),
        ne("a2", 3, layer="network", source="suricata", event_type="ids-alert"),
        ne("b1", 1, ip="198.51.100.7"),
        ne("h1", 2, ip=None, layer="host", source="wazuh", event_type="wazuh-alert", asset="board-host",
           rule_id="5710", level=12),
        ne("a3", 30),  # 같은 IP 지만 27분 쉬었다 → 새 인시던트
    ])


def test_correlate_once_builds_incidents_links_and_cursor(store):
    seed(store)
    store.ping()
    r = correlate_once(store, W, FAR)
    assert (r.processed, r.created) == (5, 4)
    rows = q(store, "SELECT entity_key, layers, event_count, rule_floor, current_priority, status, fingerprint "
                    "FROM incidents ORDER BY id")
    assert sorted(x[0] for x in rows) == ["asset:board-host", "ip:198.51.100.7", "ip:203.0.113.9", "ip:203.0.113.9"]
    first = rows[0]
    assert first[0] == "ip:203.0.113.9" and json.loads(first[1]) == ["app", "network"] and first[2] == 2
    host = next(x for x in rows if x[0] == "asset:board-host")
    assert host[3] == "P1" and host[4] == "P1"
    assert all(x[5] == "closed" for x in rows) and all(len(x[6]) == 64 for x in rows)
    assert q(store, "SELECT COUNT(*) FROM incident_events")[0][0] == 5
    assert store.get_cursor(CURSOR_SOURCE) == q(store, "SELECT MAX(id) FROM events_norm")[0][0]


def test_second_run_attaches_and_recomputes_fingerprint_from_db(store):
    seed(store)
    correlate_once(store, W, FAR)
    store.insert_events([ne("a4", 35, layer="network", source="pfsense", event_type="pfsense-block")])
    r = correlate_once(store, W, FAR)
    assert (r.processed, r.created, r.updated) == (1, 0, 1)
    assert store.load_latest_incidents(set()) == {}
    latest = store.load_latest_incidents({"ip:203.0.113.9"})["ip:203.0.113.9"]  # 마지막 시각이 늦은 쪽
    assert latest.event_count == 2 and latest.layers == {"app", "network"}
    assert latest.signals == {"app/board/web-scan", "network/pfsense/pfsense-block"}
    assert q(store, "SELECT fingerprint FROM incidents WHERE id = %s", latest.id)[0][0] == latest.fingerprint


def test_close_stale_closes_only_quiet_open_incidents(store):
    seed(store)
    correlate_once(store, W, T0 + timedelta(minutes=31))  # 30분 이벤트의 인시던트만 열려 있다
    assert q(store, "SELECT COUNT(*) FROM incidents WHERE status = 'open'")[0][0] == 1
    assert store.close_stale(T0 + timedelta(minutes=29)) == 0
    assert store.close_stale(T0 + timedelta(minutes=31)) == 1


def test_ping_reconnects_after_connection_loss(store):
    store._conn.close()  # DB 재시작 등으로 연결이 끊긴 상황
    store.ping()
    assert store.get_cursor(CURSOR_SOURCE) == 0


def test_save_is_atomic_when_checkpoint_write_fails(store, monkeypatch):
    seed(store)

    def boom(*args, **kwargs):
        raise RuntimeError("진행 위치 저장 실패(시험)")

    monkeypatch.setattr(store_mod, "_upsert_checkpoint", boom)
    with pytest.raises(RuntimeError):
        correlate_once(store, W, FAR)
    assert q(store, "SELECT COUNT(*) FROM incidents")[0][0] == 0
    assert q(store, "SELECT COUNT(*) FROM incident_events")[0][0] == 0
    assert store.get_cursor(CURSOR_SOURCE) == 0
