"""MySQL 저장소 — 일회용 컨테이너에서 중복 무시·체크포인트·UTC 왕복을 확인한다."""
from datetime import datetime, timezone

import pytest

from app.normalizer import NormalizedEvent
from app.store import MySQLStore
from tests._mysql import ROOT_PW

pytestmark = pytest.mark.integration


@pytest.fixture
def store(schema_applied):
    s = MySQLStore(host="127.0.0.1", port=schema_applied["port"], user="root", password=ROOT_PW,
                   database="mini_xdr")
    yield s
    s.close()


def ev(ref, sec=0):
    return NormalizedEvent(ts=datetime(2026, 10, 26, 5, 0, sec, 123000, tzinfo=timezone.utc), layer="app",
                           source="board", event_type="web-scan", raw_ref=ref, src_ip="203.0.113.9")


def test_insert_ignores_duplicates_by_raw_ref(store):
    assert store.insert_events([ev("st-1"), ev("st-2")]) == 2
    assert store.insert_events([ev("st-2"), ev("st-3")]) == 1


def test_checkpoint_roundtrip_in_utc(store):
    assert store.get_checkpoint("graylog-test") is None
    t = datetime(2026, 10, 26, 5, 30, 0, 456000, tzinfo=timezone.utc)
    store.set_checkpoint("graylog-test", t, "last-id")
    assert store.get_checkpoint("graylog-test") == t
    later = datetime(2026, 10, 26, 5, 31, 0, tzinfo=timezone.utc)
    store.set_checkpoint("graylog-test", later)
    assert store.get_checkpoint("graylog-test") == later


def test_event_timestamp_stored_as_utc_with_millis(store):
    store.insert_events([ev("st-ts", 7)])
    assert store.fetch_event_ts("st-ts") == datetime(2026, 10, 26, 5, 0, 7, 123000, tzinfo=timezone.utc)
