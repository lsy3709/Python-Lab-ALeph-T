"""상관 실행기 — 진행 위치·묶음·닫힘 집계를 메모리 저장소로 확인한다."""
from datetime import timedelta

from app.correlator import CURSOR_SOURCE, correlate_once
from tests.test_correlator import NOW, T0, W, ev


class FakeCorrStore:
    def __init__(self, events):
        self.events = list(events)
        self.cursor = 0
        self.incidents = []          # 저장된 IncidentState
        self.links = []
        self.closed_before = None

    def get_cursor(self, source):
        assert source == CURSOR_SOURCE
        return self.cursor

    def fetch_events_after(self, last_id, limit):
        return [e for e in self.events if e.id > last_id][:limit]

    def load_latest_incidents(self, keys):
        latest = {}
        for inc in self.incidents:
            if inc.entity_key in keys and (inc.entity_key not in latest
                                           or inc.last_event_at > latest[inc.entity_key].last_event_at):
                latest[inc.entity_key] = inc
        return latest

    def save_correlation(self, batch, source, last):
        assert source == CURSOR_SOURCE
        for inc in batch.touched:
            if inc.id is None:
                inc.id = len(self.incidents) + 1
                self.incidents.append(inc)
        self.links += [(inc.id, eid) for inc, eid in batch.links]
        self.cursor = last.id

    def close_stale(self, before):
        self.closed_before = before
        n = 0
        for inc in self.incidents:
            if inc.status == "open" and inc.last_event_at < before:
                inc.status, n = "closed", n + 1
        return n


def test_processes_in_batches_and_moves_cursor():
    store = FakeCorrStore([ev(i, i) for i in range(1, 8)])
    r = correlate_once(store, W, NOW, batch_size=3)
    assert (r.processed, r.batches, store.cursor) == (7, 3, 7)
    assert r.created == 1 and r.updated == 2  # 첫 묶음에서 열고, 다음 두 묶음은 이어 붙임
    assert len(store.links) == 7 and store.incidents[0].event_count == 7


def test_nothing_new_processes_nothing():
    store = FakeCorrStore([ev(1, 0)])
    correlate_once(store, W, NOW)
    r = correlate_once(store, W, NOW)
    assert (r.processed, r.batches, r.created) == (0, 0, 0)


def test_closes_quiet_incidents_with_window_cutoff():
    store = FakeCorrStore([ev(1, 0)])
    r = correlate_once(store, W, T0 + timedelta(minutes=5))
    assert store.incidents[0].status == "open" and r.closed == 0
    r = correlate_once(store, W, T0 + timedelta(minutes=30))
    assert r.closed == 1 and store.closed_before == T0 + timedelta(minutes=20)


def test_max_batches_limits_one_cycle():
    store = FakeCorrStore([ev(i, i) for i in range(1, 11)])
    r = correlate_once(store, W, NOW, batch_size=2, max_batches=2)
    assert r.processed == 4 and store.cursor == 4
