"""수집 알고리즘 — 가짜 Graylog·가짜 저장소로 체크포인트·페이지·정체 방지를 검증한다."""
from datetime import datetime, timedelta, timezone

from app.collector import CollectConfig, collect_once
from app.graylog import GraylogError

NOW = datetime(2026, 10, 26, 6, 0, 0, tzinfo=timezone.utc)
SRC = "graylog"


def msg(i, ts, rule="web-scan"):
    return {"gl2_message_id": f"id{i:04d}", "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "source": "board", "rule": rule, "src_ip": "203.0.113.5"}


def _ts(m):
    return datetime.fromisoformat(m["timestamp"].replace("Z", "+00:00"))


class FakeGraylog:
    def __init__(self, messages, fail=False):
        self.messages = sorted(messages, key=_ts)
        self.calls = []
        self.fail = fail

    def search_absolute(self, query, frm, to, *, limit, offset, fields=None):
        self.calls.append((frm, to, limit, offset))
        if self.fail:
            raise GraylogError("Graylog 검색 실패: HTTP 500")
        hits = [m for m in self.messages if frm <= _ts(m) <= to]
        return hits[offset:offset + limit]


class FakeStore:
    def __init__(self, checkpoint=None):
        self.checkpoint = checkpoint
        self.rows = {}

    def get_checkpoint(self, source):
        return self.checkpoint

    def set_checkpoint(self, source, ts, last_id=None):
        self.checkpoint = ts

    def insert_events(self, events):
        new = [e for e in events if e.raw_ref not in self.rows]
        self.rows.update({e.raw_ref: e for e in new})
        return len(new)


CFG = CollectConfig(query="*", page_size=3, overlap=timedelta(seconds=60),
                    backfill=timedelta(minutes=10), max_pages=50, lag=timedelta(seconds=2))


def test_first_run_backfills_and_sets_checkpoint_to_window_end():
    g = FakeGraylog([msg(1, NOW - timedelta(minutes=5)), msg(2, NOW - timedelta(minutes=20))])
    s = FakeStore()
    r = collect_once(g, s, CFG, NOW, source=SRC)
    assert g.calls[0][0] == NOW - timedelta(minutes=10)
    assert (r.fetched, r.inserted) == (1, 1)
    assert s.checkpoint == NOW - timedelta(seconds=2)


def test_resumes_from_checkpoint_minus_overlap_and_dedupes():
    cp = NOW - timedelta(minutes=3)
    g = FakeGraylog([msg(1, cp - timedelta(seconds=30)), msg(2, cp + timedelta(seconds=10))])
    s = FakeStore(checkpoint=cp)
    s.rows["id0001"] = object()  # 이전 주기에 이미 적재된 것
    r = collect_once(g, s, CFG, NOW, source=SRC)
    assert g.calls[0][0] == cp - timedelta(seconds=60)
    assert (r.fetched, r.inserted, r.duplicates) == (2, 1, 1)


def test_pages_through_more_than_page_size():
    base = NOW - timedelta(minutes=5)
    g = FakeGraylog([msg(i, base + timedelta(seconds=i)) for i in range(7)])
    s = FakeStore()
    r = collect_once(g, s, CFG, NOW, source=SRC)
    assert r.inserted == 7 and len(s.rows) == 7


def test_same_millisecond_block_does_not_stall():
    same = NOW - timedelta(minutes=5)
    g = FakeGraylog([msg(i, same) for i in range(8)])  # 8건이 같은 밀리초, page_size=3
    s = FakeStore()
    r = collect_once(g, s, CFG, NOW, source=SRC)
    assert r.inserted == 8
    assert len(g.calls) < 20


def test_skipped_messages_are_counted():
    m = msg(1, NOW - timedelta(minutes=1))
    plain = {"gl2_message_id": "plain1", "timestamp": m["timestamp"], "source": "x", "message": "hi"}
    s = FakeStore()
    r = collect_once(FakeGraylog([m, plain]), s, CFG, NOW, source=SRC)
    assert (r.fetched, r.skipped, r.inserted) == (2, 1, 1)


def test_graylog_error_keeps_checkpoint():
    cp = NOW - timedelta(minutes=3)
    s = FakeStore(checkpoint=cp)
    r = collect_once(FakeGraylog([], fail=True), s, CFG, NOW, source=SRC)
    assert r.error and s.checkpoint == cp


def test_max_pages_stops_early_and_checkpoints_last_processed():
    base = NOW - timedelta(minutes=5)
    g = FakeGraylog([msg(i, base + timedelta(seconds=i)) for i in range(10)])
    s = FakeStore()
    cfg = CollectConfig(**{**CFG.__dict__, "max_pages": 2})
    r = collect_once(g, s, cfg, NOW, source=SRC)
    # 1쪽: id0~2 적재 → cursor=base+2초 / 2쪽: base+2초부터 id2(중복)·id3·id4 → 2페이지에서 멈춤
    assert (r.inserted, r.duplicates) == (5, 1)
    assert s.checkpoint == base + timedelta(seconds=4)
