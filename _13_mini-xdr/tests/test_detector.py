"""이상탐지 실행기 — 기준선 캐시(시 단위)·학습/채점 구간 분리·behavior 이벤트 중복 방지·이력."""
from datetime import datetime, timedelta, timezone

from app.detector import AnomalyDetector, DetectConfig, detect_summary, report
from app.correlator import EventRow

NOW = datetime(2026, 10, 26, 10, 20, 0, tzinfo=timezone.utc)
CUR = datetime(2026, 10, 26, 10, 0, 0, tzinfo=timezone.utc)
CFG = DetectConfig(baseline_days=30, min_samples=30, threshold=3.0)


def ev(i, ts, ip, event_type="web-scan", layer="app"):
    return EventRow(id=i, ts=ts, layer=layer, source="board", event_type=event_type, src_ip=ip)


def history():
    """어제 IP 40개가 각자 한 시간에 10~14건 → 집단 기준선."""
    out, i = [], 0
    for k in range(40):
        for j in range(10 + k % 5):
            i += 1
            out.append(ev(i, CUR - timedelta(days=1) + timedelta(minutes=j), f"198.51.100.{k}"))
    return out


class FakeStore:
    def __init__(self, events):
        self.events = list(events)
        self.fetches, self.saved, self.scores = [], [], []

    def fetch_events_between(self, start, end):
        self.fetches.append((start, end))
        return [e for e in self.events if start <= e.ts < end and e.layer != "behavior"]

    def save_baselines(self, baselines, now):
        self.saved.append(len(baselines))

    def insert_events(self, events):
        refs = {getattr(e, "raw_ref", None) for e in self.events}
        new = [e for e in events if e.raw_ref not in refs]
        self.events += new
        return len(new)

    def insert_anomaly_score(self, score):
        self.scores.append(score)


def burst(n=200, ip="203.0.113.50", start_id=10_000):
    return [ev(start_id + j, CUR + timedelta(minutes=5, seconds=j), ip) for j in range(n)]


def test_first_run_builds_baseline_from_training_window_and_scores_recent_buckets():
    store = FakeStore(history() + burst())
    r = AnomalyDetector(CFG).run(store, NOW)
    train, target = store.fetches
    assert train == (CUR - timedelta(days=30), CUR - timedelta(hours=1))   # 채점 버킷은 학습에서 빠짐
    assert target == (CUR - timedelta(hours=1), NOW + timedelta(minutes=1))
    assert r.rebuilt and r.population >= 1 and r.individual == 0
    assert (r.targets, r.anomalies, r.new_events) == (1, 1, 1) and len(store.scores) == 1


def test_repeated_runs_insert_behavior_event_only_once():
    store = FakeStore(history() + burst())
    det = AnomalyDetector(CFG)
    det.run(store, NOW)
    r2 = det.run(store, NOW + timedelta(seconds=30))
    assert r2.new_events == 0 and len(store.scores) == 1
    assert len(store.fetches) == 3          # 같은 시(hour) — 학습 구간은 다시 읽지 않음
    assert sum(1 for e in store.events if e.layer == "behavior") == 1


def test_baseline_rebuilt_when_hour_changes():
    store = FakeStore(history())
    det = AnomalyDetector(CFG)
    det.run(store, NOW)
    r = det.run(store, NOW + timedelta(hours=1))
    assert r.rebuilt and len(store.saved) == 2


def test_summary_line():
    r = AnomalyDetector(CFG).run(FakeStore(history() + burst()), NOW)
    line = detect_summary(r)
    assert line.startswith("[이상] 채점 버킷 1 · 이상 1 · 새 behavior 1") and "기준선 재계산" in line


def test_report_scans_whole_window_without_writing():
    store = FakeStore(history() + burst())
    rep = report(store, NOW, CFG)
    assert rep["buckets"] == 41 and rep["flagged"]["events"] == 1 and rep["top"][0]["entity"] == "203.0.113.50"
    assert store.scores == [] and store.saved == []
