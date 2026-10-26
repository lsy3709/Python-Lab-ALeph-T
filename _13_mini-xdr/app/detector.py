"""이상탐지 실행기 — 기준선은 시(hour)가 바뀔 때만 다시 계산하고, 매 주기 직전·현재 버킷만 채점한다.

사후 분석: python -m app.detector --report  (전체 기간 기준선으로 과거 버킷을 훑는다 — DB 에 쓰지 않음)
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol

from app.anomaly import (POPULATION, Score, anomaly_events, band, bucket_start, bucketize, build_baselines,
                         score_bucket)
from app.correlator import EventRow
from app.normalizer import NormalizedEvent

FUTURE_SLACK = timedelta(minutes=1)  # 시계가 조금 앞선 센서의 이벤트도 채점 구간에 넣는다


@dataclass(frozen=True)
class DetectConfig:
    baseline_days: int = 30
    min_samples: int = 30
    threshold: float = 3.0


@dataclass
class DetectResult:
    targets: int = 0       # 채점한 버킷 수
    anomalies: int = 0     # 이상 특징이 하나라도 있는 버킷 수
    new_events: int = 0    # 새로 넣은 behavior 이벤트 수
    individual: int = 0    # 쓸 수 있는 개인 기준선(엔티티×특징) 수
    population: int = 0    # 쓸 수 있는 집단 기준선 수
    rebuilt: bool = False


class DetectorStore(Protocol):
    def fetch_events_between(self, start: datetime, end: datetime) -> list[EventRow]: ...
    def save_baselines(self, baselines: dict, now: datetime) -> None: ...
    def insert_events(self, events: list[NormalizedEvent]) -> int: ...
    def insert_anomaly_score(self, score: Score) -> None: ...


class AnomalyDetector:
    def __init__(self, cfg: DetectConfig) -> None:
        self.cfg = cfg
        self.baselines: dict = {}
        self.built_for: datetime | None = None

    def _score(self, agg) -> Score:
        return score_bucket(agg, self.baselines, min_samples=self.cfg.min_samples, threshold=self.cfg.threshold)

    def run(self, store: DetectorStore, now: datetime) -> DetectResult:
        r = DetectResult()
        current = bucket_start(now)
        target_from = current - timedelta(hours=1)
        if self.built_for != current:  # 학습 구간 = 채점 버킷(직전·현재) 이전 — 자기 자신이 기준선에 섞이지 않게
            train = store.fetch_events_between(current - timedelta(days=self.cfg.baseline_days), target_from)
            self.baselines = build_baselines(bucketize(train).values())
            store.save_baselines(self.baselines, now)
            self.built_for, r.rebuilt = current, True
        usable = [key for key, b in self.baselines.items() if b.n >= self.cfg.min_samples]
        r.individual = sum(1 for key in usable if key[1] != POPULATION)
        r.population = len(usable) - r.individual
        for agg in bucketize(store.fetch_events_between(target_from, now + FUTURE_SLACK)).values():
            s = self._score(agg)
            r.targets += 1
            if not s.anomalies:
                continue
            r.anomalies += 1
            inserted = store.insert_events(anomaly_events(s))  # raw_ref 가 같으면 무시 → 버킷당 한 번
            if inserted:
                store.insert_anomaly_score(s)
                r.new_events += inserted
        return r


def detect_summary(r: DetectResult) -> str:
    line = (f"[이상] 채점 버킷 {r.targets} · 이상 {r.anomalies} · 새 behavior {r.new_events} · "
            f"기준선 개인 {r.individual} / 집단 {r.population}")
    return line + (" · 기준선 재계산" if r.rebuilt else "")


def report(store: DetectorStore, now: datetime, cfg: DetectConfig, top: int = 10) -> dict:
    """전체 기간 기준선으로 과거 버킷을 모두 채점한 사후 분석(미래 데이터도 기준선에 섞인다 — 경향 파악용)."""
    aggs = bucketize(store.fetch_events_between(now - timedelta(days=cfg.baseline_days), now + FUTURE_SLACK))
    det = AnomalyDetector(cfg)
    det.baselines = build_baselines(aggs.values())
    scores = [det._score(a) for a in aggs.values()]
    flagged = Counter(name for s in scores for name in s.anomalies)
    ranked = sorted((s for s in scores if s.anomalies), key=lambda s: -s.max_z)[:top]
    usable = {k: b for k, b in det.baselines.items() if b.n >= cfg.min_samples}
    return {
        "buckets": len(scores),
        "flagged_buckets": sum(1 for s in scores if s.anomalies),
        "flagged": dict(flagged),
        "bands": dict(Counter(band(s.max_z) for s in scores if s.anomalies)),
        "population": {f"{k[0]}:{k[2]}": (round(b.center, 2), round(b.scale, 2), b.n)
                       for k, b in sorted(usable.items()) if k[1] == POPULATION},
        "individual": sorted({f"{k[0]}:{k[1]}" for k in usable if k[1] != POPULATION}),
        "top": [{"entity": s.agg.entity, "type": s.agg.entity_type, "bucket": s.agg.start,
                 "features": {n: (round(s.z[n].value, 2), round(s.z[n].z, 1), s.z[n].kind) for n in s.anomalies}}
                for s in ranked],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mini-xdr 행위 이상탐지 사후 분석(쓰기 없음)")
    parser.add_argument("--report", action="store_true", required=True)
    parser.parse_args(argv)
    from app.config import Settings
    from app.worker import build_store, detect_config

    settings = Settings()
    store = build_store(settings)
    try:
        rep = report(store, datetime.now(timezone.utc), detect_config(settings))
    finally:
        store.close()
    print(f"버킷 {rep['buckets']} · 이상 버킷 {rep['flagged_buckets']} · 특징별 {rep['flagged']}")
    print(f"이상 버킷의 최대 z 구간: {rep['bands']}  (z3=3~5 · z5=5~8 · z8=8 이상)")
    print("집단 기준선(중심, 척도, 표본):")
    for name, value in rep["population"].items():
        print(f"  {name:<16} {value}")
    print(f"개인 기준선이 있는 엔티티: {rep['individual']}")
    print("상위 이상:")
    for t in rep["top"]:
        print(f"  {t['bucket']:%m-%d %H시}Z {t['type']}:{t['entity']}  {t['features']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
