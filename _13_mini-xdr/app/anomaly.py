"""행위 이상탐지 — 1시간 버킷 특징을 기준선과 비교하는 robust z-score([186] 4-2). LLM 을 쓰지 않는다.

- 엔티티: 출발지 IP, 계정. 표본: 활동이 있었던 1시간 버킷(로그인 시각은 로그인 1건이 표본 1개).
- robust z = (값 − 중앙값) / max(1.4826 × MAD, 하한) — 폭주가 섞인 기준선에서도 중심이 끌려가지 않는다.
- 기준선 2단: 개인(표본 ≥ min) → 집단(같은 유형 전체, entity='*') → 둘 다 부족하면 채점하지 않는다.
- 버킷 특징 4개는 큰 값만 이상(한쪽), 로그인 시각은 평소 시각과의 원형 거리.
"""
from __future__ import annotations

import hashlib
import math
import statistics
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.correlator import EventRow
from app.normalizer import NormalizedEvent

POPULATION = "*"
BUCKET_FEATURES = ("events", "signals", "login_fail", "ratio_404")
HOUR_FEATURE = "login_hour"
FLOORS = {"events": 1.0, "signals": 1.0, "login_fail": 1.0, "ratio_404": 0.2, HOUR_FEATURE: 1.0}
LOGIN_FAIL, LOGIN_OK = "login-bruteforce", "login-success"
NOT_A_USER = {"", "-", "(unknown)"}
KST = timezone(timedelta(hours=9))


def bucket_start(ts: datetime) -> datetime:
    return ts.replace(minute=0, second=0, microsecond=0)


@dataclass
class BucketAgg:
    entity_type: str        # "ip" · "user"
    entity: str
    start: datetime
    events: int = 0
    signals: set[str] = field(default_factory=set)
    login_fail: int = 0
    login_ok: int = 0
    app_events: int = 0
    n404: int = 0
    last_ts: datetime | None = None
    login_hours: list[float] = field(default_factory=list)   # 계정의 로그인 성공 시각(KST, 시 단위 소수)
    ips: Counter = field(default_factory=Counter)

    def features(self) -> dict[str, float]:
        f: dict[str, float] = {"events": self.events, "signals": len(self.signals)}
        if self.login_fail or self.login_ok:
            f["login_fail"] = self.login_fail
        if self.app_events:
            f["ratio_404"] = self.n404 / self.app_events
        return f

    def top_ip(self) -> str | None:
        return self.ips.most_common(1)[0][0] if self.ips else None


def _entities(e: EventRow):
    if e.src_ip:
        yield "ip", e.src_ip
    if e.user_name and e.user_name not in NOT_A_USER:
        yield "user", e.user_name


def bucketize(events: Iterable[EventRow]) -> dict[tuple[str, str, datetime], BucketAgg]:
    aggs: dict[tuple[str, str, datetime], BucketAgg] = {}
    for e in events:
        if e.layer == "behavior":  # 이상탐지가 만든 이벤트는 다시 세지 않는다
            continue
        start = bucket_start(e.ts)
        for etype, entity in _entities(e):
            a = aggs.setdefault((etype, entity, start), BucketAgg(etype, entity, start))
            a.events += 1
            a.signals.add(e.rule_id or e.event_type)
            if e.event_type == LOGIN_FAIL:
                a.login_fail += 1
            elif e.event_type == LOGIN_OK:
                a.login_ok += 1
                if etype == "user":
                    local = e.ts.astimezone(KST)
                    a.login_hours.append(local.hour + local.minute / 60)
            if e.layer == "app":
                a.app_events += 1
                if e.event_type == "web-scan" or e.rule_id == "100230":
                    a.n404 += 1
            a.last_ts = e.ts if a.last_ts is None else max(a.last_ts, e.ts)
            if etype == "user" and e.src_ip:
                a.ips[e.src_ip] += 1
    return aggs


def robust(values: list[float], floor: float) -> tuple[float, float, int]:
    """(중앙값, max(1.4826×MAD, 하한), 표본 수)."""
    center = statistics.median(values)
    mad = statistics.median([abs(v - center) for v in values])
    return center, max(1.4826 * mad, floor), len(values)


def circular(hours: list[float], floor: float) -> tuple[float, float, int]:
    """시각(0~24)의 원형 평균과 원형 표준편차(시간 단위). 23시와 1시의 평균은 0시."""
    angles = [h / 24 * 2 * math.pi for h in hours]
    c = sum(math.cos(a) for a in angles) / len(angles)
    s = sum(math.sin(a) for a in angles) / len(angles)
    center = (math.atan2(s, c) / (2 * math.pi) * 24) % 24
    r = min(math.hypot(c, s), 1.0)
    std = 12.0 if r < 1e-9 else math.sqrt(-2 * math.log(r)) / (2 * math.pi) * 24
    return center, max(std, floor), len(hours)


def hour_distance(a: float, b: float) -> float:
    d = abs(a - b) % 24
    return min(d, 24 - d)


@dataclass(frozen=True)
class Baseline:
    center: float
    scale: float
    n: int
    kind: str  # "individual" · "population"


def build_baselines(aggs: Iterable[BucketAgg]) -> dict[tuple[str, str, str], Baseline]:
    samples: dict[tuple[str, str, str], list[float]] = {}
    for a in aggs:
        for name, value in a.features().items():
            for entity in (a.entity, POPULATION):
                samples.setdefault((a.entity_type, entity, name), []).append(value)
        if a.entity_type == "user":
            for h in a.login_hours:
                for entity in (a.entity, POPULATION):
                    samples.setdefault(("user", entity, HOUR_FEATURE), []).append(h)
    out = {}
    for (etype, entity, name), values in samples.items():
        kind = "population" if entity == POPULATION else "individual"
        fn = circular if name == HOUR_FEATURE else robust
        out[(etype, entity, name)] = Baseline(*fn(values, FLOORS[name]), kind)
    return out


def pick(baselines: dict, etype: str, entity: str, name: str, min_samples: int) -> Baseline | None:
    for key in ((etype, entity, name), (etype, POPULATION, name)):
        b = baselines.get(key)
        if b and b.n >= min_samples:
            return b
    return None


@dataclass(frozen=True)
class FeatureScore:
    value: float
    z: float
    kind: str
    center: float
    scale: float


@dataclass
class Score:
    agg: BucketAgg
    z: dict[str, FeatureScore]
    anomalies: list[str]

    @property
    def max_z(self) -> float:
        return max((f.z for f in self.z.values()), default=0.0)


def score_bucket(agg: BucketAgg, baselines: dict, *, min_samples: int, threshold: float) -> Score:
    scores: dict[str, FeatureScore] = {}
    for name, value in agg.features().items():
        b = pick(baselines, agg.entity_type, agg.entity, name, min_samples)
        if b:
            scores[name] = FeatureScore(value, (value - b.center) / b.scale, b.kind, b.center, b.scale)
    if agg.entity_type == "user" and agg.login_hours:
        b = pick(baselines, "user", agg.entity, HOUR_FEATURE, min_samples)
        if b:
            hour = max(agg.login_hours, key=lambda h: hour_distance(h, b.center))
            scores[HOUR_FEATURE] = FeatureScore(round(hour, 2), hour_distance(hour, b.center) / b.scale, b.kind,
                                                round(b.center, 2), b.scale)
    anomalies = [name for name, f in scores.items() if f.z >= threshold]
    return Score(agg, scores, anomalies)


def band(z: float) -> str:
    """지문에 들어갈 이상점수 구간."""
    return "z8" if z >= 8 else "z5" if z >= 5 else "z3"


def anomaly_events(score: Score) -> list[NormalizedEvent]:
    """이상 특징마다 behavior 이벤트 1건. raw_ref 가 (유형·엔티티·특징·버킷)로 정해져 다시 채점해도 같다."""
    a = score.agg
    out = []
    for name in score.anomalies:
        key = f"{a.entity_type}|{a.entity}|{name}|{a.start:%Y%m%d%H}"
        out.append(NormalizedEvent(
            ts=a.last_ts, layer="behavior", source="anomaly",
            event_type=f"anomaly-{name}-{band(score.z[name].z)}",
            raw_ref="anom:" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:40],
            src_ip=a.entity if a.entity_type == "ip" else a.top_ip(),
            user_name=a.entity if a.entity_type == "user" else None,
        ))
    return out
