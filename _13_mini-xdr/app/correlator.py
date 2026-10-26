"""상관 — 같은 엔티티의 이벤트를 '쉬는 틈' 기준 창으로 묶어 인시던트를 만든다([186] ③).

엔티티 키는 출발지 IP > 계정 > 자산(에이전트) 순으로 정한다. src_ip 가 없는 호스트 점검 경보는
에이전트 이름으로 묶인다. 엔티티의 최근 인시던트 [opened_at - W, last_event_at + W] 안에 들어오는
이벤트는 그 인시던트에 붙고, 아니면 새 인시던트를 연다. W 동안 조용하면 닫힌다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from app.fingerprint import fingerprint, signal_of

PRIORITIES = ("P1", "P2", "P3", "P4")  # 앞쪽일수록 급함


@dataclass(frozen=True)
class EventRow:
    """events_norm 한 행 — 상관·타임라인의 입력."""
    id: int
    ts: datetime          # UTC aware
    layer: str
    source: str
    event_type: str
    src_ip: str | None = None
    user_name: str | None = None
    asset: str | None = None
    rule_id: str | None = None
    level: int | None = None
    mitre: str | None = None


def entity_key(e: EventRow) -> str:
    if e.src_ip:
        return f"ip:{e.src_ip}"
    if e.user_name:
        return f"user:{e.user_name}"
    return f"asset:{e.asset or e.source}"


def rule_floor(max_level: int | None) -> str:
    """Wazuh level → AI 가 더 낮출 수 없는 우선순위 하한([186] 4-4 방어 4)."""
    level = max_level or 0
    if level >= 12:
        return "P1"
    if level >= 10:
        return "P2"
    if level >= 7:
        return "P3"
    return "P4"


def higher(a: str | None, b: str) -> str:
    """더 급한 우선순위(P1 이 가장 급함)."""
    return b if a is None else min(a, b, key=PRIORITIES.index)


@dataclass
class IncidentState:
    entity_key: str
    opened_at: datetime
    last_event_at: datetime
    id: int | None = None  # None = 아직 DB 에 없는 새 인시던트
    status: str = "open"
    layers: set[str] = field(default_factory=set)
    signals: set[str] = field(default_factory=set)
    event_count: int = 0
    max_level: int | None = None
    current_priority: str | None = None

    @property
    def entity_type(self) -> str:
        return self.entity_key.split(":", 1)[0]

    @property
    def rule_floor(self) -> str:
        return rule_floor(self.max_level)

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.entity_type, self.layers, self.signals)

    def covers(self, ts: datetime, window: timedelta) -> bool:
        return self.opened_at - window <= ts <= self.last_event_at + window

    def absorb(self, e: EventRow) -> None:
        self.opened_at = min(self.opened_at, e.ts)
        self.last_event_at = max(self.last_event_at, e.ts)
        self.layers.add(e.layer)
        self.signals.add(signal_of(e.layer, e.source, e.rule_id, e.event_type))
        self.event_count += 1
        if e.level is not None:
            self.max_level = max(self.max_level or 0, e.level)


@dataclass
class CorrelationBatch:
    touched: list[IncidentState]            # 새로 열었거나 바뀐 인시던트
    links: list[tuple[IncidentState, int]]  # (인시던트, event_id)
    created: int


def correlate(events: list[EventRow], latest: dict[str, IncidentState], window: timedelta,
              now: datetime) -> CorrelationBatch:
    """events 를 시각순으로 인시던트에 붙인다. latest(엔티티별 최근 인시던트)는 제자리에서 갱신된다."""
    touched: dict[int, IncidentState] = {}
    links: list[tuple[IncidentState, int]] = []
    created = 0
    for e in sorted(events, key=lambda x: (x.ts, x.id)):
        key = entity_key(e)
        inc = latest.get(key)
        if inc is None or not inc.covers(e.ts, window):
            new = IncidentState(entity_key=key, opened_at=e.ts, last_event_at=e.ts)
            if inc is None or e.ts > inc.last_event_at:  # 늦게 도착한 과거 이벤트는 '최근'을 바꾸지 않는다
                latest[key] = new
            inc, created = new, created + 1
        inc.absorb(e)
        touched[id(inc)] = inc
        links.append((inc, e.id))
    for inc in touched.values():
        inc.status = "open" if inc.last_event_at >= now - window else "closed"
        inc.current_priority = higher(inc.current_priority, inc.rule_floor)
    return CorrelationBatch(list(touched.values()), links, created)
