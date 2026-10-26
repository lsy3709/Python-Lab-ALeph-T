"""타임라인 — 이어지는 같은 신호를 한 줄로 접는다(연속 길이 부호화).

콘솔 상세 화면이 쓰고, P4 에서는 LLM 에 줄 인시던트 카드도 이 함수로 줄인다(입력 다이어트).
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from app.correlator import EventRow

MAX_USERS = 3


@dataclass
class TimelineItem:
    first: datetime
    last: datetime
    layer: str
    source: str
    signal: str            # 룰 번호 또는 rule
    count: int = 1
    users: list[str] = field(default_factory=list)
    mitre: str | None = None
    max_level: int | None = None


def build_timeline(events: Iterable[EventRow], max_items: int = 200) -> tuple[list[TimelineItem], bool]:
    """(타임라인, 잘렸는지). events 는 시각순이어야 한다."""
    items: list[TimelineItem] = []
    for e in events:
        signal = e.rule_id or e.event_type
        top = items[-1] if items else None
        if top and (top.layer, top.source, top.signal) == (e.layer, e.source, signal):
            top.last, top.count = e.ts, top.count + 1
        else:
            if len(items) == max_items:
                return items, True
            top = TimelineItem(first=e.ts, last=e.ts, layer=e.layer, source=e.source, signal=signal)
            items.append(top)
        if e.user_name and e.user_name not in top.users and len(top.users) < MAX_USERS:
            top.users.append(e.user_name)
        if e.level is not None:
            top.max_level = max(top.max_level or 0, e.level)
        top.mitre = top.mitre or e.mitre
    return items, False


def offset_label(seconds: float) -> str:
    """인시던트 시작부터의 경과 — +0s, +40s, +3m05s, +2h10m."""
    s = int(seconds)
    if s < 60:
        return f"+{s}s"
    if s < 3600:
        return f"+{s // 60}m{s % 60:02d}s"
    return f"+{s // 3600}h{s % 3600 // 60:02d}m"
