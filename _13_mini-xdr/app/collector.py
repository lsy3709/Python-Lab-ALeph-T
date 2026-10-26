"""수집 한 주기 — 체크포인트부터 Graylog 를 오름차순으로 읽어 정규화·적재한다.

같은 밀리초 메시지 묶음에서 멈추지 않도록 offset 으로 넘기고, 늦게 색인된 메시지는
다음 주기의 overlap 재조회와 raw_ref 중복 무시(INSERT IGNORE)로 놓치지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from app.graylog import GraylogError
from app.normalizer import NormalizedEvent, normalize

FIELDS = (
    "gl2_message_id", "timestamp", "source", "rule", "src_ip", "username", "user",
    "wazuh_rule_id", "wazuh_rule_level", "wazuh_rule_groups", "wazuh_rule_mitre_id",
    "wazuh_agent_name", "wazuh_data_srcip", "wazuh_data_dstuser", "wazuh_data_srcuser",
)


class Searcher(Protocol):
    def search_absolute(self, query, frm, to, *, limit, offset, fields=None) -> list[dict]: ...


class EventStore(Protocol):
    def get_checkpoint(self, source: str) -> datetime | None: ...
    def set_checkpoint(self, source: str, ts: datetime, last_id: str | None = None) -> None: ...
    def insert_events(self, events: list[NormalizedEvent]) -> int: ...


@dataclass(frozen=True)
class CollectConfig:
    query: str
    page_size: int = 500
    overlap: timedelta = timedelta(seconds=60)
    backfill: timedelta = timedelta(minutes=1440)
    max_pages: int = 50
    lag: timedelta = timedelta(seconds=2)


@dataclass
class CollectResult:
    fetched: int = 0
    skipped: int = 0
    inserted: int = 0
    duplicates: int = 0
    pages: int = 0
    window_from: datetime | None = None
    window_to: datetime | None = None
    error: str | None = None


def _msg_ts(msg: dict) -> datetime:
    return datetime.fromisoformat(msg["timestamp"].replace("Z", "+00:00"))


def collect_once(client: Searcher, store: EventStore, cfg: CollectConfig, now: datetime,
                 *, source: str = "graylog") -> CollectResult:
    checkpoint = store.get_checkpoint(source)
    start = (checkpoint - cfg.overlap) if checkpoint else (now - cfg.backfill)
    end = now - cfg.lag
    result = CollectResult(window_from=start, window_to=end)
    cursor, offset, last_seen = start, 0, None

    try:
        while True:
            if result.pages >= cfg.max_pages:
                # 한 주기 상한 — 처리한 곳까지만 체크포인트, 나머지는 다음 주기에
                store.set_checkpoint(source, last_seen or start)
                return result
            page = client.search_absolute(cfg.query, cursor, end, limit=cfg.page_size,
                                          offset=offset, fields=FIELDS)
            result.pages += 1
            if not page:
                break
            events = [e for e in (normalize(m) for m in page) if e is not None]
            result.fetched += len(page)
            result.skipped += len(page) - len(events)
            inserted = store.insert_events(events) if events else 0
            result.inserted += inserted
            result.duplicates += len(events) - inserted

            page_last = max(_msg_ts(m) for m in page)
            last_seen = page_last
            if len(page) < cfg.page_size:
                break
            if page_last > cursor:
                cursor, offset = page_last, 0
            else:
                offset += len(page)  # 전부 같은 밀리초 → 다음 묶음으로
    except GraylogError as exc:
        result.error = str(exc)
        return result

    store.set_checkpoint(source, end)
    return result
