"""MySQL 저장소 — events_norm 적재(중복 무시)와 수집 체크포인트. 시각은 모두 UTC."""
from __future__ import annotations

from datetime import datetime, timezone

import pymysql

from app.normalizer import NormalizedEvent

_INSERT = (
    "INSERT IGNORE INTO events_norm "
    "(ts, layer, source, src_ip, user_name, asset, event_type, rule_id, level, mitre, raw_ref) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)


def _naive_utc(ts: datetime) -> datetime:
    return ts.astimezone(timezone.utc).replace(tzinfo=None)


def _aware(ts: datetime | None) -> datetime | None:
    return ts.replace(tzinfo=timezone.utc) if ts else None


class MySQLStore:
    def __init__(self, *, host: str, port: int, user: str, password: str, database: str) -> None:
        self._conn = pymysql.connect(host=host, port=port, user=user, password=password, database=database,
                                     charset="utf8mb4", autocommit=True, init_command="SET time_zone = '+00:00'")

    def insert_events(self, events: list[NormalizedEvent]) -> int:
        """새로 들어간 행 수를 돌려준다(raw_ref 가 이미 있으면 조용히 무시)."""
        rows = [(_naive_utc(e.ts), e.layer, e.source, e.src_ip, e.user_name, e.asset, e.event_type,
                 e.rule_id, e.level, e.mitre, e.raw_ref) for e in events]
        with self._conn.cursor() as cur:
            return cur.executemany(_INSERT, rows) or 0

    def get_checkpoint(self, source: str) -> datetime | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT last_ts FROM checkpoints WHERE source = %s", (source,))
            row = cur.fetchone()
        return _aware(row[0]) if row else None

    def set_checkpoint(self, source: str, ts: datetime, last_id: str | None = None) -> None:
        with self._conn.cursor() as cur:
            # VALUES(col) 은 MySQL 8.0.20 부터 폐지 예고 → 행 별칭(AS new) 문법 사용(8.0.19+)
            cur.execute(
                "INSERT INTO checkpoints (source, last_ts, last_id) VALUES (%s, %s, %s) AS new "
                "ON DUPLICATE KEY UPDATE last_ts = new.last_ts, last_id = new.last_id",
                (source, _naive_utc(ts), last_id),
            )

    def fetch_event_ts(self, raw_ref: str) -> datetime | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT ts FROM events_norm WHERE raw_ref = %s", (raw_ref,))
            row = cur.fetchone()
        return _aware(row[0]) if row else None

    def close(self) -> None:
        self._conn.close()
