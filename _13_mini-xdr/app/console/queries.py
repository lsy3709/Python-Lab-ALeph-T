"""콘솔 조회 — 읽기 전용 세션(transaction_read_only)으로 연결해, 코드에 실수가 있어도 DB 를 바꿀 수 없다."""
from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager

import pymysql
from pymysql.cursors import DictCursor

from app.correlator import EventRow
from app.store import EVENT_COLUMNS, event_from_row

STATUSES = ("all", "open", "closed")
PRIORITY_FILTERS = ("", "P1", "P2", "P3", "P4")
PAGE_SIZE = 50
TIMELINE_FETCH = 2000  # 상세 화면 타임라인에 읽어 올 최대 이벤트 수
_INCIDENT_COLUMNS = ("id, entity_key, status, opened_at, last_event_at, layers, event_count, max_level, "
                     "fingerprint, rule_floor, current_priority")
_FROM_INCIDENT_EVENTS = "FROM incident_events ie JOIN events_norm e ON e.id = ie.event_id WHERE ie.incident_id = %s"


def connect_readonly(*, host: str, port: int, user: str, password: str, database: str) -> pymysql.Connection:
    # 한 SET 문으로 시간대와 읽기 전용을 함께 — 재연결해도 init_command 로 다시 적용된다
    return pymysql.connect(host=host, port=port, user=user, password=password, database=database,
                           charset="utf8mb4", autocommit=True,
                           init_command="SET time_zone = '+00:00', SESSION transaction_read_only = ON")


class ConsoleQueries:
    def __init__(self, conn: pymysql.Connection) -> None:
        self._conn = conn

    def _dicts(self, sql: str, args: tuple = ()) -> list[dict]:
        with self._conn.cursor(DictCursor) as cur:
            cur.execute(sql, args)
            return list(cur.fetchall())

    @staticmethod
    def _parse(row: dict) -> dict:
        row["layers"] = json.loads(row["layers"])
        return row

    def list_incidents(self, *, status: str = "all", priority: str = "", multi: bool = False,
                       page: int = 1) -> tuple[list[dict], int]:
        where, args = [], []
        if status in ("open", "closed"):
            where.append("status = %s")
            args.append(status)
        if priority in PRIORITY_FILTERS[1:]:
            where.append("current_priority = %s")
            args.append(priority)
        if multi:
            where.append("JSON_LENGTH(layers) > 1")
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        total = self._dicts(f"SELECT COUNT(*) AS n FROM incidents {clause}", tuple(args))[0]["n"]
        rows = self._dicts(
            f"SELECT {_INCIDENT_COLUMNS} FROM incidents {clause} "
            "ORDER BY current_priority IS NULL, current_priority, last_event_at DESC LIMIT %s OFFSET %s",
            (*args, PAGE_SIZE, (max(page, 1) - 1) * PAGE_SIZE))
        return [self._parse(r) for r in rows], total

    def get_incident(self, iid: int) -> dict | None:
        rows = self._dicts(f"SELECT {_INCIDENT_COLUMNS} FROM incidents WHERE id = %s", (iid,))
        return self._parse(rows[0]) if rows else None

    def signal_summary(self, iid: int) -> list[dict]:
        # SIGNAL 은 MySQL 예약어라 별칭은 sig
        return self._dicts(
            "SELECT e.layer, e.source, COALESCE(e.rule_id, e.event_type) AS sig, COUNT(*) AS n, "
            "MIN(e.ts) AS first, MAX(e.ts) AS last, MAX(e.level) AS max_level, MAX(e.mitre) AS mitre "
            f"{_FROM_INCIDENT_EVENTS} GROUP BY e.layer, e.source, sig ORDER BY first", (iid,))

    def incident_events(self, iid: int, limit: int = TIMELINE_FETCH) -> list[EventRow]:
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT {EVENT_COLUMNS} {_FROM_INCIDENT_EVENTS} ORDER BY e.ts, e.id LIMIT %s", (iid, limit))
            return [event_from_row(r) for r in cur.fetchall()]

    def users(self, iid: int, limit: int = 10) -> list[str]:
        rows = self._dicts(f"SELECT DISTINCT e.user_name AS u {_FROM_INCIDENT_EVENTS} AND e.user_name IS NOT NULL "
                           "LIMIT %s", (iid, limit))
        return [r["u"] for r in rows]

    def latest_triage(self, iid: int) -> dict | None:
        rows = self._dicts("SELECT source, gate, model, priority, verdict, false_positive_likelihood, confidence, "
                           "reasoning_ko, recommended_playbook, created_at FROM triage_results WHERE incident_id = %s "
                           "ORDER BY id DESC LIMIT 1", (iid,))
        if not rows:
            return None
        r = rows[0]
        for k in ("false_positive_likelihood", "confidence"):
            r[k] = float(r[k]) if r[k] is not None else None
        return r

    def usage_stats(self) -> dict:
        """판정 출처·관문 분포와 LLM 호출 집계(연결 테스트 제외)."""
        decided = self._dicts("SELECT source, gate, COUNT(*) AS n FROM triage_results GROUP BY source, gate")
        by_gate, by_source = {}, {}
        for r in decided:
            by_gate[r["gate"]] = by_gate.get(r["gate"], 0) + r["n"]
            by_source[r["source"]] = by_source.get(r["source"], 0) + r["n"]
        calls = self._dicts(
            "SELECT COUNT(*) AS requests, COALESCE(SUM(input_tokens), 0) AS tokens_in, "
            "COALESCE(SUM(output_tokens), 0) AS tokens_out, COALESCE(SUM(cache_read_tokens), 0) AS cache_read, "
            "COALESCE(SUM(cache_write_tokens), 0) AS cache_write, COALESCE(SUM(cost_usd_est), 0) AS cost "
            "FROM llm_calls WHERE gate_reason <> 'connection_test'")[0]
        by_status = {r["status"]: r["n"] for r in self._dicts(
            "SELECT status, COUNT(*) AS n FROM llm_calls WHERE gate_reason <> 'connection_test' GROUP BY status")}
        by_model = {r["model"]: r["n"] for r in self._dicts(
            "SELECT model, COUNT(*) AS n FROM llm_calls WHERE gate_reason <> 'connection_test' GROUP BY model")}
        cache = self._dicts("SELECT COUNT(*) AS n, COALESCE(SUM(hits), 0) AS hits FROM verdict_cache")[0]
        return {"decisions": sum(by_gate.values()), "by_gate": by_gate, "by_source": by_source,
                "llm_decisions": by_source.get("llm", 0), "cache_decisions": by_source.get("cache", 0),
                "requests": calls["requests"], "tokens_in": int(calls["tokens_in"]), "tokens_out": int(calls["tokens_out"]),
                "cache_read": int(calls["cache_read"]), "cache_write": int(calls["cache_write"]),
                "cost": float(calls["cost"]), "by_status": by_status, "by_model": by_model,
                "floored": by_gate.get("LLM-FLOOR", 0), "cache_rows": cache["n"], "cache_hits": int(cache["hits"])}

    def list_anomalies(self, limit: int = 100) -> list[dict]:
        rows = self._dicts("SELECT id, entity_type, entity, ts, score, features FROM anomaly_scores "
                           "ORDER BY ts DESC, id DESC LIMIT %s", (limit,))
        for r in rows:
            r["features"] = json.loads(r["features"])
        return rows

    def baseline_summary(self, min_samples: int = 30) -> dict:
        population = self._dicts("SELECT entity_type, feature, mean, std, n, updated_at FROM baselines "
                                 "WHERE entity = '*' ORDER BY entity_type, feature")
        individual = self._dicts("SELECT entity_type, entity, COUNT(*) AS features FROM baselines "
                                 "WHERE entity <> '*' AND n >= %s GROUP BY entity_type, entity "
                                 "ORDER BY entity_type, entity", (min_samples,))
        insufficient = self._dicts("SELECT COUNT(*) AS n FROM (SELECT entity_type, entity FROM baselines "
                                   "WHERE entity <> '*' GROUP BY entity_type, entity HAVING MAX(n) < %s) t",
                                   (min_samples,))[0]["n"]
        return {"population": population, "individual": individual, "insufficient": insufficient}

    def stats(self) -> dict:
        s = self._dicts(
            "SELECT (SELECT COUNT(*) FROM events_norm) AS events, (SELECT COUNT(*) FROM incidents) AS incidents, "
            "(SELECT COUNT(*) FROM incidents WHERE status = 'open') AS open_incidents, "
            "(SELECT COUNT(*) FROM incidents WHERE JSON_LENGTH(layers) > 1) AS multi_layer, "
            "(SELECT COALESCE(MAX(id), 0) FROM events_norm) AS max_event_id, "
            "(SELECT last_id FROM checkpoints WHERE source = 'correlator') AS cursor_id")[0]
        s["backlog"] = int(s["max_event_id"]) - int(s["cursor_id"] or 0)  # 아직 상관하지 않은 이벤트 수(근사)
        return s


@contextmanager
def open_queries(settings) -> Iterator[ConsoleQueries]:
    """요청마다 연결을 열고 닫는다(waitress 는 여러 스레드 — 연결 하나를 나눠 쓰지 않는다)."""
    password = settings.mysql_password.get_secret_value() if settings.mysql_password else ""
    conn = connect_readonly(host=settings.mysql_host, port=settings.mysql_port, user=settings.mysql_user,
                            password=password, database=settings.mysql_db)
    try:
        yield ConsoleQueries(conn)
    finally:
        conn.close()
