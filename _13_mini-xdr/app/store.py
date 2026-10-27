"""MySQL 저장소 — events_norm 적재(중복 무시)·수집 체크포인트·상관 저장. 시각은 모두 UTC."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pymysql

from app.correlator import CorrelationBatch, EventRow, IncidentState
from app.fingerprint import signal_of
from app.normalizer import NormalizedEvent

_INSERT = (
    "INSERT IGNORE INTO events_norm "
    "(ts, layer, source, src_ip, user_name, asset, event_type, rule_id, level, mitre, raw_ref) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
_INSERT_INCIDENT = (
    "INSERT INTO incidents (entity_key, status, opened_at, last_event_at, layers, event_count, max_level, "
    "fingerprint, rule_floor, current_priority) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)
_UPDATE_INCIDENT = (
    "UPDATE incidents SET status = %s, opened_at = %s, last_event_at = %s, layers = %s, event_count = %s, "
    "max_level = %s, fingerprint = %s, rule_floor = %s, current_priority = %s WHERE id = %s"
)
# events_norm 을 e 로 부를 때의 열 순서 — event_from_row 와 짝(콘솔도 함께 쓴다)
EVENT_COLUMNS = "e.id, e.ts, e.layer, e.source, e.event_type, e.src_ip, e.user_name, e.asset, e.rule_id, e.level, e.mitre"


def _naive_utc(ts: datetime) -> datetime:
    return ts.astimezone(timezone.utc).replace(tzinfo=None)


def _aware(ts: datetime | None) -> datetime | None:
    return ts.replace(tzinfo=timezone.utc) if ts else None


def event_from_row(r: tuple) -> EventRow:
    return EventRow(id=r[0], ts=_aware(r[1]), layer=r[2], source=r[3], event_type=r[4], src_ip=r[5],
                    user_name=r[6], asset=r[7], rule_id=r[8], level=r[9], mitre=r[10])


def _upsert_checkpoint(cur, source: str, ts: datetime, last_id: str | None) -> None:
    # VALUES(col) 은 MySQL 8.0.20 부터 폐지 예고 → 행 별칭(AS new) 문법 사용(8.0.19+)
    cur.execute(
        "INSERT INTO checkpoints (source, last_ts, last_id) VALUES (%s, %s, %s) AS new "
        "ON DUPLICATE KEY UPDATE last_ts = new.last_ts, last_id = new.last_id",
        (source, _naive_utc(ts), last_id),
    )


def _marks(n: int) -> str:
    return ", ".join(["%s"] * n)


class MySQLStore:
    def __init__(self, *, host: str, port: int, user: str, password: str, database: str) -> None:
        self._connect_kwargs = dict(host=host, port=port, user=user, password=password, database=database,
                                    charset="utf8mb4", autocommit=True, init_command="SET time_zone = '+00:00'")
        self._conn = pymysql.connect(**self._connect_kwargs)

    def ping(self) -> None:
        """연결이 끊겼으면 새로 연결한다(컨테이너 워커가 DB 재시작을 견디게).

        PyMySQL 1.2 부터 ping(reconnect=True) 는 폐지 예고 → 끊김을 확인하고 새 연결을 만든다.
        """
        try:
            self._conn.ping(reconnect=False)
        except pymysql.err.Error:
            try:
                self._conn.close()
            except pymysql.err.Error:
                pass
            self._conn = pymysql.connect(**self._connect_kwargs)

    # ── 수집 ─────────────────────────────────────────────
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
            _upsert_checkpoint(cur, source, ts, last_id)

    def fetch_event_ts(self, raw_ref: str) -> datetime | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT ts FROM events_norm WHERE raw_ref = %s", (raw_ref,))
            row = cur.fetchone()
        return _aware(row[0]) if row else None

    # ── 상관 ─────────────────────────────────────────────
    def get_cursor(self, source: str) -> int:
        """상관 진행 위치(마지막으로 처리한 events_norm.id). 처음이면 0."""
        with self._conn.cursor() as cur:
            cur.execute("SELECT last_id FROM checkpoints WHERE source = %s", (source,))
            row = cur.fetchone()
        return int(row[0]) if row and row[0] else 0

    def fetch_events_after(self, last_id: int, limit: int) -> list[EventRow]:
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT {EVENT_COLUMNS} FROM events_norm e WHERE e.id > %s ORDER BY e.id LIMIT %s",
                        (last_id, limit))
            return [event_from_row(r) for r in cur.fetchall()]

    def load_latest_incidents(self, keys: set[str]) -> dict[str, IncidentState]:
        """엔티티별 최근 인시던트(마지막 시각 기준). 신호 집합은 연결된 이벤트에서 다시 읽는다."""
        if not keys:
            return {}
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT id, entity_key, status, opened_at, last_event_at, layers, event_count, max_level, "
                "current_priority FROM (SELECT i.*, ROW_NUMBER() OVER (PARTITION BY entity_key "
                "ORDER BY last_event_at DESC, id DESC) AS rn FROM incidents i "
                f"WHERE entity_key IN ({_marks(len(keys))})) t WHERE rn = 1", tuple(keys))
            found = {r[1]: IncidentState(entity_key=r[1], id=r[0], status=r[2], opened_at=_aware(r[3]),
                                         last_event_at=_aware(r[4]), layers=set(json.loads(r[5])),
                                         event_count=r[6], max_level=r[7], current_priority=r[8])
                     for r in cur.fetchall()}
            if found:
                by_id = {inc.id: inc for inc in found.values()}
                cur.execute(
                    "SELECT DISTINCT ie.incident_id, e.layer, e.source, e.rule_id, e.event_type "
                    "FROM incident_events ie JOIN events_norm e ON e.id = ie.event_id "
                    f"WHERE ie.incident_id IN ({_marks(len(by_id))})", tuple(by_id))
                for iid, layer, source, rule_id, event_type in cur.fetchall():
                    by_id[iid].signals.add(signal_of(layer, source, rule_id, event_type))
        return found

    def save_correlation(self, batch: CorrelationBatch, source: str, last: EventRow) -> None:
        """인시던트·이벤트 연결·진행 위치를 한 트랜잭션으로 — 중간에 끊겨도 반쯤 저장되지 않는다."""
        self._conn.begin()
        try:
            with self._conn.cursor() as cur:
                for inc in batch.touched:
                    vals = (inc.status, _naive_utc(inc.opened_at), _naive_utc(inc.last_event_at),
                            json.dumps(sorted(inc.layers)), inc.event_count, inc.max_level, inc.fingerprint,
                            inc.rule_floor, inc.current_priority)
                    if inc.id is None:
                        cur.execute(_INSERT_INCIDENT, (inc.entity_key, *vals))
                        inc.id = cur.lastrowid
                    else:
                        cur.execute(_UPDATE_INCIDENT, (*vals, inc.id))
                if batch.links:
                    cur.executemany("INSERT IGNORE INTO incident_events (incident_id, event_id) VALUES (%s, %s)",
                                    [(inc.id, event_id) for inc, event_id in batch.links])
                _upsert_checkpoint(cur, source, last.ts, str(last.id))
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ── 행위 이상탐지 ─────────────────────────────────────
    def fetch_events_between(self, start: datetime, end: datetime) -> list[EventRow]:
        """[start, end) 의 이벤트 — 이상탐지가 만든 behavior 는 빼고(다시 세지 않게)."""
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT {EVENT_COLUMNS} FROM events_norm e WHERE e.ts >= %s AND e.ts < %s "
                        "AND e.layer <> 'behavior' ORDER BY e.ts, e.id", (_naive_utc(start), _naive_utc(end)))
            return [event_from_row(r) for r in cur.fetchall()]

    def save_baselines(self, baselines: dict, now: datetime) -> None:
        """기준선 테이블을 통째로 교체한다(한 트랜잭션) — 학습 구간에서 사라진 엔티티는 지워진다.
        mean·std 열에는 robust 중심(중앙값·원형 평균)과 척도(1.4826·MAD 또는 원형 표준편차)를 넣는다."""
        rows = [(etype, entity[:128], name, b.center, b.scale, b.n, _naive_utc(now))
                for (etype, entity, name), b in baselines.items()]
        self._conn.begin()
        try:
            with self._conn.cursor() as cur:
                cur.execute("DELETE FROM baselines")
                if rows:
                    cur.executemany("INSERT INTO baselines (entity_type, entity, feature, mean, std, n, updated_at) "
                                    "VALUES (%s, %s, %s, %s, %s, %s, %s)", rows)
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def insert_anomaly_score(self, score) -> None:
        feats = {name: {"value": round(f.value, 3), "z": round(f.z, 2), "kind": f.kind,
                        "center": round(f.center, 3), "scale": round(f.scale, 3)} for name, f in score.z.items()}
        a = score.agg
        with self._conn.cursor() as cur:
            cur.execute("INSERT INTO anomaly_scores (entity_type, entity, ts, score, features) VALUES (%s, %s, %s, %s, %s)",
                        (a.entity_type, a.entity[:128], _naive_utc(a.last_ts), round(score.max_z, 3),
                         json.dumps(feats, ensure_ascii=False)))

    # ── 트리아지 ───────────────────────────────────────
    def settings_repo(self):
        """웹 UI 설정(app_settings) — 워커가 매 주기 공급자·모델·키를 다시 읽는다."""
        from app.settings_store import MySQLSettingsRepo

        return MySQLSettingsRepo(self._conn)

    def triage_candidates(self, since: datetime | None, limit: int | None) -> list[dict]:
        """limit 이 있으면 최근 N건, 없으면 열린 인시던트 + 마지막 이벤트가 since 이후인 것."""
        cols = ("id, entity_key, status, opened_at, last_event_at, layers, event_count, max_level, fingerprint, "
                "rule_floor, current_priority, last_triaged_at, material_state")
        with self._conn.cursor(pymysql.cursors.DictCursor) as cur:
            if limit:
                cur.execute(f"SELECT {cols} FROM incidents ORDER BY last_event_at DESC LIMIT %s", (limit,))
            else:
                cur.execute(f"SELECT {cols} FROM incidents WHERE status = 'open' OR last_event_at >= %s "
                            "ORDER BY last_event_at", (_naive_utc(since),))
            rows = list(cur.fetchall())
        for r in rows:
            r["layers"] = json.loads(r["layers"])
            r["material_state"] = json.loads(r["material_state"]) if r["material_state"] else None
            for k in ("opened_at", "last_event_at", "last_triaged_at"):
                r[k] = _aware(r[k])
        return rows

    def card_inputs(self, incident_id: int, events_limit: int = 2000) -> dict:
        join = "FROM incident_events ie JOIN events_norm e ON e.id = ie.event_id WHERE ie.incident_id = %s"
        with self._conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("SELECT e.layer, e.source, COALESCE(e.rule_id, e.event_type) AS sig, COUNT(*) AS n, "
                        f"MAX(e.level) AS max_level, MAX(e.mitre) AS mitre {join} GROUP BY e.layer, e.source, sig",
                        (incident_id,))
            summary = list(cur.fetchall())
            cur.execute(f"SELECT DISTINCT e.user_name AS u {join} AND e.user_name IS NOT NULL "
                        "AND e.user_name <> '(unknown)' LIMIT 10", (incident_id,))
            users = [r["u"] for r in cur.fetchall()]
            cur.execute("SELECT entity_key, opened_at, last_event_at FROM incidents WHERE id = %s", (incident_id,))
            inc = cur.fetchone()
        with self._conn.cursor() as cur:
            cur.execute(f"SELECT {EVENT_COLUMNS} {join} ORDER BY e.ts, e.id LIMIT %s", (incident_id, events_limit))
            events = [event_from_row(r) for r in cur.fetchall()]
            anomalies = []
            etype, entity = inc["entity_key"].split(":", 1)
            if etype in ("ip", "user"):  # 이 엔티티의 이상 점수 중 인시던트 기간(앞뒤 1시간) 안의 것
                cur.execute("SELECT features FROM anomaly_scores WHERE entity_type = %s AND entity = %s "
                            "AND ts BETWEEN %s - INTERVAL 1 HOUR AND %s + INTERVAL 1 HOUR ORDER BY score DESC LIMIT 5",
                            (etype, entity, inc["opened_at"], inc["last_event_at"]))
                anomalies = [{"features": json.loads(r[0])} for r in cur.fetchall()]
        return {"summary": summary, "events": events, "anomalies": anomalies, "users": users,
                "signals": [s["sig"] for s in summary]}

    def get_cached_verdict(self, fingerprint: str, now: datetime) -> dict | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT verdict, model FROM verdict_cache WHERE fingerprint = %s AND expires_at > %s",
                        (fingerprint, _naive_utc(now)))
            row = cur.fetchone()
        return {**json.loads(row[0]), "model": row[1]} if row else None

    def hit_cached_verdict(self, fingerprint: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute("UPDATE verdict_cache SET hits = hits + 1 WHERE fingerprint = %s", (fingerprint,))

    def put_cached_verdict(self, fingerprint: str, verdict: dict, model: str, expires_at: datetime) -> None:
        with self._conn.cursor() as cur:
            cur.execute("INSERT INTO verdict_cache (fingerprint, verdict, model, expires_at) VALUES (%s, %s, %s, %s) AS new "
                        "ON DUPLICATE KEY UPDATE verdict = new.verdict, model = new.model, expires_at = new.expires_at",
                        (fingerprint, json.dumps(verdict, ensure_ascii=False), model[:64], _naive_utc(expires_at)))

    def llm_usage(self, now: datetime) -> dict:
        """트리아지 호출 수(일·시간)와 최근 10분 연속 오류 수 — 연결 테스트(connection_test)는 예산에서 뺀다."""
        n = _naive_utc(now)
        with self._conn.cursor() as cur:
            cur.execute("SELECT SUM(ts >= %s - INTERVAL 1 DAY), SUM(ts >= %s - INTERVAL 1 HOUR) FROM llm_calls "
                        "WHERE gate_reason <> 'connection_test'", (n, n))
            day, hour = cur.fetchone()
            cur.execute("SELECT status FROM llm_calls WHERE gate_reason <> 'connection_test' "
                        "AND ts >= %s - INTERVAL 10 MINUTE ORDER BY id DESC LIMIT 10", (n,))
            recent = [r[0] for r in cur.fetchall()]
        errors = 0
        for status in recent:
            if status != "error":
                break
            errors += 1
        return {"day": int(day or 0), "hour": int(hour or 0), "recent_errors": errors}

    def record_llm_call(self, result, incidents_in_batch: int, gate_reason: str, cache_ttl: str = "5m") -> None:
        from app.llm_triage import estimate_call_cost

        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO llm_calls (provider, model, incidents_in_batch, input_tokens, output_tokens, cache_read_tokens, "
                "cache_write_tokens, cost_usd_est, latency_ms, status, gate_reason) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (result.provider, result.model[:64], incidents_in_batch, result.input_tokens, result.output_tokens,
                 result.cache_read, result.cache_write, estimate_call_cost(result, cache_ttl), result.latency_ms,
                 result.status, gate_reason[:64]))

    def save_decision(self, inc: dict, decision, material: dict, now: datetime) -> None:
        """판정 이력 1행 + 인시던트의 현재 우선순위·마지막 판정 시각·실질 상태를 한 트랜잭션으로."""
        d = decision
        self._conn.begin()
        try:
            with self._conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO triage_results (incident_id, source, gate, model, priority, verdict, "
                    "false_positive_likelihood, reasoning_ko, recommended_playbook, confidence) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                    (inc["id"], d.source, d.gate[:16], (d.model or None) and d.model[:64], d.priority, d.verdict,
                     d.false_positive_likelihood, d.reasoning_ko[:600], d.recommended_playbook, d.confidence))
                cur.execute("UPDATE incidents SET current_priority = %s, last_triaged_at = %s, material_state = %s "
                            "WHERE id = %s", (d.priority, _naive_utc(now), json.dumps(material), inc["id"]))
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def close_stale(self, before: datetime) -> int:
        """마지막 이벤트가 before 보다 이른 열린 인시던트를 닫는다."""
        with self._conn.cursor() as cur:
            return cur.execute("UPDATE incidents SET status = 'closed' WHERE status = 'open' AND last_event_at < %s",
                               (_naive_utc(before),))

    def close(self) -> None:
        self._conn.close()
