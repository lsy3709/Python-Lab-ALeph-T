"""설정 저장소 — app_settings(웹 UI 설정) 읽기·쓰기와 연결 테스트 사용 기록(llm_calls).

콘솔의 사건 조회는 읽기 전용 연결을 쓰고, 이 모듈은 설정 화면에서만 쓰는 별도의 쓰기 연결을 쓴다.
"""
from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import pymysql

from app.llm_probe import ProbeResult, estimate_cost


def connect_writable(*, host: str, port: int, user: str, password: str, database: str) -> pymysql.Connection:
    return pymysql.connect(host=host, port=port, user=user, password=password, database=database,
                           charset="utf8mb4", autocommit=True, init_command="SET time_zone = '+00:00'")


class MySQLSettingsRepo:
    def __init__(self, conn: pymysql.Connection) -> None:
        self._conn = conn

    def get_all(self) -> dict[str, str]:
        with self._conn.cursor() as cur:
            cur.execute("SELECT name, value FROM app_settings")
            return dict(cur.fetchall())

    def put(self, name: str, value: str, is_secret: bool) -> None:
        with self._conn.cursor() as cur:
            cur.execute("INSERT INTO app_settings (name, value, is_secret) VALUES (%s, %s, %s) AS new "
                        "ON DUPLICATE KEY UPDATE value = new.value, is_secret = new.is_secret",
                        (name, value, is_secret))

    def delete(self, name: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute("DELETE FROM app_settings WHERE name = %s", (name,))


def record_llm_call(conn: pymysql.Connection, r: ProbeResult) -> None:
    """실제로 토큰을 쓴 샘플 호출만 기록한다(모델 목록 조회는 토큰 0 이라 기록하지 않음)."""
    if r.step != "샘플 호출" or not r.model:
        return
    tokens_in, tokens_out = r.input_tokens or 0, r.output_tokens or 0
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO llm_calls (provider, model, input_tokens, output_tokens, cost_usd_est, latency_ms, status, "
            "gate_reason) VALUES (%s, %s, %s, %s, %s, %s, %s, 'connection_test')",
            (r.provider, r.model[:64], tokens_in, tokens_out, estimate_cost(r.provider, r.model, tokens_in, tokens_out),
             r.latency_ms, "ok" if r.ok else "error"))


@contextmanager
def open_settings_conn(settings) -> Iterator[pymysql.Connection]:
    """요청마다 쓰기 연결을 열고 닫는다(설정 화면 전용)."""
    password = settings.mysql_password.get_secret_value() if settings.mysql_password else ""
    conn = connect_writable(host=settings.mysql_host, port=settings.mysql_port, user=settings.mysql_user,
                            password=password, database=settings.mysql_db)
    try:
        yield conn
    finally:
        conn.close()
