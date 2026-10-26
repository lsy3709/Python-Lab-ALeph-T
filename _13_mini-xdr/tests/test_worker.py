"""워커 조립 — 가짜 의존성으로 한 주기를 돌리고, 설정으로 클라이언트를 만드는 규칙을 확인한다."""
from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings
from app.correlator import CorrelateResult
from app.graylog import GraylogClient
from app.worker import build_client, collect_config, correlate_summary, cycle, run_cycle, summary_line
from tests.test_collector import CFG, FakeGraylog, FakeStore, msg

NOW = datetime(2026, 10, 26, 6, 0, 0, tzinfo=timezone.utc)
W = timedelta(minutes=10)


class CycleStore(FakeStore):
    """수집용 가짜 저장소 + 상관용 메서드(상관할 새 이벤트는 없음)."""

    def __init__(self, fail_ping=False):
        super().__init__()
        self.fail_ping = fail_ping

    def ping(self):
        if self.fail_ping:
            raise ConnectionError("DB 연결 끊김(시험)")

    def get_cursor(self, source):
        return 0

    def fetch_events_after(self, last_id, limit):
        return []

    def load_latest_incidents(self, keys):
        return {}

    def save_correlation(self, batch, source, last):
        raise AssertionError("새 이벤트가 없으면 저장하지 않아야 한다")

    def close_stale(self, before):
        return 2


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)


def test_run_cycle_and_summary_line():
    r = run_cycle(FakeGraylog([msg(1, NOW - timedelta(minutes=2))]), FakeStore(), CFG, NOW)
    line = summary_line(r)
    assert r.inserted == 1
    assert "적재 1" in line and "중복 0" in line and "오류" not in line


def test_summary_line_shows_error():
    r = run_cycle(FakeGraylog([], fail=True), FakeStore(), CFG, NOW)
    assert "오류" in summary_line(r)


def test_cycle_collects_then_correlates():
    lines, failed = cycle(FakeGraylog([msg(1, NOW - timedelta(minutes=2))]), CycleStore(), CFG, W, NOW)
    assert not failed
    assert lines[0].startswith("[수집]") and "적재 1" in lines[0]
    assert lines[1] == "[상관] 처리 0 · 새 인시던트 0 · 갱신 0 · 닫힘 2"


def test_cycle_survives_db_error_without_raising():
    lines, failed = cycle(FakeGraylog([]), CycleStore(fail_ping=True), CFG, W, NOW)
    assert failed and lines == ["[오류] ConnectionError: DB 연결 끊김(시험)"]


def test_cycle_marks_collect_error_as_failed_but_still_correlates():
    lines, failed = cycle(FakeGraylog([], fail=True), CycleStore(), CFG, W, NOW)
    assert failed and "오류" in lines[0] and lines[1].startswith("[상관]")


def test_correlate_summary():
    r = CorrelateResult(processed=5, created=2, updated=1, closed=3)
    assert correlate_summary(r) == "[상관] 처리 5 · 새 인시던트 2 · 갱신 1 · 닫힘 3"


def test_build_client_requires_graylog_auth():
    with pytest.raises(ValueError):
        build_client(Settings(_env_file=None))
    client = build_client(Settings(_env_file=None, graylog_token="t" * 40))
    assert isinstance(client, GraylogClient)
    client.close()


def test_collect_config_from_settings():
    cfg = collect_config(Settings(_env_file=None, collect_page_size=200, collect_overlap_sec=30))
    assert cfg.page_size == 200 and cfg.overlap == timedelta(seconds=30)
    assert cfg.query == "_exists_:wazuh_rule_id OR _exists_:rule"
