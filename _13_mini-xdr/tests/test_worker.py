"""워커 조립 — 가짜 의존성으로 한 주기를 돌리고, 설정으로 클라이언트를 만드는 규칙을 확인한다."""
from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings
from app.graylog import GraylogClient
from app.worker import build_client, collect_config, run_cycle, summary_line
from tests.test_collector import CFG, FakeGraylog, FakeStore, msg

NOW = datetime(2026, 10, 26, 6, 0, 0, tzinfo=timezone.utc)


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
