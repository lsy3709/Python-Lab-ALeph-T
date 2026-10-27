"""워커 조립 — 가짜 의존성으로 한 주기를 돌리고, 설정으로 클라이언트를 만드는 규칙을 확인한다."""
from datetime import datetime, timedelta, timezone

import pytest

from app.config import Settings
from app.correlator import CorrelateResult
from app.detector import AnomalyDetector, DetectConfig
from app.graylog import GraylogClient
from app.worker import (build_client, collect_config, correlate_summary, cycle, detect_config, run_cycle,
                        summary_line)
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

    def fetch_events_between(self, start, end):
        return []

    def save_baselines(self, baselines, now):
        self.baselines_saved = len(baselines)

    def insert_anomaly_score(self, score):
        raise AssertionError("이상이 없으면 기록하지 않아야 한다")


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


def test_cycle_runs_anomaly_between_collect_and_correlate():
    det = AnomalyDetector(DetectConfig())
    lines, failed = cycle(FakeGraylog([]), CycleStore(), CFG, W, NOW, detector=det)
    assert not failed and [line.split(" ")[0] for line in lines] == ["[수집]", "[이상]", "[상관]"]
    assert det.built_for is not None


def test_detect_config_from_settings():
    cfg = detect_config(Settings(_env_file=None, baseline_days=14, baseline_min_samples=20, anomaly_z=4.0))
    assert (cfg.baseline_days, cfg.min_samples, cfg.threshold) == (14, 20, 4.0)
    assert detect_config(Settings(_env_file=None)) == DetectConfig(30, 30, 3.0)


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


class FakeTriageStep:
    def run(self, store, now):
        return "[판정] 대상 0 · 건너뜀 0 · 관문 없음 · LLM 요청 0 · 토큰 입력 0/출력 0/캐시 0 · LLM 꺼짐(gemini API 키 없음)"


def test_cycle_runs_triage_last():
    lines, failed = cycle(FakeGraylog([]), CycleStore(), CFG, W, NOW, detector=AnomalyDetector(DetectConfig()),
                          triage=FakeTriageStep())
    assert not failed and [line.split(" ")[0] for line in lines] == ["[수집]", "[이상]", "[상관]", "[판정]"]


def test_triage_config_parses_whitelist_and_limits():
    from ipaddress import ip_network
    from app.worker import triage_config
    cfg = triage_config(Settings(_env_file=None, whitelist_cidrs="127.0.0.1/32, 10.10.0.0/16", triage_batch=3,
                                 max_hourly_llm_calls=7, triage_lookback_min=30))
    assert cfg.whitelist == (ip_network("127.0.0.1/32"), ip_network("10.10.0.0/16"))
    assert (cfg.batch_size, cfg.max_hourly, cfg.lookback) == (3, 7, timedelta(minutes=30))
    assert cfg.max_daily == 200 and triage_config(Settings(_env_file=None)).whitelist == (ip_network("127.0.0.1/32"),)


class RepoStore:
    def __init__(self, rows=None):
        from tests.test_llm_settings import FakeRepo
        self.repo = FakeRepo()
        for k, val in (rows or {}).items():
            self.repo.put(k, val, False)

    def settings_repo(self):
        return self.repo


def test_llm_route_follows_effective_config():
    from app.llm_triage import ClaudeTriager, GeminiTriager
    from app.worker import llm_route
    fake = "AIza" + "ROUTEFAKE" * 4 + "q1"
    assert llm_route(Settings(_env_file=None), RepoStore()) is None                       # 키 없음 → 규칙 판정
    r = llm_route(Settings(_env_file=None, llm_provider="gemini", gemini_api_key=fake, gemini_model="gm"), RepoStore())
    assert isinstance(r.triager, GeminiTriager) and (r.model, r.escalate_model) == ("gm", None)
    r = llm_route(Settings(_env_file=None, anthropic_api_key="sk-" + "x" * 30), RepoStore())
    assert isinstance(r.triager, ClaudeTriager) and (r.model, r.escalate_model) == ("claude-haiku-5-5", "claude-sonnet-5-5")
    r = llm_route(Settings(_env_file=None, gemini_api_key=fake), RepoStore({"llm_provider": "gemini", "gemini_model": "ui"}))
    assert r.model == "ui"                                                                  # 웹 UI 설정이 우선
