"""분석 워커 — python -m app.worker [--once]

설정(.env)으로 Graylog 클라이언트·MySQL 저장소를 조립해 poll_interval_sec 마다
한 주기(재연결 → 수집 → 이상탐지 → 상관 → 트리아지)를 돈다. 이상탐지가 만든 behavior 이벤트는 같은 주기의
상관에서 인시던트에 붙고, 트리아지는 웹 UI 의 AI 설정을 매 주기 다시 읽는다(키가 없으면 규칙 판정).
한 주기에서 오류가 나도 워커는 멈추지 않고 다음 주기에 다시 시도한다.
"""
from __future__ import annotations

import argparse
import hashlib
import time
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network

from app.collector import CollectConfig, CollectResult, collect_once
from app.config import Settings
from app.correlator import CorrelateResult, correlate_once
from app.detector import AnomalyDetector, DetectConfig, detect_summary
from app.graylog import GraylogClient
from app.llm_settings import effective_llm_config
from app.llm_triage import ClaudeTriager, GeminiTriager
from app.secret_box import SecretBox, SecretBoxError
from app.triage import LLMRoute, TriageConfig, run_triage, triage_summary


def run_cycle(client, store, cfg: CollectConfig, now: datetime | None = None) -> CollectResult:
    return collect_once(client, store, cfg, now or datetime.now(timezone.utc))


def summary_line(r: CollectResult) -> str:
    head = f"[수집] {r.window_from:%m-%d %H:%M:%S}~{r.window_to:%H:%M:%S}Z 페이지 {r.pages} · 조회 {r.fetched} · "
    body = f"적재 {r.inserted} · 중복 {r.duplicates} · 건너뜀 {r.skipped}"
    return head + body + (f" · 오류 {r.error}" if r.error else "")


def correlate_summary(r: CorrelateResult) -> str:
    return f"[상관] 처리 {r.processed} · 새 인시던트 {r.created} · 갱신 {r.updated} · 닫힘 {r.closed}"


def cycle(client, store, cfg: CollectConfig, window: timedelta, now: datetime | None = None,
          detector: AnomalyDetector | None = None, triage=None) -> tuple[list[str], bool]:
    """한 주기: 재연결 → 수집 → 이상탐지 → 상관 → 트리아지. (로그 줄, 실패 여부)를 돌려주고 예외는 밖으로 던지지 않는다."""
    lines: list[str] = []
    try:
        store.ping()
        now = now or datetime.now(timezone.utc)
        collected = run_cycle(client, store, cfg, now)
        lines.append(summary_line(collected))
        if detector is not None:
            lines.append(detect_summary(detector.run(store, now)))
        lines.append(correlate_summary(correlate_once(store, window, now)))
        if triage is not None:
            lines.append(triage.run(store, now))
        return lines, bool(collected.error)
    except Exception as exc:  # DB 재시작 등 — 워커(컨테이너)가 죽지 않고 다음 주기에 다시 시도한다
        lines.append(f"[오류] {type(exc).__name__}: {exc}")
        return lines, True


def build_client(settings: Settings) -> GraylogClient:
    token, user, password = settings.graylog_credentials()
    if not (token or user):
        raise ValueError("Graylog 인증 정보가 없습니다 — .env 에 GRAYLOG_TOKEN 또는 GRAYLOG_USER/GRAYLOG_PASSWORD")
    return GraylogClient(settings.graylog_url, token=token, user=user, password=password)


def collect_config(settings: Settings) -> CollectConfig:
    return CollectConfig(query=settings.graylog_query, page_size=settings.collect_page_size,
                         overlap=timedelta(seconds=settings.collect_overlap_sec),
                         backfill=timedelta(minutes=settings.collect_backfill_min),
                         max_pages=settings.collect_max_pages)


def detect_config(settings: Settings) -> DetectConfig:
    return DetectConfig(baseline_days=settings.baseline_days, min_samples=settings.baseline_min_samples,
                        threshold=settings.anomaly_z)


def triage_config(settings: Settings) -> TriageConfig:
    nets = tuple(ip_network(c.strip(), strict=False) for c in settings.whitelist_cidrs.split(",") if c.strip())
    return TriageConfig(lookback=timedelta(minutes=settings.triage_lookback_min),
                        cooldown=timedelta(seconds=settings.triage_cooldown_sec), batch_size=settings.triage_batch,
                        cache_ttl=timedelta(hours=settings.verdict_cache_hours),
                        max_daily=settings.max_daily_llm_calls, max_hourly=settings.max_hourly_llm_calls,
                        whitelist=nets)


def _secret_box(settings: Settings) -> SecretBox | None:
    key = settings.secret_key_value()
    try:
        return SecretBox(key) if key else None
    except SecretBoxError:
        return None


def llm_route(settings: Settings, store) -> LLMRoute | None:
    """유효 AI 설정(웹 UI > .env)으로 LLM 경로를 만든다. 쓸 수 없으면 None(규칙 판정)."""
    cfg = effective_llm_config(settings, store.settings_repo(), _secret_box(settings))
    if cfg.disabled_reason:
        return None
    if cfg.provider == "gemini":
        return LLMRoute(GeminiTriager(cfg.api_key), cfg.model, settings.gemini_escalate_model or None)
    return LLMRoute(ClaudeTriager(cfg.api_key, cache_ttl=settings.prompt_cache_ttl), cfg.model,
                    settings.claude_escalate_model or None)


class TriageStep:
    """워커 주기의 트리아지 단계 — 설정이 바뀔 때만 LLM 클라이언트를 새로 만든다."""

    def __init__(self, settings: Settings) -> None:
        self.settings, self.cfg = settings, triage_config(settings)
        self._signature, self._route = None, None

    def run(self, store, now: datetime) -> str:
        llm = effective_llm_config(self.settings, store.settings_repo(), _secret_box(self.settings))
        signature = (llm.provider, llm.model, hashlib.sha256((llm.api_key or "").encode()).hexdigest(),
                     llm.disabled_reason)
        if signature != self._signature:
            self._route, self._signature = llm_route(self.settings, store), signature
        line = triage_summary(run_triage(store, self._route, self.cfg, now))
        return line + (f" · LLM 꺼짐({llm.disabled_reason}) → 규칙 판정" if self._route is None else "")


def build_store(settings: Settings):
    from app.store import MySQLStore  # PyMySQL 연결은 실제 실행 때만

    password = settings.mysql_password.get_secret_value() if settings.mysql_password else ""
    return MySQLStore(host=settings.mysql_host, port=settings.mysql_port, user=settings.mysql_user,
                      password=password, database=settings.mysql_db)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mini-xdr 분석 워커(수집 → 이상탐지 → 상관 → 트리아지)")
    parser.add_argument("--once", action="store_true", help="한 주기만 실행하고 종료")
    args = parser.parse_args(argv)
    settings = Settings()
    client, store, cfg = build_client(settings), build_store(settings), collect_config(settings)
    window = timedelta(minutes=settings.correlation_window_min)
    detector = AnomalyDetector(detect_config(settings))  # 기준선 캐시를 주기 사이에 유지
    triage = TriageStep(settings)
    try:
        while True:
            lines, failed = cycle(client, store, cfg, window, detector=detector, triage=triage)
            for line in lines:
                print(line, flush=True)
            if args.once:
                return 1 if failed else 0
            time.sleep(settings.poll_interval_sec)
    except KeyboardInterrupt:
        return 0
    finally:
        client.close()
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
