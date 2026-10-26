"""분석 워커 — python -m app.worker [--once]

설정(.env)으로 Graylog 클라이언트·MySQL 저장소를 조립해 poll_interval_sec 마다
한 주기(재연결 → 수집 → 이상탐지 → 상관)를 돈다. 이상탐지가 만든 behavior 이벤트는 같은 주기의 상관에서
인시던트에 붙는다. 한 주기에서 오류가 나도 워커는 멈추지 않고 다음 주기에 다시 시도한다.
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timedelta, timezone

from app.collector import CollectConfig, CollectResult, collect_once
from app.config import Settings
from app.correlator import CorrelateResult, correlate_once
from app.detector import AnomalyDetector, DetectConfig, detect_summary
from app.graylog import GraylogClient


def run_cycle(client, store, cfg: CollectConfig, now: datetime | None = None) -> CollectResult:
    return collect_once(client, store, cfg, now or datetime.now(timezone.utc))


def summary_line(r: CollectResult) -> str:
    head = f"[수집] {r.window_from:%m-%d %H:%M:%S}~{r.window_to:%H:%M:%S}Z 페이지 {r.pages} · 조회 {r.fetched} · "
    body = f"적재 {r.inserted} · 중복 {r.duplicates} · 건너뜀 {r.skipped}"
    return head + body + (f" · 오류 {r.error}" if r.error else "")


def correlate_summary(r: CorrelateResult) -> str:
    return f"[상관] 처리 {r.processed} · 새 인시던트 {r.created} · 갱신 {r.updated} · 닫힘 {r.closed}"


def cycle(client, store, cfg: CollectConfig, window: timedelta, now: datetime | None = None,
          detector: AnomalyDetector | None = None) -> tuple[list[str], bool]:
    """한 주기: 재연결 → 수집 → 이상탐지 → 상관. (로그 줄, 실패 여부)를 돌려주고 예외는 밖으로 던지지 않는다."""
    lines: list[str] = []
    try:
        store.ping()
        now = now or datetime.now(timezone.utc)
        collected = run_cycle(client, store, cfg, now)
        lines.append(summary_line(collected))
        if detector is not None:
            lines.append(detect_summary(detector.run(store, now)))
        lines.append(correlate_summary(correlate_once(store, window, now)))
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


def build_store(settings: Settings):
    from app.store import MySQLStore  # PyMySQL 연결은 실제 실행 때만

    password = settings.mysql_password.get_secret_value() if settings.mysql_password else ""
    return MySQLStore(host=settings.mysql_host, port=settings.mysql_port, user=settings.mysql_user,
                      password=password, database=settings.mysql_db)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mini-xdr 분석 워커(수집 → 이상탐지 → 상관)")
    parser.add_argument("--once", action="store_true", help="한 주기만 실행하고 종료")
    args = parser.parse_args(argv)
    settings = Settings()
    client, store, cfg = build_client(settings), build_store(settings), collect_config(settings)
    window = timedelta(minutes=settings.correlation_window_min)
    detector = AnomalyDetector(detect_config(settings))  # 기준선 캐시를 주기 사이에 유지
    try:
        while True:
            lines, failed = cycle(client, store, cfg, window, detector=detector)
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
