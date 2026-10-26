"""수집 워커 — python -m app.worker [--once]

설정(.env)으로 Graylog 클라이언트·MySQL 저장소를 조립해 poll_interval_sec 마다 한 주기씩 수집한다.
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timedelta, timezone

from app.collector import CollectConfig, CollectResult, collect_once
from app.config import Settings
from app.graylog import GraylogClient


def run_cycle(client, store, cfg: CollectConfig, now: datetime | None = None) -> CollectResult:
    return collect_once(client, store, cfg, now or datetime.now(timezone.utc))


def summary_line(r: CollectResult) -> str:
    head = f"[수집] {r.window_from:%m-%d %H:%M:%S}~{r.window_to:%H:%M:%S}Z 페이지 {r.pages} · 조회 {r.fetched} · "
    body = f"적재 {r.inserted} · 중복 {r.duplicates} · 건너뜀 {r.skipped}"
    return head + body + (f" · 오류 {r.error}" if r.error else "")


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


def build_store(settings: Settings):
    from app.store import MySQLStore  # PyMySQL 연결은 실제 실행 때만

    password = settings.mysql_password.get_secret_value() if settings.mysql_password else ""
    return MySQLStore(host=settings.mysql_host, port=settings.mysql_port, user=settings.mysql_user,
                      password=password, database=settings.mysql_db)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mini-xdr 수집 워커")
    parser.add_argument("--once", action="store_true", help="한 주기만 실행하고 종료")
    args = parser.parse_args(argv)
    settings = Settings()
    client, store, cfg = build_client(settings), build_store(settings), collect_config(settings)
    try:
        while True:
            r = run_cycle(client, store, cfg)
            print(summary_line(r), flush=True)
            if args.once:
                return 1 if r.error else 0
            time.sleep(settings.poll_interval_sec)
    except KeyboardInterrupt:
        return 0
    finally:
        client.close()
        store.close()


if __name__ == "__main__":
    raise SystemExit(main())
