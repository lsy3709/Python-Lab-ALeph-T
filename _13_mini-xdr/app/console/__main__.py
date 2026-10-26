"""콘솔 실행 — python -m app.console [--host 127.0.0.1] [--port 8099]"""
from __future__ import annotations

import argparse
from functools import partial

from waitress import serve

from app.config import Settings
from app.console import create_app
from app.console.queries import open_queries
from app.console.settings_views import SettingsDeps
from app.secret_box import SecretBox, SecretBoxError
from app.settings_store import open_settings_conn


def build_settings_deps(settings: Settings) -> SettingsDeps:
    box, problem = None, None
    key = settings.secret_key_value()
    if key:
        try:
            box = SecretBox(key)
        except SecretBoxError as exc:
            problem = str(exc)
    return SettingsDeps(env=settings, open_conn=partial(open_settings_conn, settings), box=box, box_problem=problem)


def main(argv: list[str] | None = None) -> int:
    settings = Settings()
    parser = argparse.ArgumentParser(description="mini-xdr 콘솔(사건 조회는 읽기 전용, AI 설정은 /settings)")
    parser.add_argument("--host", default=settings.console_host)
    parser.add_argument("--port", type=int, default=settings.console_port)
    args = parser.parse_args(argv)
    app = create_app(partial(open_queries, settings), build_settings_deps(settings))
    print(f"[콘솔] http://{args.host}:{args.port} 에서 대기(사건 조회 읽기 전용 · AI 설정 /settings)", flush=True)
    serve(app, host=args.host, port=args.port, threads=4)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
