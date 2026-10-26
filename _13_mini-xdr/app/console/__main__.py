"""콘솔 실행 — python -m app.console [--host 127.0.0.1] [--port 8099]"""
from __future__ import annotations

import argparse
from functools import partial

from waitress import serve

from app.config import Settings
from app.console import create_app
from app.console.queries import open_queries


def main(argv: list[str] | None = None) -> int:
    settings = Settings()
    parser = argparse.ArgumentParser(description="mini-xdr 읽기 전용 콘솔")
    parser.add_argument("--host", default=settings.console_host)
    parser.add_argument("--port", type=int, default=settings.console_port)
    args = parser.parse_args(argv)
    app = create_app(partial(open_queries, settings))
    print(f"[콘솔] http://{args.host}:{args.port} 에서 대기(읽기 전용)", flush=True)
    serve(app, host=args.host, port=args.port, threads=4)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
