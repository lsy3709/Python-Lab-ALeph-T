"""읽기 전용 콘솔 — 인시던트 목록(우선순위순)·상세(신호 요약·타임라인).

로그 값(계정명·경로 등)은 공격자가 넣을 수 있는 문자열이라 템플릿 자동 이스케이프로만 출력한다.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from flask import Flask, abort, jsonify, render_template, request

from app.console.queries import PAGE_SIZE, PRIORITY_FILTERS, STATUSES, TIMELINE_FETCH
from app.timeline import build_timeline, offset_label

KST = timezone(timedelta(hours=9), "KST")  # 한국은 서머타임이 없어 고정 오프셋으로 충분(Windows 는 tzdata 없음)
TIMELINE_ITEMS = 200
CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"


def kst(value: datetime | None) -> str:
    if value is None:
        return "-"
    if value.tzinfo is None:  # DB 값은 naive UTC
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(KST).strftime("%m-%d %H:%M:%S")


def create_app(open_queries) -> Flask:
    """open_queries: 호출하면 ConsoleQueries 를 주는 컨텍스트 매니저(요청마다 연결을 열고 닫는다)."""
    app = Flask(__name__)
    app.jinja_env.filters["kst"] = kst
    app.jinja_env.filters["num"] = lambda v: f"{v:,}"

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.get("/")
    def incidents():
        status = request.args.get("status", "all")
        status = status if status in STATUSES else "all"
        priority = request.args.get("priority", "")
        priority = priority if priority in PRIORITY_FILTERS else ""
        multi = request.args.get("multi") == "1"
        page = max(1, request.args.get("page", 1, type=int))
        with open_queries() as q:
            rows, total = q.list_incidents(status=status, priority=priority, multi=multi, page=page)
            stats = q.stats()
        return render_template("list.html", rows=rows, total=total, page=page, pages=max(1, -(-total // PAGE_SIZE)),
                               stats=stats, status=status, priority=priority, multi=multi,
                               statuses=STATUSES, priorities=PRIORITY_FILTERS[1:])

    @app.get("/incidents/<int:iid>")
    def incident(iid: int):
        with open_queries() as q:
            inc = q.get_incident(iid)
            if inc is None:
                abort(404)
            summary, events, users = q.signal_summary(iid), q.incident_events(iid), q.users(iid)
        timeline, cut = build_timeline(events, TIMELINE_ITEMS)
        return render_template("detail.html", inc=inc, summary=summary, timeline=timeline, users=users,
                               start=events[0].ts if events else None, offset_label=offset_label,
                               truncated=cut or len(events) < inc["event_count"],
                               fetch_limit=TIMELINE_FETCH, item_limit=TIMELINE_ITEMS)

    @app.get("/healthz")
    def healthz():
        try:
            with open_queries() as q:
                s = q.stats()
        except Exception:  # 내부 주소·오류 내용을 밖에 보이지 않는다
            return jsonify(ok=False), 503
        return jsonify(ok=True, events=s["events"], incidents=s["incidents"], open=s["open_incidents"],
                       backlog=s["backlog"])

    return app
