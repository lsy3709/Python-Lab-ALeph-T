"""콘솔 — 대시보드(그래프)·인시던트 목록(우선순위순)·상세(신호 요약·타임라인)는 읽기 전용, AI 설정(/settings)만 쓰기.

로그 값(계정명·경로 등)은 공격자가 넣을 수 있는 문자열이라 템플릿 자동 이스케이프로만 출력한다.
"""
from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import date, datetime, time, timedelta, timezone

from flask import Flask, abort, jsonify, render_template, request

from app.console import settings_views
from app.console.charts import BAR_COLOR, LAYER_COLORS, PRIORITY_COLORS, hbars, stacked_columns
from app.console.queries import PAGE_SIZE, PRIORITY_FILTERS, STATUSES, TIMELINE_FETCH
from app.console.security import host_allowed
from app.timeline import build_timeline, offset_label

KST = timezone(timedelta(hours=9), "KST")  # 한국은 서머타임이 없어 고정 오프셋으로 충분(Windows 는 tzdata 없음)
TIMELINE_ITEMS = 200
SHOWN_Z = 3.0  # 행위 이상 화면에서 보여 줄 최소 z(기본 ANOMALY_Z 와 같음)
SOURCE_LABELS = {"llm": "LLM", "cache": "지문 캐시", "rule": "규칙", "refusal": "LLM 거절 → 규칙"}
FEATURE_LABELS = {"events": "시간당 이벤트", "signals": "신호 종류", "login_fail": "로그인 실패",
                  "ratio_404": "404 비율", "login_hour": "로그인 시각(KST)"}
LAYERS = ("app", "host", "network", "data", "behavior")  # 누적 순서(아래→위) — 색은 계층을 따라간다
DASH_DAYS, DEFAULT_DAYS = (7, 14, 30), 14
GATE_LABELS = {"G1": "화이트리스트", "G2": "규칙으로 결론", "G3": "지문 캐시 재사용", "G5": "예산·서킷 → 규칙",
               "MASK-LEAK": "마스킹 누출 차단 → 규칙", "NOKEY": "LLM 키 없음 → 규칙", "LLM-ERR": "LLM 오류·스키마 실패 → 규칙",
               "LLM-REFUSAL": "LLM 거절 → 규칙", "LLM": "LLM 판정", "LLM-FLOOR": "LLM 판정(규칙 하한이 이김)"}
CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"


def kst(value: datetime | None) -> str:
    if value is None:
        return "-"
    if value.tzinfo is None:  # DB 값은 naive UTC
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(KST).strftime("%m-%d %H:%M:%S")


def gate_label(gate: str) -> str:
    """그래프용 관문 이름 — 뜻이 이미 'LLM …' 이면 코드(LLM·LLM-ERR 등)를 앞에 겹쳐 쓰지 않는다."""
    meaning = GATE_LABELS.get(gate, "")
    if not meaning:
        return gate
    return meaning if gate.startswith("LLM") and meaning.startswith("LLM") else f"{gate} {meaning}"


def dashboard_range(days: int, now: datetime) -> tuple[list[date], datetime]:
    """오늘(KST)까지 days 일의 날짜 목록과, 첫날 KST 자정을 naive UTC 로 바꾼 조회 시작 시각."""
    today = now.astimezone(KST).date()
    day_list = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]
    since = datetime.combine(day_list[0], time(0), KST).astimezone(timezone.utc).replace(tzinfo=None)
    return day_list, since


def create_app(open_queries, settings_deps: settings_views.SettingsDeps | None = None,
               now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> Flask:
    """open_queries: 호출하면 ConsoleQueries 를 주는 컨텍스트 매니저(요청마다 연결을 열고 닫는다).
    settings_deps: 주면 AI 설정 화면(/settings)을 켠다. now: 대시보드 기간 계산용 시계(테스트에서 고정)."""
    app = Flask(__name__)
    app.secret_key = secrets.token_bytes(32)  # CSRF 토큰용 세션 서명 — 재시작하면 바뀐다(다시 열면 됨)
    app.config.update(SESSION_COOKIE_NAME="mxdr_session", SESSION_COOKIE_SAMESITE="Strict",
                      SESSION_COOKIE_HTTPONLY=True)
    app.jinja_env.filters["kst"] = kst
    app.jinja_env.filters["num"] = lambda v: f"{v:,}"

    @app.before_request
    def only_local_host():  # DNS 리바인딩 방지 — Host 가 localhost 계열이 아니면 거부
        if not host_allowed(request.host):
            abort(400, "허용되지 않은 Host")

    @app.context_processor
    def menu():
        return {"settings_enabled": settings_deps is not None}

    if settings_deps is not None:
        settings_views.register(app, settings_deps)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        # no-referrer 로 두면 브라우저가 POST 의 Origin 을 "null" 로 보내 설정 저장이 막힌다(Fetch 표준, 실측)
        # → same-origin: 같은 출처에만 리퍼러를 보내고 외부 사이트로는 보내지 않는다.
        resp.headers["Referrer-Policy"] = "same-origin"
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

    @app.get("/dashboard")
    def dashboard():
        days = request.args.get("days", DEFAULT_DAYS, type=int)
        days = days if days in DASH_DAYS else DEFAULT_DAYS
        day_list, since = dashboard_range(days, now())
        with open_queries() as q:
            daily, priorities = q.daily_layer_counts(since), q.priority_counts(since)
            entities, gates, stats = q.top_entities(since), q.gate_counts(since), q.stats()
        labels = [d.strftime("%m-%d") for d in day_list]
        values = {(r["day"].strftime("%m-%d"), r["layer"]): r["n"] for r in daily}
        layer_totals = {k: sum(v for (_, key), v in values.items() if key == k) for k in LAYERS}
        by_priority: dict[str, dict[str, int]] = {}
        for r in priorities:
            by_priority.setdefault(r["priority"] or "미정", {})[r["status"]] = r["n"]
        priority_rows = [(p, by_priority[p]) for p in ("P1", "P2", "P3", "P4", "미정") if p in by_priority]
        gate_rows = [(g, gates[g]) for g in GATE_LABELS if g in gates] +                     [(g, n) for g, n in sorted(gates.items()) if g not in GATE_LABELS]
        charts = {
            "daily": stacked_columns(labels, [(k, k) for k in LAYERS], values, colors=LAYER_COLORS),
            "priority": hbars([(f"{p} · 열림 {s.get('open', 0):,}", sum(s.values()), PRIORITY_COLORS[p])
                               for p, s in priority_rows], width=540, label_w=120),   # 반쪽 카드 — 글자가 작아지지 않게
            "entities": hbars([(e["entity_key"], e["events"], BAR_COLOR) for e in entities]),
            "gates": hbars([(gate_label(g), n, BAR_COLOR) for g, n in gate_rows], width=540, label_w=250),
        }
        return render_template("dashboard.html", days=days, choices=DASH_DAYS, charts=charts, stats=stats,
                               labels=labels, values=values, layers=LAYERS, layer_colors=LAYER_COLORS,
                               layer_totals=layer_totals, priority_rows=priority_rows, entities=entities,
                               gate_rows=gate_rows, gate_labels=GATE_LABELS)

    @app.get("/incidents/<int:iid>")
    def incident(iid: int):
        with open_queries() as q:
            inc = q.get_incident(iid)
            if inc is None:
                abort(404)
            summary, events, users = q.signal_summary(iid), q.incident_events(iid), q.users(iid)
            triage = q.latest_triage(iid)
        timeline, cut = build_timeline(events, TIMELINE_ITEMS)
        return render_template("detail.html", inc=inc, summary=summary, timeline=timeline, users=users, triage=triage,
                               source_labels=SOURCE_LABELS,
                               start=events[0].ts if events else None, offset_label=offset_label,
                               truncated=cut or len(events) < inc["event_count"],
                               fetch_limit=TIMELINE_FETCH, item_limit=TIMELINE_ITEMS)

    @app.get("/anomalies")
    def anomalies():
        with open_queries() as q:
            rows, summary = q.list_anomalies(), q.baseline_summary()
        for r in rows:  # 임계 미만 특징은 숨기고 z 큰 순서로
            r["shown"] = sorted(((n, f) for n, f in r["features"].items() if f["z"] >= SHOWN_Z),
                                key=lambda item: -item[1]["z"])
        return render_template("anomalies.html", rows=rows, summary=summary, labels=FEATURE_LABELS)

    @app.get("/usage")
    def usage():
        with open_queries() as q:
            u = q.usage_stats()
        pct = lambda a, b: f"{a / b:.1%}" if b else "-"  # noqa: E731
        rates = {"call_rate": pct(u["llm_decisions"], u["decisions"]),
                 "cache_hit": pct(u["cache_decisions"], u["cache_decisions"] + u["llm_decisions"]),
                 "prompt_cache": pct(u["cache_read"], u["tokens_in"] + u["cache_read"])}
        return render_template("usage.html", u=u, rates=rates, source_labels=SOURCE_LABELS, gate_labels=GATE_LABELS)

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
