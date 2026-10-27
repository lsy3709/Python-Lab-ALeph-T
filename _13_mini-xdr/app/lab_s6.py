"""S6(관리자 API 키 추측 폭주) 끝-끝 연동 확인 — 신호 → 탐지 → 대응 → mini-xdr 판정까지 한 번에.

PC(호스트)에서:  python -m app.lab_s6 --ip 203.0.113.176
 ① 게시판 /api/security/events 에 일부러 틀린 키로 N회(기본 15) — X-Forwarded-For 로 출발지를 문서용 IP 로 정한다
 ② 15초마다 각 계층을 확인한다(최대 --wait 초):
    Graylog 신호 → (선택) Wazuh 100260 → Graylog S6 이벤트 → n8n 112 실행 → 게시판 차단 → mini-xdr 인시던트·판정
 ③ 원복(기본): S6 이벤트 창이 지날 때까지 기다린 뒤 게시판 차단 해제 · 그 IP 의 열린 티켓 종료 → 재차단 없는지 확인.
    --keep 이면 남겨 둔다. (창 안에서는 이벤트가 1분마다 다시 발동해 112 봇이 다시 차단한다 — 라이브 실측)
※ 112 IP 차단봇이 Slack·Discord·Telegram 으로 알림을 보낸다.
※ 문서용 대역(192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24)만 허용 — 실제 주소를 막지 않게.
※ 시도에 쓰는 틀린 키는 매번 무작위로 만들고 출력하지 않는다.
"""
from __future__ import annotations

import argparse
import json
import secrets
import sys
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from ipaddress import ip_address, ip_network
from typing import Any

import httpx

from app.config import Settings
from app.lab_check import S6_BOT, _secret, connect_db, docker_run, n8n_executions

TEST_NETS = [ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


class Abort(Exception):
    """시작 전 점검에서 멈춰야 할 때."""


@dataclass
class Ctx:
    settings: Settings
    http: httpx.Client | None
    ip: str
    count: int
    start: datetime
    s6_definition: str | None = None
    open_db: Callable[[], Any] | None = None
    run: Callable[[list[str]], tuple[int, str]] = docker_run
    incident_id: int | None = None
    settle_sec: int = 255   # S6 이벤트가 더는 다시 발동하지 않을 때까지(창 + 평가 주기 + 여유) — 정의에서 읽어 덮어씀


@dataclass(frozen=True)
class Stage:
    name: str
    fn: Callable[..., tuple[bool, str]]
    required: bool = True


@dataclass(frozen=True)
class Result:
    done: bool
    detail: str
    at: float | None = None   # 시작 후 몇 초에 확인됐나


def validate_ip(ip: str) -> str:
    try:
        addr = ip_address(ip)
    except ValueError:
        raise ValueError(f"IP 형식이 아닙니다: {ip!r}") from None
    if not any(addr in net for net in TEST_NETS):
        raise ValueError("문서용 대역(192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24)만 쓸 수 있습니다")
    return ip


def _board(ctx: Ctx) -> tuple[str, dict]:
    key = _secret(ctx.settings.board_api_key)
    if not key:
        raise Abort("BOARD_API_KEY 없음 — .env 에 게시판 SECURITY_API_KEY 와 같은 값을 넣으세요(차단 확인·원복에 필요)")
    return ctx.settings.board_url.rstrip("/"), {"X-API-Key": key}


def _blocked_rows(ctx: Ctx) -> list[dict]:
    base, headers = _board(ctx)
    r = ctx.http.get(base + "/api/admin/blocked", params={"q": ctx.ip}, headers=headers, timeout=10)
    r.raise_for_status()
    return [row for row in r.json().get("blocked", []) if row.get("ip") == ctx.ip]


def _open_tickets(ctx: Ctx) -> list[dict]:
    base, headers = _board(ctx)
    r = ctx.http.get(base + "/api/admin/incidents", params={"status": "open"}, headers=headers, timeout=10)
    r.raise_for_status()
    return [t for t in r.json().get("incidents", []) if t.get("src_ip") == ctx.ip and t.get("status") == "open"]


def _graylog(ctx: Ctx, method: str, path: str, **kw) -> dict:
    token, user, password = ctx.settings.graylog_credentials()
    auth = (token, "token") if token else (user, password)
    r = ctx.http.request(method, ctx.settings.graylog_url.rstrip("/") + path, auth=auth, timeout=15,
                         headers={"Accept": "application/json", "X-Requested-By": "mini-xdr"}, **kw)
    r.raise_for_status()
    return r.json()


def _since(ctx: Ctx, now: datetime | None) -> int:
    return int(((now or datetime.now(timezone.utc)) - ctx.start).total_seconds()) + 120


def precheck(ctx: Ctx) -> None:
    if _blocked_rows(ctx):
        raise Abort(f"이미 차단된 IP 입니다: {ctx.ip} — 다른 문서용 IP 를 쓰거나 먼저 해제하세요")


def find_s6_definition(ctx: Ctx) -> str:
    body = _graylog(ctx, "GET", "/api/events/definitions", params={"per_page": "200"})
    for d in body.get("event_definitions", []):
        if d.get("title", "").startswith("S6"):
            cfg = d.get("config", {})
            window, every = cfg.get("search_within_ms"), cfg.get("execute_every_ms")
            if window and every:
                ctx.settle_sec = int(window // 1000 + every // 1000 + 15)
            return d["id"]
    raise Abort("Graylog 에 S6 이벤트 정의가 없습니다 — [158] 2장대로 만드세요")


def send_attempts(ctx: Ctx) -> list[int]:
    """틀린 키로 신호 내는 라우트를 두드린다(신호는 require_api_key 라우트만 낸다 — [158] 0장 함정)."""
    wrong = "wrong-" + secrets.token_hex(8)
    url = ctx.settings.board_url.rstrip("/") + "/api/security/events"
    body = {"student": "zz_s6", "src_ip": ctx.ip, "decision": "deny"}
    return [ctx.http.post(url, json=body, timeout=10,
                          headers={"X-API-Key": wrong, "X-Forwarded-For": ctx.ip}).status_code
            for _ in range(ctx.count)]


# ---------- 단계별 확인((끝났나, 내용)) ----------

def stage_graylog_signal(ctx: Ctx, now: datetime | None = None):
    body = _graylog(ctx, "GET", "/api/search/universal/relative", params={
        "query": f'rule:admin-auth-fail AND src_ip:"{ctx.ip}"', "range": str(_since(ctx, now)), "limit": "1"})
    n = int(body.get("total_results") or 0)
    return n >= ctx.count, f"admin-auth-fail {n}건/{ctx.count}"


def stage_wazuh(ctx: Ctx, now: datetime | None = None):
    body = _graylog(ctx, "GET", "/api/search/universal/relative", params={
        "query": "wazuh_rule_id:(100260 OR 100261)", "range": str(_since(ctx, now)), "limit": "200",
        "fields": "wazuh_rule_id,wazuh_data_srcip"})
    msgs = [m["message"] for m in body.get("messages", [])]
    mine = Counter(m.get("wazuh_rule_id") for m in msgs if m.get("wazuh_data_srcip") == ctx.ip)
    if mine.get("100260"):
        return True, f"100260 {mine['100260']}건 · 100261 {mine.get('100261', 0)}건(srcip={ctx.ip})"
    others = sorted({str(m.get("wazuh_data_srcip")) for m in msgs})
    return False, (f"100260 이 들어왔지만 srcip 가 {', '.join(others)}" if msgs else "아직 없음")


def stage_graylog_event(ctx: Ctx, now: datetime | None = None):
    body = _graylog(ctx, "POST", "/api/events/search", json={
        "query": "", "page": 1, "per_page": 50,
        "filter": {"alerts": "include", "event_definitions": [ctx.s6_definition]},
        "timerange": {"type": "relative", "range": _since(ctx, now)}})
    mine = [e["event"] for e in body.get("events", []) if e["event"].get("fields", {}).get("src_ip") == ctx.ip]
    if not mine:
        return False, "아직 발동 안 함(1분마다 평가)"
    return True, f"발동 {len(mine)}회 · {mine[-1].get('message', '')}"


def stage_n8n(ctx: Ctx, now: datetime | None = None):
    rows = n8n_executions(ctx, ctx.start, S6_BOT)
    ok = [r for r in rows if r.get("status") == "success"]
    if ok:
        return True, f"112 IP 차단봇 실행 {len(rows)}건(성공 {len(ok)})"
    return False, (f"실행 {len(rows)}건 · 상태 {sorted({r.get('status') for r in rows})}" if rows else "아직 실행 없음")


def stage_board_block(ctx: Ctx, now: datetime | None = None):
    rows = _blocked_rows(ctx)
    if not rows:
        return False, "아직 차단 안 됨"
    return True, f"차단됨(차단자 {rows[0].get('blocked_by', '-')})"


def stage_board_ticket(ctx: Ctx, now: datetime | None = None):
    tickets = _open_tickets(ctx)
    if tickets:
        return True, "열린 티켓 " + ", ".join(f"#{t['id']}" for t in tickets)
    return False, "없음 — 112 봇은 티켓을 만들지 않는다(티켓은 114 인시던트 봇 몫)"


def stage_minixdr_incident(ctx: Ctx, now: datetime | None = None):
    with ctx.open_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT id, layers, event_count, rule_floor, current_priority FROM incidents "
                    "WHERE entity_key = %s AND last_event_at >= %s ORDER BY id DESC LIMIT 1",
                    (f"ip:{ctx.ip}", ctx.start.astimezone(timezone.utc).replace(tzinfo=None)))
        row = cur.fetchone()
    if not row:
        return False, "아직 인시던트 없음(워커 주기 30초)"
    ctx.incident_id = row[0]
    layers = "+".join(json.loads(row[1])) if isinstance(row[1], str) else "+".join(row[1] or [])
    return True, f"인시던트 #{row[0]} · 계층 {layers} · 이벤트 {row[2]}건 · 규칙 하한 {row[3] or '-'} · 현재 {row[4] or '-'}"


def stage_minixdr_triage(ctx: Ctx, now: datetime | None = None):
    if ctx.incident_id is None:
        return False, "인시던트를 기다리는 중"
    with ctx.open_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT source, gate, model, priority, verdict, recommended_playbook, reasoning_ko "
                    "FROM triage_results WHERE incident_id = %s AND created_at >= %s ORDER BY id DESC LIMIT 1",
                    (ctx.incident_id, ctx.start.astimezone(timezone.utc).replace(tzinfo=None)))
        row = cur.fetchone()
    if not row:
        return False, "아직 판정 없음"
    source, gate, model, priority, verdict, playbook, reasoning = row
    return True, f"{source}·{gate} · {model or '-'} · {priority} · {verdict} · 권고 {playbook} — {(reasoning or '')[:80]}"


STAGES = [
    Stage("1 게시판 → Graylog 신호", stage_graylog_signal),
    Stage("2 Wazuh 100260(호스트 로그 경로)", stage_wazuh, required=False),
    Stage("3 Graylog S6 이벤트 발동", stage_graylog_event),
    Stage("4 n8n 112 IP 차단봇 실행", stage_n8n),
    Stage("5 게시판 IP 차단", stage_board_block),
    Stage("6 게시판 티켓", stage_board_ticket, required=False),
    Stage("7 mini-xdr 인시던트", stage_minixdr_incident),
    Stage("8 mini-xdr 판정(AI·규칙)", stage_minixdr_triage),
]


def poll(ctx, stages, *, wait: float, interval: float, sleep=time.sleep, clock=time.monotonic, log=print):
    """필수 단계가 모두 끝나면 한 번 더 확인(선택 단계용)하고 멈춘다. 한 단계가 실패해도 다른 단계는 계속 본다."""
    t0 = clock()
    results = {st.name: Result(False, "확인 전") for st in stages}
    finishing = False
    while True:
        elapsed = clock() - t0
        for st in stages:
            if results[st.name].done:
                continue
            try:
                done, detail = st.fn(ctx)
            except Exception as exc:
                done, detail = False, f"확인 실패({type(exc).__name__})"
            results[st.name] = Result(done, detail, elapsed if done else None)
            if done:
                log(f"  +{elapsed:>4.0f}초 ✅ {st.name}: {detail}")
        if all(results[s.name].done for s in stages if s.required):
            if finishing or all(r.done for r in results.values()):
                break
            finishing = True
        elif clock() - t0 >= wait:
            break
        sleep(interval)
    return results


def wait_for_settle(ctx: Ctx, *, now: datetime | None = None, sleep=time.sleep, log=print) -> None:
    """시도 시각(ctx.start)부터 settle_sec 이 지날 때까지 기다린다 — 그 전에 풀면 이벤트가 다시 발동해 재차단된다."""
    remaining = ctx.settle_sec - ((now or datetime.now(timezone.utc)) - ctx.start).total_seconds()
    if remaining > 0:
        log(f"  S6 이벤트 창이 지나갈 때까지 {remaining:.0f}초 기다린 뒤 원복합니다(그 전에 풀면 1분 뒤 다시 차단됨)")
        sleep(remaining)


def cleanup(ctx: Ctx) -> list[str]:
    base, headers = _board(ctx)
    lines = []
    r = ctx.http.post(base + "/api/admin/unblock", json={"ip": ctx.ip}, headers=headers, timeout=10)
    lines.append(f"차단 해제 {ctx.ip}: HTTP {r.status_code}")
    for t in _open_tickets(ctx):
        r = ctx.http.post(base + "/api/admin/incident/close", json={"id": t["id"]}, headers=headers, timeout=10)
        lines.append(f"티켓 #{t['id']} 종료: HTTP {r.status_code}")
    if _blocked_rows(ctx):
        lines.append(f"⚠️ {ctx.ip} 가 다시 차단돼 있습니다 — 이벤트 창이 덜 지났습니다. 1~2분 뒤 다시 해제하세요")
    else:
        lines.append("재차단 없음 확인")
    return lines


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.lab_s6", description="S6 끝-끝 연동 확인")
    ap.add_argument("--ip", required=True, help="출발지로 쓸 문서용 IP(예: 203.0.113.176)")
    ap.add_argument("--count", type=int, default=15, help="틀린 키 시도 횟수(임계 10 초과가 되게, 기본 15)")
    ap.add_argument("--wait", type=int, default=480, help="최대 대기 초(기본 480)")
    ap.add_argument("--interval", type=int, default=15, help="확인 간격 초(기본 15)")
    ap.add_argument("--keep", action="store_true", help="끝나도 차단·티켓을 원복하지 않음")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    try:
        ip = validate_ip(args.ip)
    except ValueError as exc:
        print(f"❌ {exc}")
        return 2
    settings = Settings()
    with httpx.Client() as http:
        ctx = Ctx(settings=settings, http=http, ip=ip, count=args.count, start=datetime.now(timezone.utc),
                  open_db=lambda: connect_db(settings))
        try:
            precheck(ctx)
            ctx.s6_definition = find_s6_definition(ctx)
        except Abort as exc:
            print(f"❌ 시작 전 점검: {exc}")
            return 2
        print(f"S6 끝-끝 연동 확인 — 출발지 {ip} · 틀린 키 {args.count}회 · 최대 {args.wait}초")
        print("※ 112 IP 차단봇이 Slack·Discord·Telegram 으로 알림을 보냅니다.")
        ctx.start = datetime.now(timezone.utc)
        codes = Counter(send_attempts(ctx))
        print(f"  +   0초 → 게시판 응답: " + ", ".join(f"HTTP {c} ×{n}" for c, n in sorted(codes.items())))
        results = poll(ctx, STAGES, wait=args.wait, interval=args.interval)
        print("결과:")
        for st in STAGES:
            r = results[st.name]
            mark = "✅" if r.done else ("❌" if st.required else "➖")
            when = f"+{r.at:.0f}초" if r.at is not None else "-"
            print(f"  {mark} {st.name} ({when}): {r.detail}")
        if not args.keep:
            wait_for_settle(ctx)
            print("원복:")
            for line in cleanup(ctx):
                print("  " + line)
    return 0 if all(results[s.name].done for s in STAGES if s.required) else 1


if __name__ == "__main__":
    raise SystemExit(main())
