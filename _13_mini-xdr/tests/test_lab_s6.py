"""S6 끝-끝 연동 확인 — 문서용 IP 만·틀린 키 비노출·단계 판정·조기 종료·원복."""
import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app import lab_s6 as s6
from app.config import Settings

BOARD_KEY = "boardkey" + "q" * 20
GL_TOKEN = "gltoken" + "w" * 30
IP = "203.0.113.176"
START = datetime(2026, 10, 27, 2, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)


def settings(**kw):
    base = dict(_env_file=None, board_url="http://board:5000", board_api_key=BOARD_KEY, graylog_url="http://gl:9000",
                graylog_token=GL_TOKEN, llm_provider="none")
    base.update(kw)
    return Settings(**base)


@pytest.mark.parametrize("ip", ["8.8.8.8", "10.0.0.5", "127.0.0.1", "203.0.114.1", "abc", ""])
def test_only_documentation_ranges_allowed(ip):
    with pytest.raises(ValueError):
        s6.validate_ip(ip)


def test_documentation_ranges_accepted():
    for ip in ("192.0.2.10", "198.51.100.7", IP):
        assert s6.validate_ip(ip) == ip


class Board:
    def __init__(self, blocked=()):
        self.posts, self.blocked, self.closed = [], set(blocked), []
        self.tickets = [{"id": 31, "src_ip": IP, "status": "open"}, {"id": 32, "src_ip": "203.0.113.9", "status": "open"}]

    def handle(self, req):
        path = req.url.path
        if path == "/api/security/events":
            self.posts.append((req.headers.get("X-API-Key"), req.headers.get("X-Forwarded-For"), json.loads(req.content)))
            return httpx.Response(401, json={"msg": "API 키가 없거나 잘못되었습니다."})
        assert req.headers.get("X-API-Key") == BOARD_KEY
        if path == "/api/admin/blocked":
            rows = [{"ip": ip, "blocked_by": "n8n"} for ip in self.blocked if req.url.params.get("q", "") in ip]
            return httpx.Response(200, json={"count": len(rows), "blocked": rows})
        if path == "/api/admin/unblock":
            self.blocked.discard(json.loads(req.content)["ip"])
            return httpx.Response(200, json={"blocked": False})
        if path == "/api/admin/incidents":
            return httpx.Response(200, json={"count": 2, "incidents": self.tickets})
        if path == "/api/admin/incident/close":
            self.closed.append(json.loads(req.content)["id"])
            return httpx.Response(200, json={})
        return httpx.Response(404)


def ctx_for(board, **kw):
    s = settings(**kw)
    http = httpx.Client(transport=httpx.MockTransport(board.handle))
    return s6.Ctx(settings=s, http=http, ip=IP, count=15, start=START)


def test_send_attempts_uses_forwarded_ip_and_a_random_wrong_key(capsys):
    board = Board()
    codes = s6.send_attempts(ctx_for(board))
    assert codes == [401] * 15 and len(board.posts) == 15
    keys = {k for k, _, _ in board.posts}
    assert len(keys) == 1 and BOARD_KEY not in keys and all(xff == IP for _, xff, _ in board.posts)
    assert board.posts[0][2]["src_ip"] == IP
    assert next(iter(keys)) not in capsys.readouterr().out          # 시도한 키 값은 출력하지 않는다


def test_precheck_refuses_ip_already_blocked():
    with pytest.raises(s6.Abort, match="이미 차단"):
        s6.precheck(ctx_for(Board(blocked={IP})))
    s6.precheck(ctx_for(Board()))   # 차단 안 됐으면 통과


def test_precheck_needs_board_key():
    with pytest.raises(s6.Abort, match="BOARD_API_KEY"):
        s6.precheck(ctx_for(Board(), board_api_key=None))


def test_cleanup_unblocks_and_closes_only_this_ips_tickets():
    board = Board(blocked={IP, "203.0.113.9"})
    lines = s6.cleanup(ctx_for(board))
    assert IP not in board.blocked and "203.0.113.9" in board.blocked
    assert board.closed == [31] and any("31" in l for l in lines)


def test_board_block_stage():
    board = Board()
    ctx = ctx_for(board)
    assert s6.stage_board_block(ctx) == (False, "아직 차단 안 됨")
    board.blocked.add(IP)
    done, detail = s6.stage_board_block(ctx)
    assert done and "n8n" in detail


def test_graylog_event_stage_matches_src_ip():
    def handle(req):
        assert req.url.path == "/api/events/search"
        body = json.loads(req.content)
        assert body["filter"]["event_definitions"] == ["def-s6"]
        return httpx.Response(200, json={"events": [
            {"event": {"timestamp": "2026-10-27T02:01:33Z", "message": "S6 ...: 203.0.113.9", "fields": {"src_ip": "203.0.113.9"}}},
            {"event": {"timestamp": "2026-10-27T02:01:34Z", "message": "S6 ...: 203.0.113.176 - count()=15.0",
                       "fields": {"src_ip": IP}}}]})
    ctx = s6.Ctx(settings=settings(), http=httpx.Client(transport=httpx.MockTransport(handle)), ip=IP, count=15,
                 start=START, s6_definition="def-s6")
    done, detail = s6.stage_graylog_event(ctx, now=START + timedelta(minutes=2))
    assert done and "1회" in detail and "count()=15" in detail


def test_poll_stops_when_required_stages_done_and_reports_timing():
    ticks = {"a": 2, "b": 3}            # 단계별로 몇 번째 확인에서 끝나는지
    seen = {"a": 0, "b": 0, "opt": 0}

    def make(name):
        def fn(ctx, now=None):
            seen[name] += 1
            return (name in ticks and seen[name] >= ticks[name]), f"{name} 결과"
        return fn

    stages = [s6.Stage("a", make("a")), s6.Stage("b", make("b")), s6.Stage("opt", make("opt"), required=False)]
    clock = {"t": 0.0}
    out = s6.poll(None, stages, wait=300, interval=15, sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
                  clock=lambda: clock["t"], log=lambda *_: None)
    assert out["a"].done and out["a"].at == 15 and out["b"].at == 30
    assert not out["opt"].done and clock["t"] == 45      # 필수 단계가 끝나면 한 번 더 보고 멈춘다


def test_poll_times_out_and_keeps_last_detail():
    stages = [s6.Stage("x", lambda ctx, now=None: (False, "아직"))]
    clock = {"t": 0.0}
    out = s6.poll(None, stages, wait=60, interval=15, sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
                  clock=lambda: clock["t"], log=lambda *_: None)
    assert not out["x"].done and out["x"].detail == "아직" and clock["t"] >= 60


def test_stage_error_does_not_stop_polling():
    def boom(ctx, now=None):
        raise httpx.ConnectError("down")
    clock = {"t": 0.0}
    out = s6.poll(None, [s6.Stage("x", boom)], wait=30, interval=15,
                  sleep=lambda s: clock.__setitem__("t", clock["t"] + s), clock=lambda: clock["t"], log=lambda *_: None)
    assert not out["x"].done and "ConnectError" in out["x"].detail


def test_minixdr_stages_read_incident_and_triage():
    rows = {"incidents": (7, '["app", "host"]', 17, "P2", "P2"),
            "triage_results": ("llm", "LLM", "gemini-x", "P2", "true_positive", "block_ip", "키 추측 폭주로 보임")}

    @contextmanager
    def open_db():
        class Cur:
            def execute(self, sql, params=None):
                assert params[0] in (f"ip:{IP}", 7)
                self.row = next(v for k, v in rows.items() if f"FROM {k}" in sql)

            def fetchone(self):
                return self.row

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class Conn:
            def cursor(self):
                return Cur()
        yield Conn()

    ctx = s6.Ctx(settings=settings(), http=None, ip=IP, count=15, start=START, open_db=open_db)
    done, detail = s6.stage_minixdr_incident(ctx)
    assert done and "#7" in detail and "app" in detail and ctx.incident_id == 7
    done, detail = s6.stage_minixdr_triage(ctx)
    assert done and "gemini-x" in detail and "true_positive" in detail


def test_find_s6_definition_reads_window_and_interval():
    # 회귀(라이브 실측): 창 3분·1분마다 평가라 같은 15건으로 3번 발동 → 31초에 한 원복을 재차단이 덮어씀
    def handle(req):
        return httpx.Response(200, json={"event_definitions": [
            {"id": "x1", "title": "S1 ...", "config": {}},
            {"id": "def-s6", "title": "S6 관리자 API 무단 호출 폭주", "config": {"search_within_ms": 180000,
                                                                       "execute_every_ms": 60000}}]})
    ctx = s6.Ctx(settings=settings(), http=httpx.Client(transport=httpx.MockTransport(handle)), ip=IP, count=15,
                 start=START)
    assert s6.find_s6_definition(ctx) == "def-s6"
    assert ctx.settle_sec == 180 + 60 + 15          # 창 + 평가 주기 + 여유


def test_settle_wait_counts_from_attempts_and_skips_when_passed():
    slept = []
    ctx = s6.Ctx(settings=settings(), http=None, ip=IP, count=15, start=START, settle_sec=255)
    s6.wait_for_settle(ctx, now=START + timedelta(seconds=40), sleep=slept.append, log=lambda *_: None)
    assert slept == [215]
    slept.clear()
    s6.wait_for_settle(ctx, now=START + timedelta(seconds=300), sleep=slept.append, log=lambda *_: None)
    assert slept == []


def test_cleanup_reports_if_reblocked():
    board = Board(blocked={IP})
    original = board.handle

    def reblock(req):                    # 해제 직후 다시 차단되는 상황(창이 덜 지남)
        resp = original(req)
        if req.url.path == "/api/admin/unblock":
            board.blocked.add(IP)
        return resp
    board.handle = reblock
    lines = s6.cleanup(ctx_for(board))
    assert any("다시 차단" in l for l in lines)
    lines = s6.cleanup(ctx_for(Board(blocked={IP})))
    assert any("재차단 없음" in l for l in lines)
