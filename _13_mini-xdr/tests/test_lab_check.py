"""랩 연동 점검 — 각 계층 판정·도커 없을 때 건너뜀·비밀 비노출·종료 코드."""
import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from app import lab_check as lc
from app.config import Settings

NOW = datetime(2026, 10, 27, 3, 0, tzinfo=timezone.utc)
GL_TOKEN = "gltoken" + "x" * 30           # 테스트용 가짜 값
BOARD_KEY = "boardkey" + "y" * 20
ZBX_PW = "zbxpass" + "z" * 10

WAZUH_STATUS = """wazuh-clusterd not running...
wazuh-modulesd is running...
wazuh-remoted is running...
wazuh-analysisd is running...
wazuh-db is running...
wazuh-csyslogd is running...
wazuh-apid is running...
"""
AGENTS = """Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh-manager2 (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: SJTYPAPA, IP: any, Disconnected
   ID: 002, Name: board-host, IP: any, Active

List of agentless devices:
"""
WORKFLOWS = """Error tracking disabled because this release is older than 6 weeks.
ipBlockBot0001|112 IP 차단봇 (Graylog 연동, 132·133·134 공용)
wazuhAlertBot001|129 Wazuh 경보봇 (Graylog 연동)
"""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)


def settings(**kw):
    base = dict(_env_file=None, graylog_url="http://gl:9000", graylog_token=GL_TOKEN, board_api_key=BOARD_KEY,
                board_url="http://board:5000", n8n_url="http://n8n:5678", zabbix_url="http://zbx/api_jsonrpc.php",
                console_port=8099, llm_provider="none")
    base.update(kw)
    return Settings(**base)


class World:
    """바깥 세계(HTTP·docker·DB)를 흉내 — 항목별로 고장을 낼 수 있다."""

    def __init__(self):
        self.broken: set[str] = set()
        self.docker = True
        self.executions = [{"id": 1, "status": "success", "startedAt": "2026-10-27 02:00:00.000",
                            "workflowId": "ipBlockBot0001"}]
        self.problems = "0"
        self.zbx_calls: list[tuple[str, str | None]] = []
        self.db_rows = {"checkpoints": (NOW.replace(tzinfo=None) - timedelta(seconds=20),),
                        "events_norm": (120,), "incidents": (4,), "triage_results": (9,)}

    # ---- HTTP ----
    def handle(self, req: httpx.Request) -> httpx.Response:
        host, path = req.url.host, req.url.path
        if host in self.broken:
            raise httpx.ConnectError("down", request=req)
        if host == "board":
            if path == "/":
                return httpx.Response(200, text="<html>")
            assert req.headers.get("X-API-Key") == BOARD_KEY
            if path == "/api/admin/blocked":
                return httpx.Response(200, json={"count": 2, "blocked": [{"ip": "a"}, {"ip": "b"}]})
            if path == "/api/admin/incidents":
                return httpx.Response(200, json={"count": 1, "incidents": [{"id": 7}]})
        if host == "gl":
            if path == "/api/system":
                return httpx.Response(200, json={"version": "6.1.16"})
            if path == "/api/system/inputstates":
                return httpx.Response(200, json={"states": [{"state": "RUNNING"}, {"state": "RUNNING"},
                                                            {"state": "FAILED"}]})
            if path == "/api/search/universal/relative":
                q = req.url.params["query"]
                return httpx.Response(200, json={"total_results": 203 if "rule" in q and "wazuh" not in q else 42})
            if path == "/api/events/definitions":
                return httpx.Response(200, json={"total": 12, "event_definitions": [
                    {"title": "S6 관리자 API 무단 호출 폭주 (src_ip, 5분 10회↑)"}, {"title": "S1 ..."}]})
        if host == "n8n" and path == "/healthz":
            return httpx.Response(200, json={"status": "ok"})
        if host == "zbx":
            body = json.loads(req.content)
            self.zbx_calls.append((body["method"], req.headers.get("Authorization")))
            result = {"apiinfo.version": "7.0.31", "user.login": "zbx-session", "host.get": "5",
                      "problem.get": self.problems, "user.logout": True}[body["method"]]
            return httpx.Response(200, json={"jsonrpc": "2.0", "result": result, "id": 1})
        if host == "127.0.0.1" and path == "/healthz":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404)

    # ---- docker ----
    def run(self, args):
        if not self.docker:
            raise FileNotFoundError("docker")
        cmd = " ".join(args)
        if "wazuh-manager2" in self.broken and "wazuh-manager2" in cmd:
            return 1, ""
        if "wazuh-control" in cmd:
            return 0, WAZUH_STATUS
        if "agent_control" in cmd:
            return 0, AGENTS
        if "list:workflow" in cmd:
            return 0, WORKFLOWS
        if "execution_entity" in cmd:
            return 0, json.dumps(self.executions)
        if "mysql" in cmd:
            return 0, "6\n35\n"
        raise AssertionError(cmd)

    # ---- mini_xdr DB ----
    @contextmanager
    def open_db(self):
        if "mysql" in self.broken:
            raise ConnectionError("Can't connect")
        world = self

        class Cur:
            def execute(self, sql, params=None):
                self.row = next(v for k, v in world.db_rows.items() if k in sql)

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


def run_all(world, **kw):
    s = settings(**kw)
    env = lc.Env(settings=s, http=httpx.Client(transport=httpx.MockTransport(world.handle)), run=world.run,
                 open_db=world.open_db, now=lambda: NOW, ai_status=lambda s, conn: "AI 꺼짐 — 규칙 판정")
    return {c.name: c for c in lc.run_checks(env)}


def test_all_layers_ok_when_lab_is_healthy():
    res = run_all(World(), zabbix_user="Admin", zabbix_password=ZBX_PW)
    bad = {n: (c.status, c.detail) for n, c in res.items() if c.status not in (lc.OK,)}
    assert bad == {"Graylog 서버·입력": ("warn", bad["Graylog 서버·입력"][1])}   # 입력 1개가 FAILED
    assert "6.1.16" in res["Graylog 서버·입력"].detail and "2/3" in res["Graylog 서버·입력"].detail
    assert "board-host" in res["Wazuh 에이전트"].detail and "S6" in res["Graylog 이벤트 정의"].detail
    assert "112 IP 차단봇" in res["n8n 활성 워크플로"].detail
    assert "차단 IP 2" in res["게시판 대응 결과(차단·티켓)"].detail and "열린 티켓 1" in res["게시판 대응 결과(차단·티켓)"].detail
    assert "7.0.31" in res["Zabbix 가용성 감시"].detail and "5대" in res["Zabbix 가용성 감시"].detail


def test_board_down_is_fail_with_hint_and_others_still_run():
    w = World()
    w.broken.add("board")
    res = run_all(w)
    assert res["게시판 웹 응답"].status == lc.FAIL and "python app.py" in res["게시판 웹 응답"].hint
    assert res["Graylog 서버·입력"].status == lc.WARN        # 다른 항목은 계속 점검
    assert lc.exit_code(res.values()) == 1


def test_without_docker_docker_items_are_skipped_not_failed():
    w = World()
    w.docker = False
    res = run_all(w)
    for name in ("Wazuh 매니저 데몬", "Wazuh 에이전트", "n8n 활성 워크플로", "n8n 최근 실행(24시간)", "게시판 DB(MySQL)"):
        assert res[name].status == lc.SKIP, name
    assert lc.exit_code(res.values()) == 0


def test_wazuh_daemon_down_fails():
    out = WAZUH_STATUS.replace("wazuh-analysisd is running", "wazuh-analysisd not running")
    assert lc.parse_wazuh_status(out)["wazuh-analysisd"] is False
    w = World()
    w.run = lambda args: (0, out) if "wazuh-control" in " ".join(args) else World.run(w, args)
    res = run_all(w)
    assert res["Wazuh 매니저 데몬"].status == lc.FAIL and "wazuh-analysisd" in res["Wazuh 매니저 데몬"].detail


def test_n8n_failed_executions_warn_with_workflow_name():
    w = World()
    w.executions = [{"id": 3, "status": "error", "startedAt": "2026-10-27 02:50:00.000", "workflowId": "wazuhAlertBot001"},
                    {"id": 2, "status": "success", "startedAt": "2026-10-27 02:40:00.000", "workflowId": "ipBlockBot0001"}]
    res = run_all(w)
    c = res["n8n 최근 실행(24시간)"]
    assert c.status == lc.WARN and "실패 1" in c.detail and "129 Wazuh 경보봇" in c.detail


def test_zabbix_without_credentials_checks_version_only():
    w = World()
    res = run_all(w)
    c = res["Zabbix 가용성 감시"]
    assert c.status == lc.OK and "7.0.31" in c.detail and "ZABBIX_USER" in c.hint
    assert [m for m, _ in w.zbx_calls] == ["apiinfo.version"]


def test_zabbix_with_credentials_uses_bearer_and_logs_out():
    w = World()
    w.problems = "2"
    res = run_all(w, zabbix_user="Admin", zabbix_password=ZBX_PW)
    assert [m for m, _ in w.zbx_calls] == ["apiinfo.version", "user.login", "host.get", "problem.get", "user.logout"]
    assert w.zbx_calls[2][1] == "Bearer zbx-session" and w.zbx_calls[0][1] is None
    assert res["Zabbix 가용성 감시"].status == lc.WARN and "문제 2건" in res["Zabbix 가용성 감시"].detail


def test_stale_collector_checkpoint_warns():
    w = World()
    w.db_rows["checkpoints"] = (NOW.replace(tzinfo=None) - timedelta(minutes=30),)
    c = run_all(w)["mini-xdr 수집(Graylog → mini-xdr)"]
    assert c.status == lc.WARN and "워커" in c.hint


def test_mysql_down_fails_minixdr_db_items():
    w = World()
    w.broken.add("mysql")
    res = run_all(w)
    assert res["MySQL(mini_xdr DB)"].status == lc.FAIL
    assert "ConnectionError" in res["MySQL(mini_xdr DB)"].detail


def test_board_items_skip_without_board_key():
    res = run_all(World(), board_api_key=None)
    assert res["게시판 대응 결과(차단·티켓)"].status == lc.SKIP and "BOARD_API_KEY" in res["게시판 대응 결과(차단·티켓)"].hint


def test_report_never_contains_secrets(capsys):
    w = World()
    w.broken.add("gl")
    res = run_all(w, zabbix_user="Admin", zabbix_password=ZBX_PW)
    lc.print_report(res.values())
    printed = capsys.readouterr().out + json.dumps([c.__dict__ for c in res.values()], ensure_ascii=False)
    for secret in (GL_TOKEN, BOARD_KEY, ZBX_PW):
        assert secret not in printed
    assert "❌" in printed and "합계" in printed


def test_scrub_removes_known_secret_values():
    assert lc.scrub(f"token={GL_TOKEN} 실패", [GL_TOKEN, None]) == "token=*** 실패"


def test_parsers():
    assert [a[1] for a in lc.parse_agents(AGENTS) if a[2].startswith("Active")] == ["wazuh-manager2 (server)", "board-host"]
    assert lc.parse_workflows(WORKFLOWS)["ipBlockBot0001"].startswith("112 IP 차단봇")
    assert lc.valid_db_name("my_new_board_db") and not lc.valid_db_name("x;DROP")
