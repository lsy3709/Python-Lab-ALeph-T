"""랩 연동 점검 — 게시판(Flask)·MySQL·Wazuh·Graylog·n8n·Zabbix·mini-xdr 가 서로 이어져 있는지 한 번에 본다.

PC(호스트)에서 실행:  python -m app.lab_check        (기계용 출력: --json)
- docker 명령이 필요한 항목(Wazuh 데몬·에이전트, n8n 워크플로·실행 이력, 게시판 DB)은 docker 가 없으면 '건너뜀'.
- 결과에는 상태·건수·버전만 나온다. 키·토큰·비밀번호는 출력하지 않는다.
- ❌ 가 하나라도 있으면 종료 코드 1 — 수업 전 점검 스크립트로 쓴다.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from collections.abc import Callable, Iterable
from contextlib import AbstractContextManager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx
import pymysql

from app.config import Settings, _has

OK, WARN, FAIL, SKIP = "ok", "warn", "fail", "skip"
ICON = {OK: "✅", WARN: "⚠️", FAIL: "❌", SKIP: "⏭️"}
# 랩 기본 컨테이너 이름 — 다르면 여기만 고친다
MYSQL_CT, WAZUH_CT, N8N_CT = "mysql-server", "wazuh-manager2", "n8n"
WAZUH_DAEMONS = ("wazuh-analysisd", "wazuh-remoted", "wazuh-db", "wazuh-apid", "wazuh-csyslogd")
S6_BOT = "ipBlockBot0001"   # 112 IP 차단봇
# n8n 이미지 안의 sqlite3 모듈 경로(n8n 버전이 바뀌면 고친다) — 실행 이력은 CLI 로 못 봐서 DB 를 읽기 전용으로 연다
N8N_SQLITE = "/usr/local/lib/node_modules/n8n/node_modules/.pnpm/sqlite3@5.1.7/node_modules/sqlite3"
AGENT_RE = re.compile(r"ID:\s*(\d+),\s*Name:\s*(.+?),\s*IP:.*?,\s*(\S.*?)\s*$")
DB_NAME_RE = re.compile(r"^[A-Za-z0-9_]{1,64}$")
HINTS = {
    "게시판": "게시판 서버를 켜세요: _7_board_test 폴더에서 python app.py (5000 포트)",
    "Graylog": "docker ps 로 gl-graylog 확인 · .env 의 GRAYLOG_URL·GRAYLOG_TOKEN 확인(토큰 만료 여부)",
    "n8n": "docker ps 로 n8n 컨테이너 확인 · http://127.0.0.1:5678",
    "Zabbix": "docker ps 로 zbx-server·zbx-web 확인 · http://127.0.0.1:8081",
    "MySQL": "docker ps 로 mysql-server 확인 · .env 의 MYSQL_HOST·MYSQL_USER·MYSQL_PASSWORD 확인",
    "mini-xdr": "docker compose ps 로 console·worker 확인 · docker compose up -d",
}


@dataclass(frozen=True)
class Check:
    layer: str
    name: str
    status: str
    detail: str
    hint: str = ""


class Skip(Exception):
    def __init__(self, detail: str, hint: str = "") -> None:
        super().__init__(detail)
        self.detail, self.hint = detail, hint


Runner = Callable[[list[str]], tuple[int, str]]


@dataclass
class Env:
    settings: Settings
    http: httpx.Client
    run: Runner                                   # docker CLI(인자 목록 → (종료 코드, 표준출력))
    open_db: Callable[[], AbstractContextManager]  # mini_xdr DB 연결
    now: Callable[[], datetime]
    ai_status: Callable[[Settings, Any], str]


def docker_run(args: list[str]) -> tuple[int, str]:
    """docker CLI — 설치돼 있지 않으면 FileNotFoundError(호출 쪽이 '건너뜀'으로 바꾼다)."""
    p = subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=60)
    return p.returncode, p.stdout


# ---------- 순수 함수 ----------

def parse_wazuh_status(text: str) -> dict[str, bool]:
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if parts and parts[0].startswith("wazuh-"):
            out[parts[0]] = "is running" in line
    return out


def parse_agents(text: str) -> list[tuple[str, str, str]]:
    """agent_control -l 출력 → [(ID, 이름, 상태)]."""
    return [m.groups() for m in map(AGENT_RE.search, text.splitlines()) if m]


def parse_workflows(text: str) -> dict[str, str]:
    """n8n list:workflow 출력(id|이름) → {id: 이름}. 안내 문구 줄은 버린다."""
    out = {}
    for line in text.splitlines():
        wid, sep, name = line.partition("|")
        if sep and wid.strip():
            out[wid.strip()] = name.strip()
    return out


def short_name(name: str) -> str:
    return name.split(" (")[0]


def valid_db_name(name: str) -> bool:
    return bool(DB_NAME_RE.match(name))


def scrub(text: str, secrets: Iterable[str | None]) -> str:
    for s in secrets:
        if s:
            text = text.replace(s, "***")
    return text


def exit_code(checks: Iterable[Check]) -> int:
    return 1 if any(c.status == FAIL for c in checks) else 0


def _secret(value) -> str | None:
    return value.get_secret_value().strip() if _has(value) else None


def _user(value: str | None) -> str | None:
    return value if value and not value.startswith("<") else None


def _secrets(s: Settings) -> list[str | None]:
    return [_secret(v) for v in (s.graylog_token, s.graylog_password, s.board_api_key, s.zabbix_password,
                                 s.mysql_password, s.anthropic_api_key, s.gemini_api_key, s.settings_secret_key)]


# ---------- 바깥 호출 도우미 ----------

def _get(env: Env, url: str, **kw) -> httpx.Response:
    r = env.http.get(url, timeout=10, **kw)
    r.raise_for_status()
    return r


def _graylog(env: Env, path: str, **params) -> dict:
    token, user, password = env.settings.graylog_credentials()
    if not (token or user):
        raise Skip("Graylog 인증 정보 없음", ".env 에 GRAYLOG_TOKEN(또는 GRAYLOG_USER/PASSWORD)")
    auth = (token, "token") if token else (user, password)
    return _get(env, env.settings.graylog_url.rstrip("/") + path, params=params or None, auth=auth,
                headers={"Accept": "application/json", "X-Requested-By": "mini-xdr"}).json()


def graylog_count(env: Env, query: str, seconds: int = 86400) -> int:
    return int(_graylog(env, "/api/search/universal/relative", query=query, range=str(seconds),
                        limit="1").get("total_results") or 0)


class ZabbixError(RuntimeError):
    pass


def zabbix_call(http: httpx.Client, url: str, method: str, params, token: str | None = None):
    headers = {"Content-Type": "application/json-rpc"}
    if token:
        headers["Authorization"] = f"Bearer {token}"   # Zabbix 7: 세션은 헤더로(본문 auth 는 폐지 예정)
    r = http.post(url, json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1}, headers=headers,
                  timeout=10)
    r.raise_for_status()
    body = r.json()
    if "error" in body:
        raise ZabbixError(str(body["error"].get("data") or body["error"].get("message")))
    return body["result"]


def n8n_executions(env: Env, since_utc: datetime, workflow: str | None = None) -> list[dict]:
    """n8n 실행 이력(시작 시각이 since 이후) — DB 를 읽기 전용으로 연다."""
    where = "startedAt >= ?" + (" AND workflowId = ?" if workflow else "")
    params = [since_utc.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")] + ([workflow] if workflow else [])
    js = (f"const s=require('{N8N_SQLITE}');"
          "const db=new s.Database('/home/node/.n8n/database.sqlite',s.OPEN_READONLY);"
          f"db.all(\"SELECT id,status,startedAt,workflowId FROM execution_entity WHERE {where} "
          f"ORDER BY id DESC LIMIT 500\",{json.dumps(params)},"
          "(e,r)=>{if(e){console.error(e.message);process.exit(1)}console.log(JSON.stringify(r))});")
    rc, out = env.run(["exec", N8N_CT, "node", "-e", js])
    if rc != 0:
        raise RuntimeError("n8n 실행 이력 조회 실패(이미지 버전이 바뀌었으면 N8N_SQLITE 경로 확인)")
    return json.loads(out.strip() or "[]")


# ---------- 점검 항목(각각 (상태, 내용, 안내)) ----------

def check_board_web(env):
    url = env.settings.board_url.rstrip("/")
    _get(env, url + "/")
    return OK, f"{url} → 200", ""


def check_board_db(env):
    db = env.settings.board_db
    if not valid_db_name(db):
        raise Skip("BOARD_DB 이름이 올바르지 않음", "영문·숫자·_ 만")
    sql = (f"SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='{db}'; "
           f"SELECT COUNT(*) FROM {db}.users")
    rc, out = env.run(["exec", MYSQL_CT, "sh", "-c", f'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -N -B -e "{sql}"'])
    vals = out.split()
    if rc != 0 or len(vals) < 2:
        return FAIL, f"{MYSQL_CT} 에서 {db} 조회 실패", "docker ps 로 mysql-server 확인 · 게시판 .env 의 DATABASE_URL 확인"
    return OK, f"{db}: 테이블 {vals[0]}개 · 회원 {vals[1]}명", ""


def check_minixdr_db(env):
    with env.open_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM events_norm WHERE ts >= UTC_TIMESTAMP() - INTERVAL 1 DAY")
        events = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM incidents WHERE status = 'open'")
        incidents = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM triage_results")
        triage = cur.fetchone()[0]
    return OK, f"{env.settings.mysql_db}: 최근 24시간 이벤트 {events}건 · 열린 인시던트 {incidents}건 · 판정 {triage}건", ""


def check_board_signals(env):
    n = graylog_count(env, "_exists_:rule")
    if n:
        return OK, f"최근 24시간 게시판 신호 {n}건(GELF)", ""
    return WARN, "최근 24시간 게시판 신호 0건", "게시판에서 틀린 비밀번호로 한 번 로그인해 신호를 만든 뒤 다시 점검"


def check_wazuh_daemons(env):
    rc, out = env.run(["exec", WAZUH_CT, "/var/ossec/bin/wazuh-control", "status"])
    status = parse_wazuh_status(out)
    if not status:
        return FAIL, f"{WAZUH_CT} 상태 조회 실패(rc={rc})", "docker ps 로 wazuh-manager2 확인"
    down = [d for d in WAZUH_DAEMONS if not status.get(d)]
    if down:
        return FAIL, "멈춘 데몬: " + ", ".join(down), "docker exec wazuh-manager2 /var/ossec/bin/wazuh-control restart"
    return OK, "핵심 데몬 5개 동작(analysisd·remoted·db·apid·csyslogd→Graylog)", ""


def check_wazuh_agents(env):
    _, out = env.run(["exec", WAZUH_CT, "/var/ossec/bin/agent_control", "-l"])
    agents = [a for a in parse_agents(out) if a[0] != "000"]
    active = [a[1] for a in agents if a[2].startswith("Active")]
    if not active:
        return WARN, f"활성 에이전트 0/{len(agents)}", "게시판 PC 의 Wazuh 에이전트 서비스 확인"
    return OK, f"활성 {len(active)}/{len(agents)}: " + ", ".join(active), ""


def check_wazuh_to_graylog(env):
    n = graylog_count(env, "_exists_:wazuh_rule_id")
    if n:
        return OK, f"최근 24시간 Wazuh 경보 {n}건(syslog_output)", ""
    return WARN, "최근 24시간 Wazuh 경보 0건", "ossec.conf 의 syslog_output(→Graylog 5140/udp)·에이전트 연결 확인"


def check_graylog(env):
    version = _graylog(env, "/api/system").get("version", "?")
    states = [x.get("state") for x in _graylog(env, "/api/system/inputstates").get("states", [])]
    running = states.count("RUNNING")
    if states and running == len(states):
        return OK, f"Graylog {version} · 입력 {running}/{len(states)} RUNNING", ""
    return WARN, f"Graylog {version} · 입력 {running}/{len(states)} RUNNING", "System → Inputs 에서 멈춘 입력을 Start"


def check_event_definitions(env):
    body = _graylog(env, "/api/events/definitions", per_page="200")
    titles = [d.get("title", "") for d in body.get("event_definitions", [])]
    has_s6 = any(t.startswith("S6") for t in titles)
    detail = f"이벤트 정의 {body.get('total', len(titles))}개 · S6 {'있음' if has_s6 else '없음'}"
    return (OK, detail, "") if has_s6 else (WARN, detail, "[158] 2장대로 S6 이벤트 정의를 만드세요")


def check_n8n(env):
    status = _get(env, env.settings.n8n_url.rstrip("/") + "/healthz").json().get("status")
    return (OK if status == "ok" else WARN), f"healthz {status}", ""


def check_n8n_workflows(env):
    _, out = env.run(["exec", N8N_CT, "n8n", "list:workflow", "--active=true"])
    active = parse_workflows(out)
    if S6_BOT not in active:
        return WARN, f"활성 워크플로 {len(active)}개 · 112 IP 차단봇 꺼짐", "n8n 화면에서 112 IP 차단봇을 Active 로"
    return OK, f"활성 워크플로 {len(active)}개 · {short_name(active[S6_BOT])} 켜짐", ""


def check_n8n_runs(env):
    rows = n8n_executions(env, env.now() - timedelta(days=1))
    if not rows:
        return OK, "최근 24시간 실행 0건", ""
    failed = [r for r in rows if r.get("status") in ("error", "crashed")]
    if not failed:
        return OK, f"최근 24시간 실행 {len(rows)}건 · 모두 성공", ""
    names = parse_workflows(env.run(["exec", N8N_CT, "n8n", "list:workflow"])[1])
    by = Counter(short_name(names.get(r["workflowId"], r["workflowId"])) for r in failed)
    top = ", ".join(f"{n} {c}건" for n, c in by.most_common(3))
    return (WARN, f"최근 24시간 실행 {len(rows)}건 · 실패 {len(failed)}건({top})",
            "n8n 화면 Executions 에서 실패한 실행을 열어 원인 확인(알림 웹훅 주소·자격 증명 등)")


def check_board_results(env):
    key = _secret(env.settings.board_api_key)
    if not key:
        raise Skip("BOARD_API_KEY 없음",
                   ".env 에 BOARD_API_KEY(게시판 SECURITY_API_KEY 와 같은 값)를 넣으면 차단 IP·티켓도 봅니다")
    base, headers = env.settings.board_url.rstrip("/"), {"X-API-Key": key}
    blocked = _get(env, base + "/api/admin/blocked", headers=headers).json().get("count", 0)
    tickets = _get(env, base + "/api/admin/incidents", params={"status": "open"}, headers=headers).json().get("count", 0)
    return OK, f"차단 IP {blocked}개 · 열린 티켓 {tickets}개", ""


def check_zabbix(env):
    s = env.settings
    version = zabbix_call(env.http, s.zabbix_url, "apiinfo.version", {})
    user, password = _user(s.zabbix_user), _secret(s.zabbix_password)
    if not (user and password):
        return OK, f"Zabbix {version} 응답", "ZABBIX_USER·ZABBIX_PASSWORD 를 .env 에 넣으면 감시 호스트·문제 수도 봅니다"
    token = zabbix_call(env.http, s.zabbix_url, "user.login", {"username": user, "password": password})
    try:
        hosts = zabbix_call(env.http, s.zabbix_url, "host.get", {"countOutput": True, "filter": {"status": 0}}, token)
        problems = int(zabbix_call(env.http, s.zabbix_url, "problem.get", {"countOutput": True}, token))
    finally:
        try:
            zabbix_call(env.http, s.zabbix_url, "user.logout", [], token)
        except (httpx.HTTPError, ZabbixError):
            pass
    detail = f"Zabbix {version} · 감시 호스트 {hosts}대 · 현재 문제 {problems}건"
    if problems:
        return WARN, detail, "Zabbix 웹(http://127.0.0.1:8081) → Monitoring → Problems 확인"
    return OK, detail, ""


def check_collect(env):
    with env.open_db() as conn, conn.cursor() as cur:
        cur.execute("SELECT MAX(updated_at) FROM checkpoints")
        last = cur.fetchone()[0]
    if last is None:
        return WARN, "수집 기록 없음", "워커를 켜세요: docker compose up -d worker (또는 python -m app.worker)"
    age = (env.now().astimezone(timezone.utc).replace(tzinfo=None) - last).total_seconds()
    poll = env.settings.poll_interval_sec
    if age > max(180, poll * 4):
        return WARN, f"마지막 수집 {int(age // 60)}분 전", "워커가 멈췄는지 확인: docker compose ps · docker compose logs worker"
    return OK, f"마지막 수집 {int(age)}초 전(주기 {poll}초)", ""


def check_console(env):
    url = f"http://127.0.0.1:{env.settings.console_port}"
    _get(env, url + "/healthz")
    return OK, f"{url}/ 응답", ""


def check_ai(env):
    with env.open_db() as conn:
        text = env.ai_status(env.settings, conn)
    return OK, text, "AI 교체·키 입력은 콘솔 화면 상단 'AI 설정'(/settings)"


CHECKS = [
    ("게시판", "게시판 웹 응답", check_board_web),
    ("MySQL", "게시판 DB(MySQL)", check_board_db),
    ("MySQL", "MySQL(mini_xdr DB)", check_minixdr_db),
    ("Graylog", "게시판 → Graylog 신호(24시간)", check_board_signals),
    ("Wazuh", "Wazuh 매니저 데몬", check_wazuh_daemons),
    ("Wazuh", "Wazuh 에이전트", check_wazuh_agents),
    ("Graylog", "Wazuh → Graylog 경보(24시간)", check_wazuh_to_graylog),
    ("Graylog", "Graylog 서버·입력", check_graylog),
    ("Graylog", "Graylog 이벤트 정의", check_event_definitions),
    ("n8n", "n8n 서버", check_n8n),
    ("n8n", "n8n 활성 워크플로", check_n8n_workflows),
    ("n8n", "n8n 최근 실행(24시간)", check_n8n_runs),
    ("게시판", "게시판 대응 결과(차단·티켓)", check_board_results),
    ("Zabbix", "Zabbix 가용성 감시", check_zabbix),
    ("mini-xdr", "mini-xdr 수집(Graylog → mini-xdr)", check_collect),
    ("mini-xdr", "mini-xdr 콘솔", check_console),
    ("mini-xdr", "mini-xdr AI 설정", check_ai),
]


def run_checks(env: Env) -> list[Check]:
    secrets = _secrets(env.settings)
    out = []
    for layer, name, fn in CHECKS:
        try:
            status, detail, hint = fn(env)
        except Skip as exc:
            status, detail, hint = SKIP, exc.detail, exc.hint
        except FileNotFoundError:
            status, detail, hint = SKIP, "docker 명령 없음", "PC(호스트)에서 실행하세요 — 컨테이너 안에서는 docker 를 못 씁니다"
        except httpx.HTTPStatusError as exc:
            status, detail, hint = FAIL, f"HTTP {exc.response.status_code}", HINTS.get(layer, "")
        except httpx.HTTPError as exc:
            status, detail, hint = FAIL, f"연결 실패({type(exc).__name__})", HINTS.get(layer, "")
        except Exception as exc:  # 한 항목이 실패해도 나머지는 계속 본다
            status, detail, hint = FAIL, f"{type(exc).__name__}: {str(exc)[:160]}", HINTS.get(layer, "")
        out.append(Check(layer, name, status, scrub(detail, secrets), scrub(hint, secrets)))
    return out


def print_report(checks: Iterable[Check]) -> None:
    checks = list(checks)
    print(f"mini-xdr 랩 연동 점검 — {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    for c in checks:
        print(f"{ICON[c.status]} [{c.layer}] {c.name}: {c.detail}")
        if c.hint:
            print(f"     → {c.hint}")
    n = Counter(c.status for c in checks)
    print(f"합계: ✅ {n[OK]} · ⚠️ {n[WARN]} · ❌ {n[FAIL]} · ⏭️ {n[SKIP]}")


def describe_ai(settings: Settings, conn) -> str:
    from app.llm_settings import effective_llm_config
    from app.secret_box import SecretBox, SecretBoxError
    from app.settings_store import MySQLSettingsRepo
    key = settings.secret_key_value()
    try:
        box = SecretBox(key) if key else None
    except (SecretBoxError, ValueError):
        box = None
    cfg = effective_llm_config(settings, MySQLSettingsRepo(conn), box)
    if cfg.disabled_reason:
        return f"AI 꺼짐 — 규칙 판정({cfg.disabled_reason})"
    source = {"ui": "웹 UI 저장 키", "env": "이 PC 의 환경변수·.env 키(컨테이너 워커는 .env·웹 UI 키만 봄)"}
    return f"AI {cfg.provider} · {cfg.model} · {source.get(cfg.key_source, '-')}"


def connect_db(settings: Settings):
    return pymysql.connect(host=settings.mysql_host, port=settings.mysql_port, user=settings.mysql_user,
                           password=_secret(settings.mysql_password) or "", database=settings.mysql_db,
                           charset="utf8mb4", autocommit=True, connect_timeout=5,
                           init_command="SET time_zone = '+00:00'")


def make_env(settings: Settings, http: httpx.Client) -> Env:
    return Env(settings=settings, http=http, run=docker_run, open_db=lambda: connect_db(settings),
               now=lambda: datetime.now(timezone.utc), ai_status=describe_ai)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.lab_check", description="mini-xdr 랩 연동 점검")
    ap.add_argument("--json", action="store_true", help="기계용 JSON 출력")
    args = ap.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass
    with httpx.Client() as http:
        checks = run_checks(make_env(Settings(), http))
    if args.json:
        print(json.dumps([asdict(c) for c in checks], ensure_ascii=False, indent=2))
    else:
        print_report(checks)
    return exit_code(checks)


if __name__ == "__main__":
    raise SystemExit(main())
