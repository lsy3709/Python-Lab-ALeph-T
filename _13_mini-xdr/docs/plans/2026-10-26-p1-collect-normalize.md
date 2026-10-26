# 미니 XDR P1 — 수집·정규화 구현 계획

> **에이전트 작업자용:** 필수 하위 스킬 — `superpowers:subagent-driven-development`(권장) 또는 `superpowers:executing-plans` 로 작업 단위 실행. 단계는 체크박스(`- [ ]`)로 추적.

**목표:** Graylog 에 쌓이는 Wazuh 경보·게시판 신호·pfSense·Suricata 로그를 가져와 공통 스키마로 정규화하고 `mini_xdr.events_norm` 에 중복 없이 적재한다. 체크포인트로 끊겨도 이어 받는다.

**설계:** [186] 3장 ①collector·②normalizer·⑧store. 실행은 P1 에선 호스트 Python 워커(`python -m app.worker`)가 `localhost:9000`(Graylog)·`localhost:3306`(MySQL)에 붙는다. 컨테이너화는 콘솔이 생기는 P2 에서.

**기술:** httpx(동기 클라이언트, 테스트는 `MockTransport`) · PyMySQL · 기존 pydantic-settings

## 라이브 랩에서 확인한 사실 (2026-10-26)

| 항목 | 값 |
|---|---|
| Graylog | 6.1.16, 시간대 Asia/Seoul. `/api/search/universal/absolute` 가 ISO 시각·`sort=timestamp:asc`·`fields` 지정 모두 동작. `Accept: application/json` 필수 |
| 고유 ID | 모든 메시지에 `gl2_message_id`(26자) → `raw_ref` |
| 같은 밀리초 | 한 밀리초에 메시지 여러 건 존재 → 페이지 경계 중복·정체 대비 필요 |
| Wazuh 경보 | `wazuh_rule_id`·`wazuh_rule_level`·`wazuh_rule_groups`(JSON 문자열)·`wazuh_rule_mitre_id`(JSON 문자열)·`wazuh_agent_name`·`wazuh_data_srcip`·`wazuh_data_dstuser` |
| 게시판 GELF | `source=board`, `rule`(login-bruteforce·login-success·web-scan·admin-auth-fail·blocked-retry·gold-access), `src_ip`, `username` |
| 봇 GELF | `rule=priv-unauthorized-admin`, `source`=봇 호스트명, `user`·`username` |
| pfSense | `source=pfSense`, `rule=pfsense-block`, `src_ip`·`dst_ip`·`dst_port` |
| Suricata 포워더 | `source=suricata`, `rule=ids-alert`, `src_ip` |
| MySQL | 컨테이너 `mysql-server`, **MySQL 26.7.0**, 루트 비번은 컨테이너 환경변수 |

## 정규화 규칙

| 원본 | source | layer | event_type | src_ip / user_name / asset | level · rule_id · mitre |
|---|---|---|---|---|---|
| `wazuh_rule_id` 있음 | wazuh | 그룹에 `ids` → network, `mysql_audit` → data, `webapp`·`flask_board`·`web_scan` → app, 그 외 host | wazuh-alert | `wazuh_data_srcip` / `wazuh_data_dstuser` 또는 `wazuh_data_srcuser` / `wazuh_agent_name` | 레벨 정수 · 룰 ID · MITRE ID 쉼표 연결 |
| `rule=pfsense-block` 또는 `source=pfSense` | pfsense | network | pfsense-block | `src_ip` / — / `pfSense` | — |
| `rule=ids-alert` 또는 `source=suricata` | suricata | network | ids-alert | `src_ip` / — / `suricata` | — |
| 그 밖에 `rule` 있음 | board | app | `rule` 값 | `src_ip` / `username` 또는 `user` / 메시지 `source` | — |
| 둘 다 없음 | 건너뜀 | | | | |

- 계층은 **센서가 아니라 내용 기준**: Wazuh 가 게시판 로그를 읽어 낸 100230(404)은 app 이다. 같은 사건을 게시판 GELF 와 Wazuh 가 함께 봐도 "다계층" 으로 부풀지 않게 한다.
- 시각은 **UTC** 로 저장(`DATETIME(3)`), 체크포인트도 UTC.

## 수집 알고리즘

1. 시작점 = 체크포인트 `last_ts - overlap`(기본 60초). 체크포인트가 없으면 `now - backfill`(기본 1440분).
2. 끝점 `to = now - 2초`(색인 지연 여유).
3. `[cursor, to]` 를 오름차순 `limit=page_size`(기본 500)로 조회 → 정규화 → `INSERT IGNORE`(raw_ref 유니크로 중복 무시).
4. 페이지 마지막 시각이 cursor 보다 크면 cursor 를 그 시각으로 옮기고 offset 0. **같으면(전부 같은 밀리초) offset 을 늘려 다음 묶음**(정체 방지).
5. 페이지가 page_size 보다 적으면 그 창을 다 읽은 것 → 체크포인트 = `to`. 한 주기 최대 페이지(기본 50)를 넘기면 마지막 처리 시각을 체크포인트로 두고 다음 주기에 이어간다.
6. Graylog·DB 오류는 체크포인트를 옮기지 않는다(다음 주기 재시도).

---

## 파일 구조

| 파일 | 책임 |
|---|---|
| `app/normalizer.py` | `NormalizedEvent`·`normalize(msg)` — 위 정규화 규칙 |
| `app/graylog.py` | `GraylogClient.search_absolute()` — 인증(토큰 우선, 없으면 계정)·헤더·오류 |
| `app/collector.py` | `collect_once(client, store, cfg, now)` — 위 수집 알고리즘(외부 의존은 주입) |
| `app/store.py` | `MySQLStore` — 체크포인트 읽기/쓰기, 이벤트 `INSERT IGNORE` |
| `app/worker.py` | `python -m app.worker [--once]` — 설정으로 조립해 주기 실행·요약 로그 |
| `app/config.py` (수정) | Graylog 계정 인증·수집 설정 추가 |
| `.env.example` (수정) | 새 설정 키 |
| `requirements.txt` (수정) | httpx·PyMySQL |
| `fixtures/graylog_messages.json` | 실데이터 구조로 만든 표본(TEST-NET IP·테스트 계정만) |
| `tests/conftest.py` | 세션 범위 일회용 MySQL 컨테이너(스키마·저장소 통합 테스트 공유) |
| `tests/test_normalizer.py` · `test_graylog_client.py` · `test_collector.py` | 단위 |
| `tests/test_store_mysql.py` | (integration) 중복 무시·체크포인트 갱신·UTC 왕복 |

---

### Task 1: 정규화 — `app/normalizer.py`

- [ ] **Step 1: 표본 작성** — `fixtures/graylog_messages.json`

```json
{
  "wazuh_bruteforce": {"gl2_message_id": "01M5GRJ89N00001RXERQFFTX3Z", "timestamp": "2026-10-22T02:55:39.317Z", "source": "ha-board-container",
    "wazuh_rule_id": "100211", "wazuh_rule_level": 10, "wazuh_rule_groups": "[\"webapp\",\"local\",\"authentication_failures\"]",
    "wazuh_rule_mitre_id": "[\"T1110\"]", "wazuh_agent_name": "ha-board-container", "wazuh_data_srcip": "198.51.100.77", "wazuh_data_dstuser": "victim"},
  "wazuh_suricata_sqlmap": {"gl2_message_id": "01M5TESTSURICATA0000000001", "timestamp": "2026-10-22T03:10:00.000Z", "source": "ha-board-container",
    "wazuh_rule_id": "100242", "wazuh_rule_level": 12, "wazuh_rule_groups": "[\"suricata\",\"ids\",\"local\",\"ids_alert\",\"sqlmap\",\"sql_injection\"]",
    "wazuh_rule_mitre_id": "[\"T1190\"]", "wazuh_agent_name": "ha-board-container", "wazuh_data_srcip": "203.0.113.34"},
  "wazuh_mysql_audit": {"gl2_message_id": "01M5TESTMYSQLAUDIT00000001", "timestamp": "2026-10-22T03:20:00.000Z", "source": "board-host",
    "wazuh_rule_id": "100250", "wazuh_rule_level": 10, "wazuh_rule_groups": "[\"mysql_audit\",\"local\"]",
    "wazuh_rule_mitre_id": "[\"T1213\"]", "wazuh_agent_name": "board-host"},
  "wazuh_sca": {"gl2_message_id": "01M5TESTSCA000000000000001", "timestamp": "2026-10-22T03:30:00.000Z", "source": "board-host",
    "wazuh_rule_id": "19007", "wazuh_rule_level": 7, "wazuh_rule_groups": "[\"sca\"]", "wazuh_agent_name": "board-host"},
  "wazuh_http404": {"gl2_message_id": "01M5TESTHTTP4040000000001", "timestamp": "2026-10-22T03:40:00.000Z", "source": "ha-board-container",
    "wazuh_rule_id": "100230", "wazuh_rule_level": 5, "wazuh_rule_groups": "[\"flask_board\",\"webscan\",\"local\",\"web_scan\",\"http_404\"]",
    "wazuh_agent_name": "ha-board-container", "wazuh_data_srcip": "203.0.113.31"},
  "board_login_fail": {"gl2_message_id": "01M5TESTBOARDLOGIN0000001", "timestamp": "2026-10-16T07:20:00.123Z", "source": "board",
    "rule": "login-bruteforce", "src_ip": "203.0.113.99", "username": "zz_probe", "outcome": "fail"},
  "board_web_scan": {"gl2_message_id": "01M51SN8FC0000002Q1J170R0D", "timestamp": "2026-10-16T07:26:09.900Z", "source": "board",
    "rule": "web-scan", "src_ip": "192.168.219.103", "path": "/api/workspaces", "code": 404, "signal_kind": "web-404"},
  "bot_priv": {"gl2_message_id": "01M5TESTBOTPRIV0000000001", "timestamp": "2026-10-16T08:00:00.000Z", "source": "LAB-BOT-HOST",
    "rule": "priv-unauthorized-admin", "src_ip": "203.0.113.190", "user": "zz_s9v"},
  "pfsense_block": {"gl2_message_id": "01M4ZS8AC800001F6P5Q2SGAG8", "timestamp": "2026-10-15T12:40:37.000Z", "source": "pfSense",
    "rule": "pfsense-block", "src_ip": "192.168.120.1", "dst_ip": "192.168.120.255", "dst_port": 137},
  "suricata_ids": {"gl2_message_id": "01M5TESTSURIFWD000000001", "timestamp": "2026-10-18T05:00:00.000Z", "source": "suricata",
    "rule": "ids-alert", "src_ip": "172.31.195.249"},
  "plain_syslog": {"gl2_message_id": "01M5TESTPLAIN00000000001", "timestamp": "2026-10-18T05:00:01.000Z", "source": "somehost",
    "message": "ordinary log line without security fields"}
}
```

- [ ] **Step 2: 실패하는 테스트** — `tests/test_normalizer.py`

```python
"""정규화 — 실데이터 구조 표본으로 출처·계층·필드 매핑을 확인한다."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.normalizer import normalize

FIX = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "graylog_messages.json").read_text(encoding="utf-8"))


def test_wazuh_bruteforce_is_app_layer_with_mitre_and_user():
    e = normalize(FIX["wazuh_bruteforce"])
    assert (e.source, e.layer, e.event_type) == ("wazuh", "app", "wazuh-alert")
    assert (e.rule_id, e.level, e.mitre) == ("100211", 10, "T1110")
    assert (e.src_ip, e.user_name, e.asset) == ("198.51.100.77", "victim", "ha-board-container")
    assert e.raw_ref == "01M5GRJ89N00001RXERQFFTX3Z"
    assert e.ts == datetime(2026, 10, 22, 2, 55, 39, 317000, tzinfo=timezone.utc)


@pytest.mark.parametrize("key, layer", [
    ("wazuh_suricata_sqlmap", "network"),
    ("wazuh_mysql_audit", "data"),
    ("wazuh_sca", "host"),
    ("wazuh_http404", "app"),
])
def test_wazuh_layer_follows_rule_groups(key, layer):
    assert normalize(FIX[key]).layer == layer


def test_wazuh_without_srcip_keeps_none():
    e = normalize(FIX["wazuh_sca"])
    assert e.src_ip is None and e.mitre is None


def test_board_signal_is_app_layer_with_rule_as_event_type():
    e = normalize(FIX["board_login_fail"])
    assert (e.source, e.layer, e.event_type) == ("board", "app", "login-bruteforce")
    assert (e.src_ip, e.user_name, e.asset) == ("203.0.113.99", "zz_probe", "board")
    assert e.rule_id is None and e.level is None


def test_bot_signal_uses_user_field_and_host_as_asset():
    e = normalize(FIX["bot_priv"])
    assert (e.source, e.event_type, e.user_name, e.asset) == ("board", "priv-unauthorized-admin", "zz_s9v", "LAB-BOT-HOST")


def test_pfsense_and_suricata_are_network():
    p = normalize(FIX["pfsense_block"])
    s = normalize(FIX["suricata_ids"])
    assert (p.source, p.layer, p.event_type, p.asset) == ("pfsense", "network", "pfsense-block", "pfSense")
    assert (s.source, s.layer, s.event_type, s.asset) == ("suricata", "network", "ids-alert", "suricata")


def test_message_without_security_fields_is_skipped():
    assert normalize(FIX["plain_syslog"]) is None


def test_mitre_already_list_and_long_values_are_trimmed():
    msg = dict(FIX["wazuh_bruteforce"], wazuh_rule_mitre_id=["T1110", "T1078"], wazuh_data_dstuser="u" * 300)
    e = normalize(msg)
    assert e.mitre == "T1110,T1078"
    assert len(e.user_name) == 128


def test_missing_message_id_falls_back_to_index_id():
    msg = {k: v for k, v in FIX["board_web_scan"].items() if k != "gl2_message_id"}
    msg["_id"] = "dbdfa190-c932-11f1-b38a-26acc1b822e4"
    assert normalize(msg).raw_ref == "dbdfa190-c932-11f1-b38a-26acc1b822e4"
```

- [ ] **Step 3: 실행 → 실패 확인** — `python -m pytest tests/test_normalizer.py -q` → `ModuleNotFoundError: app.normalizer`

- [ ] **Step 4: 구현** — `app/normalizer.py`

```python
"""Graylog 메시지 → 공통 스키마(events_norm) 정규화.

계층(layer)은 센서가 아니라 '내용' 기준이다. Wazuh 가 게시판 로그를 읽어 낸 경보는 app 으로 둬서,
같은 사건을 게시판 GELF 와 Wazuh 가 함께 봐도 다계층으로 부풀지 않게 한다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

APP_GROUPS = {"webapp", "flask_board", "web_scan"}


@dataclass(frozen=True)
class NormalizedEvent:
    ts: datetime          # UTC aware
    layer: str            # app · host · network · data
    source: str           # wazuh · board · pfsense · suricata
    event_type: str
    raw_ref: str
    src_ip: str | None = None
    user_name: str | None = None
    asset: str | None = None
    rule_id: str | None = None
    level: int | None = None
    mitre: str | None = None


def _cut(value: Any, size: int) -> str | None:
    if value is None or value == "":
        return None
    return str(value)[:size]


def _as_list(value: Any) -> list[str]:
    """Graylog 는 배열 필드를 JSON 문자열('["T1110"]')로 줄 때가 있다."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return [str(value)]
    return [str(v) for v in parsed] if isinstance(parsed, list) else [str(parsed)]


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _wazuh_layer(groups: list[str]) -> str:
    g = set(groups)
    if "ids" in g:
        return "network"
    if "mysql_audit" in g:
        return "data"
    if g & APP_GROUPS:
        return "app"
    return "host"


def normalize(msg: dict[str, Any]) -> NormalizedEvent | None:
    raw_ref = msg.get("gl2_message_id") or msg.get("_id")
    if not raw_ref or "timestamp" not in msg:
        return None
    ts = _parse_ts(msg["timestamp"])

    if msg.get("wazuh_rule_id"):
        groups = _as_list(msg.get("wazuh_rule_groups"))
        mitre = ",".join(_as_list(msg.get("wazuh_rule_mitre_id"))) or None
        level = msg.get("wazuh_rule_level")
        return NormalizedEvent(
            ts=ts, layer=_wazuh_layer(groups), source="wazuh", event_type="wazuh-alert", raw_ref=raw_ref,
            src_ip=_cut(msg.get("wazuh_data_srcip"), 45),
            user_name=_cut(msg.get("wazuh_data_dstuser") or msg.get("wazuh_data_srcuser"), 128),
            asset=_cut(msg.get("wazuh_agent_name"), 128),
            rule_id=_cut(msg["wazuh_rule_id"], 16),
            level=int(level) if level not in (None, "") else None,
            mitre=_cut(mitre, 64),
        )

    rule = msg.get("rule")
    origin = msg.get("source")
    if rule == "pfsense-block" or origin == "pfSense":
        return NormalizedEvent(ts=ts, layer="network", source="pfsense", event_type="pfsense-block",
                               raw_ref=raw_ref, src_ip=_cut(msg.get("src_ip"), 45), asset="pfSense")
    if rule == "ids-alert" or origin == "suricata":
        return NormalizedEvent(ts=ts, layer="network", source="suricata", event_type="ids-alert",
                               raw_ref=raw_ref, src_ip=_cut(msg.get("src_ip"), 45), asset="suricata")
    if rule:
        return NormalizedEvent(
            ts=ts, layer="app", source="board", event_type=_cut(rule, 64), raw_ref=raw_ref,
            src_ip=_cut(msg.get("src_ip"), 45),
            user_name=_cut(msg.get("username") or msg.get("user"), 128),
            asset=_cut(origin, 128),
        )
    return None
```

- [ ] **Step 5: 실행 → 통과** — `python -m pytest tests/test_normalizer.py -q` → 12 passed
- [ ] **Step 6: 커밋·푸시** — `feat(mini-xdr): P1 정규화 — Wazuh·게시판·pfSense·Suricata → 공통 스키마`

---

### Task 2: Graylog 클라이언트 — `app/graylog.py`

- [ ] **Step 1: 실패하는 테스트** — `tests/test_graylog_client.py`

```python
"""Graylog 검색 클라이언트 — 실제 네트워크 없이 httpx.MockTransport 로 요청 모양을 검증한다."""
import base64
from datetime import datetime, timezone

import httpx
import pytest

from app.graylog import GraylogClient, GraylogError

T0 = datetime(2026, 10, 22, 2, 55, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 10, 22, 2, 56, 0, tzinfo=timezone.utc)


def _client(handler, **kw):
    return GraylogClient("http://graylog:9000", transport=httpx.MockTransport(handler), **kw)


def test_absolute_search_sends_required_headers_and_params():
    seen = {}

    def handler(request):
        seen["req"] = request
        return httpx.Response(200, json={"messages": [{"message": {"gl2_message_id": "a"}}], "total_results": 1})

    msgs = _client(handler, token="tok").search_absolute("q:1", T0, T1, limit=500, offset=0, fields=["timestamp", "rule"])
    req = seen["req"]
    assert req.url.path == "/api/search/universal/absolute"
    assert req.headers["Accept"] == "application/json"
    assert req.headers["X-Requested-By"] == "mini-xdr"
    p = req.url.params
    assert (p["query"], p["limit"], p["offset"], p["sort"]) == ("q:1", "500", "0", "timestamp:asc")
    assert (p["from"], p["to"]) == ("2026-10-22T02:55:00.000Z", "2026-10-22T02:56:00.000Z")
    assert p["fields"] == "timestamp,rule"
    assert msgs == [{"gl2_message_id": "a"}]


def test_token_auth_uses_token_as_username():
    seen = {}
    _client(lambda r: seen.setdefault("a", r.headers["Authorization"]) and httpx.Response(200, json={"messages": []}),
            token="tok").search_absolute("*", T0, T1)
    assert base64.b64decode(seen["a"].split()[1]) == b"tok:token"


def test_user_password_auth_when_no_token():
    seen = {}
    _client(lambda r: seen.setdefault("a", r.headers["Authorization"]) and httpx.Response(200, json={"messages": []}),
            user="u", password="p").search_absolute("*", T0, T1)
    assert base64.b64decode(seen["a"].split()[1]) == b"u:p"


def test_http_error_raises_without_leaking_credentials():
    with pytest.raises(GraylogError) as err:
        _client(lambda r: httpx.Response(401, text="unauthorized"), token="tok").search_absolute("*", T0, T1)
    assert "401" in str(err.value) and "tok" not in str(err.value)


def test_requires_some_credentials():
    with pytest.raises(ValueError):
        GraylogClient("http://graylog:9000")
```

- [ ] **Step 2: 실행 → 실패 확인** — `ModuleNotFoundError: app.graylog`

- [ ] **Step 3: 구현** — `app/graylog.py`

```python
"""Graylog 검색 API 클라이언트(동기). 인증은 API 토큰 우선, 없으면 계정."""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

import httpx


class GraylogError(RuntimeError):
    """Graylog 호출 실패(상태 코드만 담고 인증 정보는 담지 않는다)."""


def _iso(ts: datetime) -> str:
    return ts.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z"


class GraylogClient:
    def __init__(self, base_url: str, *, token: str | None = None, user: str | None = None,
                 password: str | None = None, timeout: float = 15.0,
                 transport: httpx.BaseTransport | None = None) -> None:
        if token:
            auth = (token, "token")  # Graylog 토큰 인증 규칙: 사용자명=토큰, 비밀번호="token"
        elif user and password:
            auth = (user, password)
        else:
            raise ValueError("Graylog 인증 정보가 없습니다(GRAYLOG_TOKEN 또는 GRAYLOG_USER/PASSWORD)")
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"), auth=auth, timeout=timeout, transport=transport,
            headers={"Accept": "application/json", "X-Requested-By": "mini-xdr"},
        )

    def search_absolute(self, query: str, frm: datetime, to: datetime, *, limit: int = 500,
                        offset: int = 0, fields: Sequence[str] | None = None) -> list[dict[str, Any]]:
        params = {"query": query, "from": _iso(frm), "to": _iso(to), "limit": str(limit),
                  "offset": str(offset), "sort": "timestamp:asc"}
        if fields:
            params["fields"] = ",".join(fields)
        try:
            resp = self._http.get("/api/search/universal/absolute", params=params)
        except httpx.HTTPError as exc:
            raise GraylogError(f"Graylog 연결 실패: {type(exc).__name__}") from None
        if resp.status_code != 200:
            raise GraylogError(f"Graylog 검색 실패: HTTP {resp.status_code}")
        return [m["message"] for m in resp.json().get("messages", [])]

    def close(self) -> None:
        self._http.close()
```

- [ ] **Step 4: 실행 → 통과** — 5 passed
- [ ] **Step 5: 커밋·푸시** — `feat(mini-xdr): P1 Graylog 검색 클라이언트 — 토큰/계정 인증·필수 헤더·오류 시 비밀 미노출`

---

### Task 3: 수집기 — `app/collector.py`

- [ ] **Step 1: 실패하는 테스트** — `tests/test_collector.py`

```python
"""수집 알고리즘 — 가짜 Graylog·가짜 저장소로 체크포인트·페이지·정체 방지를 검증한다."""
from datetime import datetime, timedelta, timezone

from app.collector import CollectConfig, collect_once

NOW = datetime(2026, 10, 26, 6, 0, 0, tzinfo=timezone.utc)
SRC = "graylog"


def msg(i, ts, rule="web-scan"):
    return {"gl2_message_id": f"id{i:04d}", "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "source": "board", "rule": rule, "src_ip": "203.0.113.5"}


class FakeGraylog:
    def __init__(self, messages, fail=False):
        self.messages = sorted(messages, key=lambda m: m["timestamp"])
        self.calls = []
        self.fail = fail

    def search_absolute(self, query, frm, to, *, limit, offset, fields=None):
        self.calls.append((frm, to, limit, offset))
        if self.fail:
            from app.graylog import GraylogError
            raise GraylogError("HTTP 500")
        f = lambda m: datetime.fromisoformat(m["timestamp"].replace("Z", "+00:00"))
        hits = [m for m in self.messages if frm <= f(m) <= to]
        return hits[offset:offset + limit]


class FakeStore:
    def __init__(self, checkpoint=None):
        self.checkpoint = checkpoint
        self.rows = {}

    def get_checkpoint(self, source):
        return self.checkpoint

    def set_checkpoint(self, source, ts, last_id=None):
        self.checkpoint = ts

    def insert_events(self, events):
        new = [e for e in events if e.raw_ref not in self.rows]
        self.rows.update({e.raw_ref: e for e in new})
        return len(new)


CFG = CollectConfig(query="*", page_size=3, overlap=timedelta(seconds=60),
                    backfill=timedelta(minutes=10), max_pages=50, lag=timedelta(seconds=2))


def test_first_run_backfills_and_sets_checkpoint_to_window_end():
    g = FakeGraylog([msg(1, NOW - timedelta(minutes=5)), msg(2, NOW - timedelta(minutes=20))])
    s = FakeStore()
    r = collect_once(g, s, CFG, NOW, source=SRC)
    assert g.calls[0][0] == NOW - timedelta(minutes=10)
    assert (r.fetched, r.inserted) == (1, 1)
    assert s.checkpoint == NOW - timedelta(seconds=2)


def test_resumes_from_checkpoint_minus_overlap_and_dedupes():
    cp = NOW - timedelta(minutes=3)
    g = FakeGraylog([msg(1, cp - timedelta(seconds=30)), msg(2, cp + timedelta(seconds=10))])
    s = FakeStore(checkpoint=cp)
    s.rows["id0001"] = object()  # 이전 주기에 이미 적재된 것
    r = collect_once(g, s, CFG, NOW, source=SRC)
    assert g.calls[0][0] == cp - timedelta(seconds=60)
    assert (r.fetched, r.inserted, r.duplicates) == (2, 1, 1)


def test_pages_through_more_than_page_size():
    base = NOW - timedelta(minutes=5)
    g = FakeGraylog([msg(i, base + timedelta(seconds=i)) for i in range(7)])
    s = FakeStore()
    r = collect_once(g, s, CFG, NOW, source=SRC)
    assert r.inserted == 7 and len(s.rows) == 7


def test_same_millisecond_block_does_not_stall():
    same = NOW - timedelta(minutes=5)
    g = FakeGraylog([msg(i, same) for i in range(8)])  # 8건이 같은 밀리초, page_size=3
    s = FakeStore()
    r = collect_once(g, s, CFG, NOW, source=SRC)
    assert r.inserted == 8
    assert len(g.calls) < 20


def test_skipped_messages_are_counted():
    m = msg(1, NOW - timedelta(minutes=1))
    plain = {"gl2_message_id": "plain1", "timestamp": m["timestamp"], "source": "x", "message": "hi"}
    s = FakeStore()
    r = collect_once(FakeGraylog([m, plain]), s, CFG, NOW, source=SRC)
    assert (r.fetched, r.skipped, r.inserted) == (2, 1, 1)


def test_graylog_error_keeps_checkpoint():
    cp = NOW - timedelta(minutes=3)
    s = FakeStore(checkpoint=cp)
    r = collect_once(FakeGraylog([], fail=True), s, CFG, NOW, source=SRC)
    assert r.error and s.checkpoint == cp


def test_max_pages_stops_early_and_checkpoints_last_processed():
    base = NOW - timedelta(minutes=5)
    g = FakeGraylog([msg(i, base + timedelta(seconds=i)) for i in range(10)])
    s = FakeStore()
    cfg = CollectConfig(**{**CFG.__dict__, "max_pages": 2})
    r = collect_once(g, s, cfg, NOW, source=SRC)
    # 1쪽: id0~2 적재 → cursor=base+2초 / 2쪽: base+2초부터 id2(중복)·id3·id4 → 2페이지에서 멈춤
    assert (r.inserted, r.duplicates) == (5, 1)
    assert s.checkpoint == base + timedelta(seconds=4)
```

- [ ] **Step 2: 실행 → 실패 확인** — `ModuleNotFoundError: app.collector`. (이 작업부터 테스트끼리 import 하므로 빈 `tests/__init__.py` 를 함께 만든다.)

- [ ] **Step 3: 구현** — `app/collector.py`

```python
"""수집 한 주기 — 체크포인트부터 Graylog 를 오름차순으로 읽어 정규화·적재한다.

같은 밀리초 메시지 묶음에서 멈추지 않도록 offset 으로 넘기고, 늦게 색인된 메시지는
다음 주기의 overlap 재조회와 raw_ref 중복 무시(INSERT IGNORE)로 놓치지 않는다.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from app.graylog import GraylogError
from app.normalizer import NormalizedEvent, normalize

FIELDS = (
    "gl2_message_id", "timestamp", "source", "rule", "src_ip", "username", "user",
    "wazuh_rule_id", "wazuh_rule_level", "wazuh_rule_groups", "wazuh_rule_mitre_id",
    "wazuh_agent_name", "wazuh_data_srcip", "wazuh_data_dstuser", "wazuh_data_srcuser",
)


class Searcher(Protocol):
    def search_absolute(self, query, frm, to, *, limit, offset, fields=None) -> list[dict]: ...


class EventStore(Protocol):
    def get_checkpoint(self, source: str) -> datetime | None: ...
    def set_checkpoint(self, source: str, ts: datetime, last_id: str | None = None) -> None: ...
    def insert_events(self, events: list[NormalizedEvent]) -> int: ...


@dataclass(frozen=True)
class CollectConfig:
    query: str
    page_size: int = 500
    overlap: timedelta = timedelta(seconds=60)
    backfill: timedelta = timedelta(minutes=1440)
    max_pages: int = 50
    lag: timedelta = timedelta(seconds=2)


@dataclass
class CollectResult:
    fetched: int = 0
    skipped: int = 0
    inserted: int = 0
    duplicates: int = 0
    pages: int = 0
    window_from: datetime | None = None
    window_to: datetime | None = None
    error: str | None = None


def collect_once(client: Searcher, store: EventStore, cfg: CollectConfig, now: datetime,
                 *, source: str = "graylog") -> CollectResult:
    checkpoint = store.get_checkpoint(source)
    start = (checkpoint - cfg.overlap) if checkpoint else (now - cfg.backfill)
    end = now - cfg.lag
    result = CollectResult(window_from=start, window_to=end)
    cursor, offset, last_seen = start, 0, None

    try:
        while result.pages < cfg.max_pages:
            page = client.search_absolute(cfg.query, cursor, end, limit=cfg.page_size,
                                          offset=offset, fields=FIELDS)
            result.pages += 1
            if not page:
                break
            events = [e for e in (normalize(m) for m in page) if e is not None]
            result.fetched += len(page)
            result.skipped += len(page) - len(events)
            inserted = store.insert_events(events) if events else 0
            result.inserted += inserted
            result.duplicates += len(events) - inserted

            page_last = max(datetime.fromisoformat(m["timestamp"].replace("Z", "+00:00")) for m in page)
            last_seen = page_last
            if len(page) < cfg.page_size:
                break
            if page_last > cursor:
                cursor, offset = page_last, 0
            else:
                offset += len(page)  # 전부 같은 밀리초 → 다음 묶음으로
        else:
            store.set_checkpoint(source, last_seen or start)
            return result
    except GraylogError as exc:
        result.error = str(exc)
        return result

    store.set_checkpoint(source, end)
    return result
```

- [ ] **Step 4: 실행 → 통과** — 7 passed
- [ ] **Step 5: 커밋·푸시** — `feat(mini-xdr): P1 수집기 — 체크포인트·overlap·페이지·같은 밀리초 정체 방지`

---

### Task 4: 저장소 — `app/store.py` 와 공유 MySQL 픽스처

- [ ] **Step 1: 공유 픽스처로 이동** — `tests/conftest.py` 에 세션 범위 `mysql_container`·`mysql_cli`·`schema_applied` 를 두고 `tests/test_schema_mysql.py` 는 그것을 쓰도록 정리(같은 컨테이너를 스키마·저장소 테스트가 함께 사용). 테스트 이미지는 환경변수 `MINI_XDR_TEST_MYSQL_IMAGE`(기본 `mysql:8.0`)로 바꿀 수 있게 한다. 컨테이너는 호스트 포트를 무작위로 열어(`-p 127.0.0.1::3306`) PyMySQL 저장소 테스트도 붙을 수 있게 한다.

```python
"""공용 테스트 픽스처 — 일회용 MySQL 컨테이너(통합 테스트 전용)."""
import os
import shutil
import subprocess
import time
import uuid

import pytest

from app.schema import SCHEMA_PATH

ROOT_PW = "xdr_throwaway_test_pw"  # 테스트가 끝나면 삭제되는 일회용 컨테이너 전용
IMAGE = os.environ.get("MINI_XDR_TEST_MYSQL_IMAGE", "mysql:8.0")


def _docker_ready() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "info"], capture_output=True).returncode == 0


def run_mysql(name: str, *args: str, input_sql: str | None = None) -> subprocess.CompletedProcess:
    # -h 127.0.0.1 TCP 접속: 초기화용 임시 서버(소켓 전용)가 아닌 최종 서버에만 붙는다.
    cmd = ["docker", "exec", "-i", name, "mysql", "-h", "127.0.0.1", "--protocol=TCP",
           "-uroot", f"-p{ROOT_PW}", *args]
    return subprocess.run(cmd, input=input_sql, capture_output=True, text=True, encoding="utf-8")


@pytest.fixture(scope="session")
def mysql_container():
    if not _docker_ready():
        pytest.skip("docker 를 쓸 수 없음")
    name = f"mini-xdr-test-{uuid.uuid4().hex[:8]}"
    subprocess.run(["docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1::3306",
                    "-e", f"MYSQL_ROOT_PASSWORD={ROOT_PW}", IMAGE], check=True, capture_output=True)
    try:
        deadline = time.time() + 180
        while run_mysql(name, "-e", "SELECT 1").returncode != 0:
            if time.time() > deadline:
                pytest.fail("MySQL 준비 시간 초과")
            time.sleep(2)
        port = subprocess.run(["docker", "port", name, "3306/tcp"], capture_output=True, text=True,
                              check=True).stdout.strip().splitlines()[0].rsplit(":", 1)[1]
        yield {"name": name, "port": int(port)}
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)


@pytest.fixture(scope="session")
def schema_applied(mysql_container):
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    for attempt in (1, 2):  # 두 번 적용해도 오류가 없어야 한다(멱등)
        r = run_mysql(mysql_container["name"], input_sql=sql)
        assert r.returncode == 0, f"{attempt}회차 적용 실패: {r.stderr}"
    return mysql_container
```

실제 배치: 상수·`run_mysql`·`docker_ready` 는 **`tests/_mysql.py`**(테스트 파일이 import 할 수 있게), 픽스처 `mysql_container`·`schema_applied` 는 **`tests/conftest.py`**(위 코드에서 helper 를 `from tests._mysql import ...` 로 가져옴). `tests/test_schema_mysql.py` 는 자기 픽스처를 지우고 `schema_applied` 를 받아 `run_mysql(schema_applied["name"], ...)` 로 호출한다.

- [ ] **Step 2: 실패하는 통합 테스트** — `tests/test_store_mysql.py`

```python
"""MySQL 저장소 — 일회용 컨테이너에서 중복 무시·체크포인트·UTC 왕복을 확인한다."""
from datetime import datetime, timezone

import pytest

from app.normalizer import NormalizedEvent
from app.store import MySQLStore
from tests._mysql import ROOT_PW

pytestmark = pytest.mark.integration


@pytest.fixture
def store(schema_applied):
    s = MySQLStore(host="127.0.0.1", port=schema_applied["port"], user="root", password=ROOT_PW, database="mini_xdr")
    yield s
    s.close()


def ev(ref, sec=0):
    return NormalizedEvent(ts=datetime(2026, 10, 26, 5, 0, sec, 123000, tzinfo=timezone.utc), layer="app",
                           source="board", event_type="web-scan", raw_ref=ref, src_ip="203.0.113.9")


def test_insert_ignores_duplicates_by_raw_ref(store):
    assert store.insert_events([ev("st-1"), ev("st-2")]) == 2
    assert store.insert_events([ev("st-2"), ev("st-3")]) == 1


def test_checkpoint_roundtrip_in_utc(store):
    assert store.get_checkpoint("graylog-test") is None
    t = datetime(2026, 10, 26, 5, 30, 0, 456000, tzinfo=timezone.utc)
    store.set_checkpoint("graylog-test", t, "last-id")
    assert store.get_checkpoint("graylog-test") == t
    later = datetime(2026, 10, 26, 5, 31, 0, tzinfo=timezone.utc)
    store.set_checkpoint("graylog-test", later)
    assert store.get_checkpoint("graylog-test") == later


def test_event_timestamp_stored_as_utc_with_millis(store):
    store.insert_events([ev("st-ts", 7)])
    assert store.fetch_event_ts("st-ts") == datetime(2026, 10, 26, 5, 0, 7, 123000, tzinfo=timezone.utc)
```

- [ ] **Step 3: 실행 → 실패 확인** — `python -m pytest -m integration -q` → `ModuleNotFoundError: app.store`

- [ ] **Step 4: 구현** — `app/store.py`

```python
"""MySQL 저장소 — events_norm 적재(중복 무시)와 수집 체크포인트. 시각은 모두 UTC."""
from __future__ import annotations

from datetime import datetime, timezone

import pymysql

from app.normalizer import NormalizedEvent

_INSERT = (
    "INSERT IGNORE INTO events_norm "
    "(ts, layer, source, src_ip, user_name, asset, event_type, rule_id, level, mitre, raw_ref) "
    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
)


def _naive_utc(ts: datetime) -> datetime:
    return ts.astimezone(timezone.utc).replace(tzinfo=None)


def _aware(ts: datetime | None) -> datetime | None:
    return ts.replace(tzinfo=timezone.utc) if ts else None


class MySQLStore:
    def __init__(self, *, host: str, port: int, user: str, password: str, database: str) -> None:
        self._conn = pymysql.connect(host=host, port=port, user=user, password=password, database=database,
                                     charset="utf8mb4", autocommit=True, init_command="SET time_zone = '+00:00'")

    def insert_events(self, events: list[NormalizedEvent]) -> int:
        rows = [(_naive_utc(e.ts), e.layer, e.source, e.src_ip, e.user_name, e.asset, e.event_type,
                 e.rule_id, e.level, e.mitre, e.raw_ref) for e in events]
        with self._conn.cursor() as cur:
            return cur.executemany(_INSERT, rows) or 0

    def get_checkpoint(self, source: str) -> datetime | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT last_ts FROM checkpoints WHERE source = %s", (source,))
            row = cur.fetchone()
        return _aware(row[0]) if row else None

    def set_checkpoint(self, source: str, ts: datetime, last_id: str | None = None) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO checkpoints (source, last_ts, last_id) VALUES (%s, %s, %s) "
                "ON DUPLICATE KEY UPDATE last_ts = VALUES(last_ts), last_id = VALUES(last_id)",
                (source, _naive_utc(ts), last_id),
            )

    def fetch_event_ts(self, raw_ref: str) -> datetime | None:
        with self._conn.cursor() as cur:
            cur.execute("SELECT ts FROM events_norm WHERE raw_ref = %s", (raw_ref,))
            row = cur.fetchone()
        return _aware(row[0]) if row else None

    def close(self) -> None:
        self._conn.close()
```

- [ ] **Step 5: 실행 → 통과** — 통합 6 passed(스키마 3·저장소 3)
- [ ] **Step 6: 커밋·푸시** — `feat(mini-xdr): P1 MySQL 저장소 — INSERT IGNORE·체크포인트 UTC, 통합 픽스처 공유`

---

### Task 5: 설정·워커 — `app/config.py`·`app/worker.py`

- [ ] **Step 1: 설정 테스트 추가** — `tests/test_config.py` 에 기본값 확인 추가

```python
def test_collect_defaults():
    s = make()
    assert s.graylog_query == "_exists_:wazuh_rule_id OR _exists_:rule"
    assert (s.collect_page_size, s.collect_backfill_min, s.collect_overlap_sec) == (500, 1440, 60)


def test_graylog_auth_available():
    assert make().graylog_auth_available is False
    assert make(graylog_token="t" * 40).graylog_auth_available is True
    assert make(graylog_user="u", graylog_password="p").graylog_auth_available is True
```

- [ ] **Step 2: `app/config.py` 에 필드 추가** — `graylog_user: str | None = None`, `graylog_password: SecretStr | None = None`, `graylog_query: str = "_exists_:wazuh_rule_id OR _exists_:rule"`, `collect_page_size: int = Field(500, ge=10, le=1000)`, `collect_backfill_min: int = Field(1440, ge=1)`, `collect_overlap_sec: int = Field(60, ge=0)`, `collect_max_pages: int = Field(50, ge=1)` 와 프로퍼티 `graylog_auth_available`. `.env.example` 에 같은 키 추가(동기화 테스트가 강제).

- [ ] **Step 3: 워커 테스트** — `tests/test_worker.py`

```python
"""워커 조립 — 가짜 의존성으로 한 주기를 돌려 요약을 확인한다."""
from datetime import datetime, timezone

from app.worker import run_cycle, summary_line
from tests.test_collector import CFG, FakeGraylog, FakeStore, msg

NOW = datetime(2026, 10, 26, 6, 0, 0, tzinfo=timezone.utc)


def test_run_cycle_returns_result_and_summary_has_counts():
    r = run_cycle(FakeGraylog([msg(1, NOW.replace(minute=58, hour=5))]), FakeStore(), CFG, NOW)
    line = summary_line(r)
    assert r.inserted == 1
    assert "적재 1" in line and "중복 0" in line
```

- [ ] **Step 4: 구현** — `app/worker.py`

```python
"""수집 워커 — python -m app.worker [--once]

설정(.env)으로 Graylog 클라이언트·MySQL 저장소를 조립해 poll_interval_sec 마다 한 주기씩 수집한다.
"""
from __future__ import annotations

import argparse
import time
from datetime import datetime, timedelta, timezone

from app.collector import CollectConfig, CollectResult, collect_once
from app.config import Settings


def run_cycle(client, store, cfg: CollectConfig, now: datetime | None = None) -> CollectResult:
    return collect_once(client, store, cfg, now or datetime.now(timezone.utc))


def summary_line(r: CollectResult) -> str:
    head = f"[수집] {r.window_from:%H:%M:%S}~{r.window_to:%H:%M:%S}Z 페이지 {r.pages} · 조회 {r.fetched} · "
    body = f"적재 {r.inserted} · 중복 {r.duplicates} · 건너뜀 {r.skipped}"
    return head + body + (f" · 오류 {r.error}" if r.error else "")


def build(settings: Settings):
    from app.graylog import GraylogClient
    from app.store import MySQLStore

    token = settings.graylog_token.get_secret_value() if settings.graylog_token else None
    password = settings.graylog_password.get_secret_value() if settings.graylog_password else None
    client = GraylogClient(settings.graylog_url, token=token, user=settings.graylog_user, password=password)
    store = MySQLStore(host=settings.mysql_host, port=settings.mysql_port, user=settings.mysql_user,
                       password=settings.mysql_password.get_secret_value() if settings.mysql_password else "",
                       database=settings.mysql_db)
    cfg = CollectConfig(query=settings.graylog_query, page_size=settings.collect_page_size,
                        overlap=timedelta(seconds=settings.collect_overlap_sec),
                        backfill=timedelta(minutes=settings.collect_backfill_min),
                        max_pages=settings.collect_max_pages)
    return client, store, cfg


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mini-xdr 수집 워커")
    parser.add_argument("--once", action="store_true", help="한 주기만 실행하고 종료")
    args = parser.parse_args(argv)
    settings = Settings()
    client, store, cfg = build(settings)
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
```

- [ ] **Step 5: 실행 → 통과** — 단위 전체 통과
- [ ] **Step 6: 커밋·푸시** — `feat(mini-xdr): P1 수집 설정·워커(python -m app.worker --once)`

---

### Task 6: 랩 적용과 라이브 실측

- [ ] **Step 1: 랩 MySQL 에 스키마·전용 계정** — 루트 비번은 컨테이너 환경변수로만 사용(값을 다루지 않음). `xdr` 계정 비밀번호는 무작위 생성해 `.env` 에만 기록.
- [ ] **Step 2: Graylog 인증** — API 토큰 발급을 시도하고, 안 되면 랩 기본 계정으로 `.env` 에 설정(값은 출력하지 않음).
- [ ] **Step 3: 최초 수집** — `python -m app.worker --once`(backfill 7일로 1회) → `events_norm` 출처·계층별 건수 확인.
- [ ] **Step 4: 실시간 확인** — 무해한 표식 신호(GELF `rule=xdr-p1-probe`, TEST-NET IP)를 보내 다음 주기에 적재되는지·지연 측정. 기존 SOAR 봇이 반응하지 않는 고유 rule 이름을 쓴다.
- [ ] **Step 5: 재실행 멱등** — 같은 창을 다시 수집해도 `적재 0 · 중복 N`.
- [ ] **Step 6: README·진행 상태 갱신 후 커밋·푸시**

## 구현 중 변경 (라이브 실측으로 바뀐 것)

1. **네트워크 신호 표** — 30일 백필에서 `snort-portscan`(출처 `snort-kali`)·`cf-waf`(출처 `cloudflare-edge`)가 board/app 으로 잘못 분류됨을 발견 → `NETWORK_SIGNALS`·`NETWORK_ORIGINS` 표로 일반화(snort·cloudflare 추가, asset 은 실제 출처). 커밋 `7d2311d`.
2. **따라잡기 중 overlap 생략** — 체크포인트가 10분(`CollectConfig.recent`)보다 오래됐으면 overlap 없이 체크포인트부터. 같은 30일 백필의 중복 재조회 11,846 → 647건(94.5% 감소). 커밋 `bbc6b9b`.
3. **체크포인트 업서트 문법** — `VALUES(col)`(MySQL 8.0.20 부터 폐지 예고) 대신 행 별칭 `AS new`. mysql:8.0·mysql:latest(26.7) 모두 통합 통과.
4. 수집 루프는 `while…else` 대신 루프 앞에서 최대 페이지를 검사하는 형태로 정리(동작 동일).

## 자체 점검 (계획 ↔ 설계 [186])

- ①collector → Task 2·3, ②normalizer → Task 1, ⑧store(이벤트·체크포인트) → Task 4, 워커 → Task 5, 라이브 → Task 6 ✅
- 이름 일관성: `NormalizedEvent` 필드 = `events_norm` 칼럼(`user_name` 포함), `collect_once(client, store, cfg, now, source=)`, `MySQLStore.insert_events/get_checkpoint/set_checkpoint`, `GraylogClient.search_absolute(query, frm, to, limit=, offset=, fields=)` ✅
