# 미니 XDR P2 — 상관(인시던트)·읽기 전용 콘솔·컨테이너화 구현 계획

> **에이전트 작업자용:** 필수 하위 스킬 — `superpowers:subagent-driven-development`(권장) 또는 `superpowers:executing-plans` 로 작업 단위 실행. 단계는 체크박스(`- [ ]`)로 추적.

**목표:** `events_norm` 에 쌓인 이벤트를 같은 엔티티·10분 창 기준으로 묶어 인시던트(`incidents`·`incident_events`)를 만들고, 지문(G3 준비)·규칙 하한을 계산한다. 읽기 전용 웹 콘솔(목록·상세 타임라인)로 보여 주고, 워커와 콘솔을 컨테이너로 올린다.

**설계:** [186] 3장 ③correlator·⑩console, 5-1 G3(지문)·4-4 방어 4(규칙 하한). 상관은 순수 함수(`correlate`)와 저장소 의존을 주입받는 실행기(`correlate_once`)로 나눠 DB 없이 단위 테스트한다. 콘솔은 게시판과 같은 Flask(학생에게 익숙) + waitress, DB 세션을 `transaction_read_only` 로 열어 코드 실수로도 쓰기가 불가능하게 한다.

**기술:** Flask 3.1 · waitress 3.0 · 기존 PyMySQL · Docker Compose(`python:3.13-slim`)

## 라이브 랩에서 확인한 사실 (2026-10-26)

| 항목 | 값 |
|---|---|
| 적재 이벤트 | 81,259건 — 출발지 IP 있음 72,404 · IP 없이 계정만 **0** · 둘 다 없음(자산만) 8,855 |
| 자산만 있는 이벤트 | board-host 7,687 · ha-board-container 361 · pfSense 427 · kali-snort 188 · SJTYPAPA 141 · wazuh-manager2 51 (호스트 점검·SCA 경보) |
| 10분 창 세션 추정 | **1,629개 인시던트**(IP 1,137 · 자산 492), 다계층 20개, 단건 340개. 이벤트 수 p50 3 · p90 15 · p99 345 · 최대 33,411(172.31.195.249 폭주) |
| 최장 인시던트 | 154분(192.168.120.1, 502건) — 폭주도 중간에 10분 이상 쉬어서 끝없는 인시던트는 없음 |
| 최고 level 분포 | 0(GELF) 993 · 5 157 · 7 57 · 8 18 · 9 267 · 10 75 · 12 47 · 13 15 |
| MySQL 계정 | `xdr`@`%`(mini_xdr.* SELECT/INSERT/UPDATE/DELETE) — 컨테이너에서 접속 가능 |
| 공개 포트 | mysql-server `0.0.0.0:3306`, gl-graylog `0.0.0.0:9000` — mysql-server 는 기본 `bridge`(이름 해석 불가), Graylog 는 `graylog_default` |
| 콘솔 포트 | 8099 비어 있음 |
| Graylog 이벤트 정의 | 전부 `rule:`·`wazuh_rule_id:` 로 거름 → 고유 rule 값의 표식 신호는 알림을 건드리지 않음 |

## 설계 결정

1. **엔티티 키 = 출발지 IP > 계정 > 자산**: `ip:203.0.113.7` · `user:alice` · `asset:board-host`. src_ip 없는 호스트 점검 경보는 에이전트 이름으로 묶인다. 같은 IP 와 계정을 하나로 잇는(서로 다른 키 병합) 상관은 심화 과제로 남긴다(실데이터에 "계정만" 이벤트가 0건).
2. **창 = 쉬는 틈 10분**(`CORRELATION_WINDOW_MIN`): 엔티티의 최근 인시던트 `[opened_at − W, last_event_at + W]` 안이면 붙이고, 아니면 새로 연다. 공격이 이어지면 길어지고 W 동안 조용하면 닫힌다(`status`).
3. **규칙 하한(rule_floor)** = 최고 Wazuh level 로: 12↑ P1 · 10↑ P2 · 7↑ P3 · 그 외 P4. `current_priority` 는 P2 에선 하한과 같고(AI 미판정), P4 에서 AI 판정이 들어와도 하한보다 낮아지지 않는다(`higher()`).
4. **지문(fingerprint)** = SHA-256(엔티티 유형·계층 집합·신호 집합·이상점수 구간). 시각·IP·계정·횟수는 넣지 않는다 → 같은 공격이 IP 만 바꿔 와도 같은 지문(P4 G3 캐시의 열쇠). 신호 = `계층/출처/(룰 번호 또는 rule)`.
5. **신호 집합은 저장하지 않고** 기존 인시던트를 이어 붙일 때 `incident_events ⋈ events_norm` 에서 다시 읽는다(스키마 변경 없음, 폭주 인시던트 33k 행도 수십 ms).
6. **진행 위치** = `checkpoints('correlator').last_id`(events_norm.id). 인시던트 저장·이벤트 연결·진행 위치를 **한 트랜잭션**으로 묶어, 중간에 죽어도 같은 이벤트가 두 번 세지지 않는다.
7. **타임라인** = 이어지는 같은 신호를 한 줄로 접는 연속 길이 부호화(`login-bruteforce ×12`). 콘솔과 P4 의 LLM 카드가 같은 함수를 쓴다(입력 다이어트).
8. **콘솔 보안**: 127.0.0.1 에만 바인딩 · 읽기 전용 DB 세션 · 템플릿 자동 이스케이프(로그 값은 공격자가 넣을 수 있는 문자열 — 저장형 XSS 방지) · CSP(`default-src 'none'`)·nosniff · 필터 값 화이트리스트 · `/healthz` 는 오류 내용을 숨김.
9. **컨테이너**: 기존 SOAR 컨테이너의 네트워크에 붙이지 않는다(10-12 대시보드 네트워크 증발 사고 교훈) → `host.docker.internal` 로 공개 포트(3306·9000)에 접속. 비밀값은 이미지에 넣지 않고 실행 때 `env_file: .env`. 비루트 사용자, `restart: "no"`(수업 때 명시적으로 켬).
10. **워커 주기 = 재연결 → 수집 → 상관**. 한 주기에서 예외가 나도 워커(컨테이너)는 죽지 않고 다음 주기에 다시 시도한다(`store.ping(reconnect=True)`).

---

## 파일 구조

| 파일 | 책임 |
|---|---|
| `app/fingerprint.py` | `signal_of()`·`fingerprint()` — 지문 계산 |
| `app/correlator.py` | `EventRow`·`IncidentState`·`entity_key()`·`rule_floor()`·`higher()`·`correlate()`(순수)·`correlate_once()`(실행기) |
| `app/timeline.py` | `TimelineItem`·`build_timeline()`·`offset_label()` |
| `app/store.py` (수정) | `ping`·`get_cursor`·`fetch_events_after`·`load_latest_incidents`·`save_correlation`(트랜잭션)·`close_stale`, 공용 `EVENT_COLUMNS`·`event_from_row` |
| `app/worker.py` (수정) | `cycle()` = 재연결→수집→상관, `correlate_summary()`, 주기 예외 복구 |
| `app/console/__init__.py` | `create_app(open_queries)` — 목록·상세·healthz, 보안 헤더 |
| `app/console/queries.py` | `connect_readonly()`·`ConsoleQueries`·`open_queries()` |
| `app/console/__main__.py` | `python -m app.console` — waitress 실행 |
| `app/console/templates/` | `base.html`·`list.html`·`detail.html` |
| `app/config.py`·`.env.example` (수정) | `CONSOLE_HOST`(127.0.0.1)·`CONSOLE_PORT`(8099) |
| `requirements.txt` (수정) | `flask>=3.1,<4`·`waitress>=3.0,<4` |
| `Dockerfile`·`.dockerignore`·`docker-compose.yml` | 워커·콘솔 공용 이미지와 실행 |
| 테스트 | `test_fingerprint`·`test_correlator`·`test_timeline`·`test_correlate_once`·`test_store_correlation_mysql`(통합)·`test_worker`(보강)·`test_console`·`test_console_mysql`(통합)·`test_container_files`·`test_config`(보강) |

---

### Task 1: 지문·규칙 하한·상관 순수 로직

**Files:** Create `app/fingerprint.py`, `app/correlator.py`, `tests/test_fingerprint.py`, `tests/test_correlator.py`

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_fingerprint.py
"""지문 — 같은 종류의 사건이면 같은 값, 시각·IP·횟수는 영향 없음."""
from app.fingerprint import fingerprint, signal_of


def test_signal_uses_rule_id_for_wazuh_and_rule_for_gelf():
    assert signal_of("host", "wazuh", "5710", "wazuh-alert") == "host/wazuh/5710"
    assert signal_of("app", "board", None, "login-bruteforce") == "app/board/login-bruteforce"


def test_order_and_duplicates_do_not_matter():
    a = fingerprint("ip", ["app", "network"], ["app/board/web-scan", "network/suricata/ids-alert"])
    b = fingerprint("ip", ["network", "app", "app"], ["network/suricata/ids-alert", "app/board/web-scan"])
    assert a == b and len(a) == 64


def test_changes_with_layers_signals_entity_type_and_anomaly_band():
    base = fingerprint("ip", ["app"], ["app/board/web-scan"])
    assert fingerprint("ip", ["app", "host"], ["app/board/web-scan"]) != base
    assert fingerprint("ip", ["app"], ["app/board/login-bruteforce"]) != base
    assert fingerprint("asset", ["app"], ["app/board/web-scan"]) != base
    assert fingerprint("ip", ["app"], ["app/board/web-scan"], anomaly_band="high") != base
```

```python
# tests/test_correlator.py
"""상관 순수 로직 — 엔티티 키·창·규칙 하한·지문·늦게 온 이벤트."""
from datetime import datetime, timedelta, timezone

from app.correlator import EventRow, IncidentState, correlate, entity_key, higher, rule_floor

T0 = datetime(2026, 10, 26, 5, 0, 0, tzinfo=timezone.utc)
W = timedelta(minutes=10)
NOW = T0 + timedelta(hours=1)


def ev(i, minutes, *, layer="app", source="board", event_type="web-scan", ip="203.0.113.9", user=None,
       asset=None, rule_id=None, level=None):
    return EventRow(id=i, ts=T0 + timedelta(minutes=minutes), layer=layer, source=source, event_type=event_type,
                    src_ip=ip, user_name=user, asset=asset, rule_id=rule_id, level=level)


def test_entity_key_prefers_ip_then_user_then_asset():
    assert entity_key(ev(1, 0)) == "ip:203.0.113.9"
    assert entity_key(ev(1, 0, ip=None, user="zz_alice")) == "user:zz_alice"
    assert entity_key(ev(1, 0, ip=None, asset="board-host")) == "asset:board-host"
    assert entity_key(ev(1, 0, ip=None, source="wazuh")) == "asset:wazuh"


def test_rule_floor_and_higher():
    assert [rule_floor(x) for x in (None, 5, 7, 10, 12, 15)] == ["P4", "P4", "P3", "P2", "P1", "P1"]
    assert higher(None, "P3") == "P3" and higher("P4", "P2") == "P2" and higher("P1", "P3") == "P1"


def test_same_entity_within_window_joins_across_layers():
    batch = correlate([ev(1, 0), ev(2, 3, layer="network", source="suricata", event_type="ids-alert")], {}, W, NOW)
    assert batch.created == 1 and len(batch.touched) == 1
    inc = batch.touched[0]
    assert inc.layers == {"app", "network"} and inc.event_count == 2
    assert inc.signals == {"app/board/web-scan", "network/suricata/ids-alert"}
    assert [eid for _, eid in batch.links] == [1, 2]


def test_gap_longer_than_window_opens_new_incident():
    batch = correlate([ev(1, 0), ev(2, 9), ev(3, 20)], {}, W, NOW)  # 9분 뒤는 붙고, 그 뒤 11분 쉬면 새로
    assert batch.created == 2
    assert [i.event_count for i in batch.touched] == [2, 1]


def test_different_entities_are_separate():
    batch = correlate([ev(1, 0), ev(2, 1, ip="198.51.100.7"), ev(3, 2, ip=None, asset="board-host")], {}, W, NOW)
    assert sorted(i.entity_key for i in batch.touched) == ["asset:board-host", "ip:198.51.100.7", "ip:203.0.113.9"]


def test_attaches_to_existing_incident_and_keeps_its_id():
    old = IncidentState(entity_key="ip:203.0.113.9", id=41, opened_at=T0, last_event_at=T0 + timedelta(minutes=2),
                        layers={"app"}, signals={"app/board/web-scan"}, event_count=5, current_priority="P4")
    latest = {"ip:203.0.113.9": old}
    batch = correlate([ev(9, 8, layer="host", source="wazuh", event_type="wazuh-alert", rule_id="5710", level=10)],
                      latest, W, NOW)
    assert batch.created == 0 and batch.touched == [old] and old.id == 41
    assert old.event_count == 6 and old.layers == {"app", "host"} and old.max_level == 10
    assert old.rule_floor == "P2" and old.current_priority == "P2"


def test_status_closed_when_quiet_longer_than_window():
    batch = correlate([ev(1, 0), ev(2, 55)], {}, W, NOW)  # NOW = T0+60분
    assert [i.status for i in batch.touched] == ["closed", "open"]


def test_priority_never_drops_below_floor_but_keeps_higher_value():
    inc = IncidentState(entity_key="ip:203.0.113.9", opened_at=T0, last_event_at=T0, current_priority="P1")
    correlate([ev(1, 1, level=3)], {"ip:203.0.113.9": inc}, W, NOW)
    assert inc.current_priority == "P1"  # AI 가 올려 둔 P1 은 하한(P4) 때문에 내려가지 않는다


def test_fingerprint_ignores_ip_and_counts():
    a = correlate([ev(1, 0), ev(2, 1)], {}, W, NOW).touched[0]
    b = correlate([ev(3, 0, ip="198.51.100.7")], {}, W, NOW).touched[0]
    assert a.fingerprint == b.fingerprint


def test_late_past_event_does_not_replace_latest_incident():
    recent = IncidentState(entity_key="ip:203.0.113.9", id=7, opened_at=T0 + timedelta(minutes=40),
                           last_event_at=T0 + timedelta(minutes=45), layers={"app"}, event_count=3)
    latest = {"ip:203.0.113.9": recent}
    batch = correlate([ev(1, 0), ev(2, 46)], latest, W, NOW)  # 0분은 늦게 온 과거 → 새 인시던트, 46분은 최근 것에
    assert batch.created == 1 and latest["ip:203.0.113.9"] is recent and recent.event_count == 4
```

- [ ] **Step 2: 실행 — 실패 확인** · `python -m pytest tests/test_fingerprint.py tests/test_correlator.py -q` → `ModuleNotFoundError`

- [ ] **Step 3: 구현** (`app/fingerprint.py`)

```python
"""인시던트 지문(호출 깔때기 G3) — '같은 종류의 사건'이면 같은 값.

넣는 것: 엔티티 유형·계층 집합·신호 집합·이상점수 구간.
넣지 않는 것: 시각·IP·계정·횟수 — 같은 공격이 IP 만 바꿔 와도 같은 지문이어야 판정을 재사용할 수 있다.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable


def signal_of(layer: str, source: str, rule_id: str | None, event_type: str) -> str:
    """신호 이름 — Wazuh 는 룰 번호, 그 밖에는 rule(event_type)."""
    return f"{layer}/{source}/{rule_id or event_type}"


def fingerprint(entity_type: str, layers: Iterable[str], signals: Iterable[str], anomaly_band: str = "none") -> str:
    canon = json.dumps({"entity": entity_type, "layers": sorted(set(layers)), "signals": sorted(set(signals)),
                        "anomaly": anomaly_band}, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()
```

`app/correlator.py` 의 순수 부분(EventRow·entity_key·rule_floor·higher·IncidentState·CorrelationBatch·correlate) — 전체 코드는 저장소 파일 참고(Task 3 의 실행기와 한 파일).

- [ ] **Step 4: 실행 — 통과 확인** · 같은 명령 → 전부 PASS
- [ ] **Step 5: 커밋** · `feat(mini-xdr): 상관 순수 로직 — 엔티티 키·10분 창·규칙 하한·지문`

### Task 2: 타임라인 접기

**Files:** Create `app/timeline.py`, `tests/test_timeline.py`

- [ ] **Step 1: 실패하는 테스트**

```python
# tests/test_timeline.py
"""타임라인 — 이어지는 같은 신호는 한 줄, 끊기면 새 줄, 상한을 넘으면 잘림 표시."""
from datetime import datetime, timedelta, timezone

from app.correlator import EventRow
from app.timeline import build_timeline, offset_label

T0 = datetime(2026, 10, 26, 5, 0, 0, tzinfo=timezone.utc)


def ev(i, sec, event_type="login-bruteforce", *, layer="app", source="board", user=None, rule_id=None, level=None,
       mitre=None):
    return EventRow(id=i, ts=T0 + timedelta(seconds=sec), layer=layer, source=source, event_type=event_type,
                    user_name=user, rule_id=rule_id, level=level, mitre=mitre)


def test_runs_of_same_signal_collapse_into_one_item():
    items, cut = build_timeline([ev(1, 0, user="zz_a"), ev(2, 5, user="zz_b"), ev(3, 9, user="zz_a"),
                                 ev(4, 40, "wazuh-alert", layer="host", source="wazuh", rule_id="100211",
                                    level=10, mitre="T1110"),
                                 ev(5, 95, "login-success", user="zz_a")])
    assert not cut
    assert [(i.signal, i.count) for i in items] == [("login-bruteforce", 3), ("100211", 1), ("login-success", 1)]
    assert items[0].users == ["zz_a", "zz_b"] and items[0].last == T0 + timedelta(seconds=9)
    assert items[1].max_level == 10 and items[1].mitre == "T1110"


def test_interrupted_run_starts_a_new_item():
    items, _ = build_timeline([ev(1, 0), ev(2, 1, "web-scan"), ev(3, 2)])
    assert [i.signal for i in items] == ["login-bruteforce", "web-scan", "login-bruteforce"]


def test_max_items_truncates():
    items, cut = build_timeline([ev(i, i, "a" if i % 2 else "b") for i in range(10)], max_items=4)
    assert cut and len(items) == 4


def test_users_are_capped_at_three():
    items, _ = build_timeline([ev(i, i, user=f"zz_{i}") for i in range(6)])
    assert items[0].users == ["zz_0", "zz_1", "zz_2"]


def test_offset_label():
    assert [offset_label(s) for s in (0, 40, 185, 7800)] == ["+0s", "+40s", "+3m05s", "+2h10m"]
```

- [ ] **Step 2~4**: RED(ModuleNotFoundError) → `app/timeline.py` 구현 → GREEN
- [ ] **Step 5: 커밋** · `feat(mini-xdr): 타임라인 접기 — 콘솔·LLM 카드 공용`

### Task 3: 상관 실행기 `correlate_once` (가짜 저장소)

**Files:** Modify `app/correlator.py`, Create `tests/test_correlate_once.py`

- [ ] **Step 1: 실패하는 테스트** — `FakeCorrStore`(메모리) 로 ① 여러 묶음 처리·진행 위치 이동 ② 새 이벤트 없으면 처리 0 ③ 조용한 인시던트 닫힘 수 집계 ④ 기존 인시던트에 이어 붙으면 `updated` 증가.

```python
# tests/test_correlate_once.py
"""상관 실행기 — 진행 위치·묶음·닫힘 집계를 메모리 저장소로 확인한다."""
from datetime import timedelta

from app.correlator import CURSOR_SOURCE, correlate_once, entity_key
from tests.test_correlator import NOW, T0, W, ev


class FakeCorrStore:
    def __init__(self, events):
        self.events = list(events)
        self.cursor = 0
        self.incidents = []          # 저장된 IncidentState
        self.links = []
        self.saved_batches = 0
        self.closed_before = None

    def get_cursor(self, source):
        assert source == CURSOR_SOURCE
        return self.cursor

    def fetch_events_after(self, last_id, limit):
        return [e for e in self.events if e.id > last_id][:limit]

    def load_latest_incidents(self, keys):
        latest = {}
        for inc in self.incidents:
            if inc.entity_key in keys and (inc.entity_key not in latest
                                           or inc.last_event_at > latest[inc.entity_key].last_event_at):
                latest[inc.entity_key] = inc
        return latest

    def save_correlation(self, batch, source, last):
        for inc in batch.touched:
            if inc.id is None:
                inc.id = len(self.incidents) + 1
                self.incidents.append(inc)
        self.links += [(inc.id, eid) for inc, eid in batch.links]
        self.cursor = last.id
        self.saved_batches += 1

    def close_stale(self, before):
        self.closed_before = before
        n = 0
        for inc in self.incidents:
            if inc.status == "open" and inc.last_event_at < before:
                inc.status, n = "closed", n + 1
        return n


def test_processes_in_batches_and_moves_cursor():
    store = FakeCorrStore([ev(i, i) for i in range(1, 8)])
    r = correlate_once(store, W, NOW, batch_size=3)
    assert (r.processed, r.batches, store.cursor) == (7, 3, 7)
    assert r.created == 1 and r.updated == 2  # 첫 묶음에서 열고, 다음 두 묶음은 이어 붙임
    assert len(store.links) == 7


def test_nothing_new_processes_nothing():
    store = FakeCorrStore([ev(1, 0)])
    correlate_once(store, W, NOW)
    r = correlate_once(store, W, NOW)
    assert (r.processed, r.batches, r.created) == (0, 0, 0)


def test_closes_quiet_incidents_with_window_cutoff():
    store = FakeCorrStore([ev(1, 0)])
    r = correlate_once(store, W, T0 + timedelta(minutes=5))
    assert store.incidents[0].status == "open" and r.closed == 0
    r = correlate_once(store, W, T0 + timedelta(minutes=30))
    assert r.closed == 1 and store.closed_before == T0 + timedelta(minutes=20)


def test_max_batches_limits_one_cycle():
    store = FakeCorrStore([ev(i, i) for i in range(1, 11)])
    r = correlate_once(store, W, NOW, batch_size=2, max_batches=2)
    assert r.processed == 4 and store.cursor == 4
    assert entity_key(store.events[0]) == "ip:203.0.113.9"
```

- [ ] **Step 2~4**: RED(ImportError: correlate_once) → 구현 → GREEN
- [ ] **Step 5: 커밋** · `feat(mini-xdr): 상관 실행기 — 진행 위치·묶음 처리·닫힘`

### Task 4: MySQL 저장소의 상관 메서드 (통합)

**Files:** Modify `app/store.py`, `tests/conftest.py`(DB 이름을 바꿔 스키마를 적용하는 `make_db` 픽스처), Create `tests/test_store_correlation_mysql.py`

- [ ] **Step 1: 실패하는 통합 테스트** — 독립 DB(`mini_xdr_corr`)에 이벤트를 넣고 `correlate_once(MySQLStore)` 를 돌려
  ① 인시던트 4개(IP A 의 app+network 1개·30분 뒤 새 1개, IP B 1개, `asset:board-host` 1개)·연결 5행·진행 위치 = 마지막 id
  ② level 12 이벤트가 든 인시던트의 하한 P1
  ③ 두 번째 실행에서 기존 인시던트에 이어 붙이면 DB 에서 다시 읽은 신호로 지문이 유지(재계산값과 같음)
  ④ `close_stale` 이 열린 인시던트를 닫음
  ⑤ 진행 위치 저장 중 오류를 일부러 내면 **트랜잭션 전체가 롤백**(인시던트 0개·진행 위치 그대로)
- [ ] **Step 2~4**: RED(AttributeError) → 구현 → GREEN(`python -m pytest -m integration -q`)
- [ ] **Step 5: 커밋** · `feat(mini-xdr): MySQL 상관 저장 — 한 트랜잭션(인시던트·연결·진행 위치)`

### Task 5: 워커 — 재연결 → 수집 → 상관, 주기 예외 복구

**Files:** Modify `app/worker.py`, `tests/test_worker.py`

- [ ] **Step 1: 실패하는 테스트** — `cycle()` 이 [수집]·[상관] 두 줄을 내고, `store.ping()` 이 예외를 내면 `[오류]` 줄과 실패 표시를 돌려주되 예외를 밖으로 던지지 않음. `correlate_summary()` 문구.
- [ ] **Step 2~4**: RED → 구현 → GREEN
- [ ] **Step 5: 커밋** · `feat(mini-xdr): 워커 주기에 상관 단계 추가·DB 끊김에도 계속 동작`

### Task 6: 읽기 전용 콘솔

**Files:** Create `app/console/{__init__,queries,__main__}.py`, `app/console/templates/{base,list,detail}.html`, `tests/test_console.py`, `tests/test_console_mysql.py`; Modify `app/config.py`, `.env.example`, `requirements.txt`, `tests/test_config.py`

- [ ] **Step 1: 실패하는 테스트**
  - `test_console.py`(가짜 조회 객체): 목록에 우선순위·엔티티·계층 배지 / 필터 화이트리스트(`?status=evil&priority=P9&page=-3` → all·''·1) / 상세에 접힌 타임라인(`×3`·`+0s`) / 없는 ID 404 / **XSS — 계정명 `<script>` 가 `&lt;script&gt;` 로만 출력** / CSP·nosniff 헤더 / `/healthz` 200·DB 실패 시 503(오류 내용 비노출)
  - `test_console_mysql.py`(통합): 실제 스키마에서 목록·상세 조회, **읽기 전용 세션에서 `DELETE` 가 오류 1792 로 거부**
  - `test_config.py`: `console_host`=127.0.0.1·`console_port`=8099 기본값(`.env.example` 동기화 테스트도 통과)
- [ ] **Step 2~4**: RED → 구현 → GREEN
- [ ] **Step 5: 커밋** · `feat(mini-xdr): 읽기 전용 콘솔 — 인시던트 목록·상세 타임라인`

### Task 7: 컨테이너화

**Files:** Create `Dockerfile`, `.dockerignore`, `docker-compose.yml`, `tests/test_container_files.py`

- [ ] **Step 1: 실패하는 정적 테스트** — `.dockerignore` 가 `.env`·`.env.*`·`.venv` 제외 / Dockerfile 이 비루트(`USER xdr`)·`COPY . .` 없음 / compose 가 콘솔을 `127.0.0.1:8099` 에만 공개·기존 스택 네트워크(`external`, `graylog_default`) 미사용·비밀값을 compose 에 직접 쓰지 않음(`env_file: .env`)
- [ ] **Step 2~4**: RED → 파일 작성 → GREEN, `docker compose build` 성공
- [ ] **Step 5: 커밋** · `feat(mini-xdr): 워커·콘솔 컨테이너화 — 기존 네트워크 미변경·비밀값은 실행 때 주입`

### Task 8: 라이브 적용·실측 → README

- [ ] 호스트에서 `python -m app.worker --once` → 81k 이벤트 상관 시간·인시던트 수(추정 1,629 와 비교)·다계층·하한 분포
- [ ] 표식 신호 2건(같은 TEST-NET IP, `rule=xdr-p2-probe-app` 앱 + `source=suricata`·`rule=xdr-p2-probe-net` 네트워크) → 다계층 인시던트 1개로 묶이는지, 감지→콘솔 표시 시간
- [ ] `docker compose up -d --build` → 워커 로그 `[수집]`·`[상관]`, `curl http://127.0.0.1:8099/healthz`, 목록·상세 화면 캡쳐
- [ ] README 진행 상태·폴더 구조·실행법·실측 표 → 커밋 `docs(mini-xdr): P2 완료 — …`

## 구현 중 변경·발견 (2026-10-26)

| 항목 | 내용 |
|---|---|
| 재연결 방식 | PyMySQL 1.2 에서 `ping(reconnect=True)` 가 폐지 예고 경고 → `ping(reconnect=False)` 로 끊김을 확인하고 **새 연결을 만드는** 방식으로 변경, 재연결 통합 테스트 추가 |
| 통합 테스트 격리 | 테스트마다 스키마를 새 DB 이름(`mxt_…`)으로 적용하는 `fresh_db` 픽스처 — 진행 위치·인시던트가 테스트끼리 섞이지 않음. mysql:8.0·latest(26.7) 모두 통과 |
| 원자성 검증 | 진행 위치 저장 함수에 일부러 예외를 넣어 인시던트·연결·진행 위치가 **모두** 롤백되는지 확인 |
| SQL 예약어 | 신호 요약 별칭 `signal` 은 MySQL 예약어 → `sig` |
| 실데이터 결과 | 81,260건 → 1,630개(추정 1,629 + 새 이벤트 1건과 일치), **고유 지문 164종** → P4 의 G3 캐시만으로 LLM 판정 상한이 164회 |
| 타임라인 지그재그 | 같은 404 사건을 게시판 GELF(web-scan)와 Wazuh(100230)가 함께 보고하면 두 신호가 번갈아 나와 접기가 끊긴다(#699: 3,014건 → 532줄, 신호 요약은 5행). **P4 LLM 카드는 신호 요약 + 타임라인 앞부분**으로 보낸다 |
| 실시간 경로 | 컨테이너 워커(30초 주기)로 같은 IP 의 앱·네트워크 표식 신호를 다계층 인시던트 1개로 묶어 콘솔 표시까지 두 번째 신호 후 28초 |

## 자체 점검

- 설계 [186] ③(같은 IP·계정·10분 창·계층 묶음) → Task 1·3·4 / ⑩ 콘솔 목록·상세 → Task 6 / P2 로드맵 "인시던트 화면" → Task 6·8 / 컨테이너화([188] §11 예고) → Task 7.
- 지문의 이상점수 구간은 P3 전까지 `"none"` 고정(인자 기본값) — P3 에서 실제 구간을 넣는다.
- `material_state`(G4 디바운스)·`last_triaged_at` 은 P4 에서 채운다(P2 는 NULL 유지).
