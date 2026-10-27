# _13_mini-xdr — SOAR 랩 위의 AI 분석 계층 (사용 설명서)

> ⚠️ **개념 학습·대체 실습**입니다. 실제 XDR 은 SKT 상용 플랫폼이 우선이며, 이 폴더는 그 개념을
> 오픈소스와 자체 코드로 체험하기 위한 강의·캡스톤용 코드입니다 *(SKT 사전 싱크 필요)*.

이미 동작하는 SOAR 랩(Flask 게시판·MySQL·Wazuh·Graylog·n8n·Zabbix) 위에 **분석 서비스 하나**를 덧붙입니다.

```text
 게시판(Flask) ─GELF─┐
 Wazuh(호스트 로그) ─syslog─┤→ Graylog ──(검색 API, 30초마다)──→ mini-xdr 워커 ──→ MySQL(mini_xdr DB)
 pfSense·IDS ───────┘     │                                   │ 수집 → 이상탐지 → 상관 → AI/규칙 판정
                          └→ 이벤트 정의 → n8n 봇(차단·잠금·알림)   └→ 콘솔(웹 화면, http://127.0.0.1:8099)
 Zabbix 는 위 서버들이 살아 있는지(가용성)를 따로 감시
```

- **하는 일**: 여러 계층의 경보를 **한 사건(인시던트)으로 묶고** → 평소와 다른 행동을 **점수화**하고 →
  AI(Claude·Gemini)나 규칙이 **우선순위·근거**를 판정해 화면에 보여 줍니다.
- **하지 않는 일**: 차단·잠금 같은 실제 대응은 기존 n8n 봇이 맡습니다. AI 에는 실행 권한이 없습니다.
- AI 키가 없어도 **규칙 판정 모드**로 끝까지 동작합니다(키 없는 학생도 수업 참여 가능).

설계·구축 기록(교안 저장소 `_local/`): [186] 기획서 · [187]~[192] 단계별 따라하기 · [193] 연동 점검·S6 끝-끝·AI 설정 화면.

---

## 목차

1. [준비물](#1-준비물)
2. [설치](#2-설치)
3. [.env 설정 항목](#3-env-설정-항목)
4. [DB 준비(처음 한 번)](#4-db-준비처음-한-번)
5. [실행 — 컨테이너(권장) / PC 에서 직접](#5-실행)
6. [화면(콘솔) 사용법](#6-화면콘솔-사용법)
7. [AI 교체·키 입력 (/settings)](#7-ai-교체키-입력-settings)
8. [랩 연동 점검 — `python -m app.lab_check`](#8-랩-연동-점검)
9. [S6 끝-끝 확인 — `python -m app.lab_s6`](#9-s6-끝-끝-확인)
10. [동작 원리 요약](#10-동작-원리-요약)
11. [명령어 모음](#11-명령어-모음)
12. [문제 해결](#12-문제-해결)
13. [보안 수칙(공개 저장소)](#13-보안-수칙공개-저장소)
14. [진행 상태·폴더 구조](#14-진행-상태폴더-구조)

---

## 1. 준비물

| 구성요소 | 주소(이 PC 기준) | 이 프로그램에서의 역할 |
|---|---|---|
| Flask 게시판 `_7_board_test` | http://127.0.0.1:5000 | 로그인 실패·관리자 API 인증 실패 등 **신호**를 GELF 로 Graylog 에 보냄 |
| MySQL 컨테이너 `mysql-server` | 127.0.0.1:3306 | 게시판 DB(`my_new_board_db`) + mini-xdr 전용 DB(`mini_xdr`) |
| Wazuh `wazuh-manager2` | (컨테이너) | 호스트 로그 분석 → 경보를 Graylog 로 전달(syslog_output) |
| Graylog | http://127.0.0.1:9000 | 모든 로그 모음·검색. mini-xdr 는 여기서 **읽기만** 함 |
| n8n | http://127.0.0.1:5678 | Graylog 이벤트를 받아 차단·잠금·알림 실행(112 IP 차단봇 등) |
| Zabbix | http://127.0.0.1:8081 | 서버·서비스 가용성 감시(보안 이벤트와 별개) |
| Python 3.13 · Docker Desktop | — | mini-xdr 실행 |

> 운영 서버(`sylovestp.com` 등)에는 올리지 않습니다. 랩·가상 데이터만 씁니다.

## 2. 설치

PowerShell 기준입니다.

```powershell
cd E:\0-Aleph-Python-Test\Python-Lab-ALeph-T\_13_mini-xdr
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
Copy-Item .env.example .env        # 이제 .env 의 값을 채운다(3장)
python -m pytest                   # 단위 테스트 — 도커 없이 1분 안에 끝남
```

> Git Bash 에서는 한글 출력이 깨질 수 있습니다. `PYTHONIOENCODING=utf-8 python -m …` 처럼 실행하거나 PowerShell 을 쓰세요.

## 3. .env 설정 항목

`.env` 는 **이 PC 에만** 두는 파일입니다(커밋 금지). `<YOUR_…>` 자리표시자를 그대로 두면 "값 없음"으로 취급합니다.

| 묶음 | 항목 | 설명 |
|---|---|---|
| 저장소 | `MYSQL_HOST`·`MYSQL_PORT`·`MYSQL_USER`·`MYSQL_PASSWORD`·`MYSQL_DB` | mini-xdr 전용 계정 `xdr` 과 DB `mini_xdr`(4장) |
| 수집 | `GRAYLOG_URL`·`GRAYLOG_TOKEN` | Graylog API 토큰(권장). 없으면 `GRAYLOG_USER`·`GRAYLOG_PASSWORD` |
| AI | `LLM_PROVIDER`(claude·gemini·none)·`ANTHROPIC_API_KEY`·`GEMINI_API_KEY`·모델 | **화면(7장)에서 넣는 것을 권장.** 화면 저장값이 .env 보다 우선 |
| AI 키 암호화 | `SETTINGS_SECRET_KEY` | 화면에서 저장하는 키를 DB 에 암호문으로 넣을 열쇠(7장 ①) |
| 깔때기·이상탐지 | `MAX_DAILY_LLM_CALLS`·`TRIAGE_*`·`BASELINE_*`·`ANOMALY_Z` 등 | 기본값 그대로 써도 됨(10장) |
| 랩 점검 | `BOARD_URL`·`BOARD_API_KEY`·`N8N_URL`·`ZABBIX_URL`·`ZABBIX_USER`·`ZABBIX_PASSWORD` | 8·9장 도구용. `BOARD_API_KEY` = 게시판 `.env` 의 `SECURITY_API_KEY` 와 같은 값 |

## 4. DB 준비(처음 한 번)

게시판 DB 는 건드리지 않고, 같은 MySQL 컨테이너에 전용 DB 를 만듭니다.

```powershell
Get-Content -Raw sql\001_schema.sql | docker exec -i mysql-server mysql -uroot -p<루트비번>
docker exec -i mysql-server mysql -uroot -p<루트비번> -e "SHOW TABLES FROM mini_xdr;"   # 11개
```

전용 최소 권한 계정(비밀번호는 직접 정해 `.env` 의 `MYSQL_PASSWORD` 에만 적기):

```sql
CREATE USER IF NOT EXISTS 'xdr'@'%' IDENTIFIED BY '<비밀번호>';
GRANT SELECT, INSERT, UPDATE, DELETE ON mini_xdr.* TO 'xdr'@'%';
```

스키마 파일은 여러 번 적용해도 안전합니다(`CREATE … IF NOT EXISTS`).

## 5. 실행

### 방법 A — 컨테이너(권장)

```powershell
docker compose up -d --build     # 워커 + 콘솔(127.0.0.1:8099)
docker compose ps                # 둘 다 Up 인지
docker compose logs -f worker    # 30초마다 [수집]·[이상]·[상관]·[판정] 한 줄씩
docker compose down              # 끄기(restart: "no" — 수업 때 직접 켬)
```

코드를 고친 뒤에는 `docker compose up -d --build` 로 **다시 빌드**해야 화면·워커에 반영됩니다.

### 방법 B — PC 에서 직접

```powershell
python -m app.worker --once      # 한 주기만(처음이면 COLLECT_BACKFILL_MIN 만큼 과거부터)
python -m app.worker             # 상시 실행 — Ctrl+C 로 종료
python -m app.console            # http://127.0.0.1:8099
```

> ⚠️ PC 워커와 컨테이너 워커를 **동시에 돌리지 마세요**(같은 진행 위치를 두고 경쟁). PC 워커를 쓸 땐 `docker compose stop worker` 먼저.

워커 로그 읽는 법:

```text
[수집] 10-27 01:05:11~01:06:41Z 페이지 1 · 조회 0 · 적재 0 · 중복 0 · 건너뜀 0   ← Graylog 에서 가져온 양
[이상] 채점 버킷 4 · 이상 1 · 새 behavior 0 · 기준선 개인 6 / 집단 9                ← 평소와 다른 행동
[상관] 처리 0 · 새 인시던트 0 · 갱신 0 · 닫힘 0                                    ← 사건 묶기
[판정] 대상 6 · 건너뜀 6 · 관문 없음 · LLM 요청 0 · 토큰 입력 0/출력 0/캐시 0         ← AI/규칙 판정
```

## 6. 화면(콘솔) 사용법

http://127.0.0.1:8099 — 상단 메뉴: **인시던트 · 행위 이상 · AI 사용량 · AI 설정**.
메뉴 오른쪽 끝 배지가 **지금 쓰는 AI** 입니다(키 값은 표시하지 않음). 누르면 AI 설정으로 갑니다.

| 배지 | 뜻 |
|---|---|
| `AI: gemini · gemini-3.5-flash-lite` (초록) | AI 판정 중 |
| `AI 꺼짐 — 규칙 판정(gemini API 키 없음) · 설정` (주황) | 키·모델이 없어 규칙으로만 판정 — 설정에서 키를 넣으면 다음 주기부터 AI |

| 화면 | 보는 것 |
|---|---|
| 인시던트(`/`) | 우선순위순 사건 목록. 엔티티(IP·계정·자산)·계층·이벤트 수·규칙 하한·현재 우선순위 |
| 인시던트 상세(`/incidents/<번호>`) | 신호 요약표 · 접은 타임라인 · **최근 판정**(출처 llm/cache/rule · 관문 · 근거 · 권고) |
| 행위 이상(`/anomalies`) | 기준선 요약(개인·집단) · 최근 이상(특징·z 점수) |
| AI 사용량(`/usage`) | LLM 호출률 · 지문 캐시 적중률 · 프롬프트 캐시 비율 · 토큰 · 비용 추정 |
| AI 설정(`/settings`) | 7장 |

사건 조회 화면은 DB 를 **읽기 전용**으로 엽니다(DELETE 시도 → 오류 1792). AI 설정만 쓰기 경로입니다.

## 7. AI 교체·키 입력 (/settings)

### ① 처음 한 번 — 암호화 열쇠 만들기

```powershell
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

출력값을 `.env` 의 `SETTINGS_SECRET_KEY=` 뒤에 붙여 넣고 콘솔을 다시 시작합니다(`docker compose up -d`).
이 열쇠가 없으면 화면에 빨간 안내가 뜨고 키 입력란이 잠깁니다. **열쇠를 바꾸면 이미 저장한 키는 못 풉니다**(다시 입력).

### ② 화면 구성

| 구역 | 하는 일 |
|---|---|
| 맨 위 4칸 | 지금 쓰는 AI · 모델 · 키(앞4…뒤4) · 판정 방식(AI/규칙 + 이유) |
| **1. 사용할 AI 고르기** | Claude · Gemini · AI 끄기 카드. **[이것으로 교체]** = 저장된 키·모델은 그대로 두고 사용할 공급자만 바꿈 |
| **2. 공급자별 키·모델 입력** | Gemini 카드 · Claude 카드 — 각자 키 입력, 모델 ID, 연결 테스트, 저장 키 삭제 |
| **3. 웹 UI 설정 모두 지우기** | 화면 저장값을 전부 지우고 .env 로 되돌림 |

### ③ 키 넣기

1. 공급자 카드(예: Gemini)의 **API 키** 칸에 키를 붙여 넣습니다(입력은 `●●●`로 가려짐).
2. **모델 ID** 를 모르면 비워 두고 아래 **[연결 테스트]**(체크 안 함)를 먼저 눌러 목록을 받은 뒤, 칸을 눌러 목록에서 고릅니다.
3. 버튼 선택:
   - **[저장하고 이 AI 사용]** — 저장 + 이 공급자로 교체
   - **[저장만]** — 키·모델만 미리 넣어 두고, 지금 쓰는 공급자는 그대로(나중에 1번 구역에서 교체)
4. 키 칸을 비우고 저장하면 **기존 저장 키를 그대로 둔 채** 모델만 바뀝니다.

키 발급: Gemini = Google AI Studio(`aistudio.google.com/apikey`) · Claude = Anthropic 콘솔.

### ④ 연결 테스트

| 선택 | 하는 일 | 비용 |
|---|---|---|
| 체크 안 함 | 그 공급자의 **모델 목록**만 받아 옴 → 키가 맞는지 확인 | 토큰 0 |
| **샘플 호출까지** 체크 | 짧은 문장 1회 호출 → 응답·입력/출력 토큰·지연·비용 추정 표시, `llm_calls` 에 `connection_test` 로 기록 | 수십 토큰 |

사용 중이 아닌 공급자도 카드마다 따로 테스트할 수 있습니다(교체 전에 미리 확인).

### ⑤ 반영 시점·우선순위

- 워커는 **매 주기(30초) 설정을 다시 읽습니다** — 교체·저장 뒤 다시 시작할 필요 없음.
- 우선순위: **화면 저장값 > .env·환경변수**. 화면에 저장한 키를 못 풀면(열쇠 바뀜) .env 로 조용히 넘어가지 않고 문제를 표시합니다.
- 한 공급자의 저장 키만 지우려면 그 카드의 **[이 공급자의 저장 키 삭제]** — 그 공급자는 .env 키로 돌아갑니다.

| 보안 장치 | 내용 |
|---|---|
| 암호문 저장 | `app_settings` 에 `enc:v1:`(Fernet) 암호문만. 열쇠는 `.env` 에만 |
| 화면 비노출 | 저장 뒤 키는 다시 나오지 않음(앞4…뒤4), 오류 문구에서도 키를 되돌려 보이지 않음 |
| 쓰기 보호 | 모든 POST 에 CSRF 토큰(SameSite=Strict) · Origin 검사 · Host 가 localhost 계열만(DNS 리바인딩 방지) |

## 8. 랩 연동 점검

```powershell
python -m app.lab_check          # 사람용 표
python -m app.lab_check --json   # 기계용
```

PC(호스트)에서 실행합니다. 17개 항목을 데이터 흐름 순서로 보고, ❌ 가 하나라도 있으면 종료 코드 1 입니다(수업 전 점검용).
결과에는 상태·건수·버전만 나오고 키·토큰·비밀번호는 나오지 않습니다.

| 항목 | 확인 방법 | ⚠️/❌ 일 때 |
|---|---|---|
| 게시판 웹 응답 | `GET /` 200 | `_7_board_test` 에서 `python app.py` |
| 게시판 DB(MySQL) | 컨테이너 안에서 테이블·회원 수 | `docker ps` 로 mysql-server |
| MySQL(mini_xdr DB) | 24시간 이벤트·열린 인시던트·판정 수 | `.env` 의 MYSQL_* |
| 게시판 → Graylog 신호 | 24시간 `_exists_:rule` 건수 | 틀린 비밀번호로 한 번 로그인해 신호 만들기 |
| Wazuh 매니저 데몬 | analysisd·remoted·db·apid·csyslogd | `wazuh-control restart` |
| Wazuh 에이전트 | `agent_control -l` 의 Active | 게시판 PC 의 에이전트 서비스 |
| Wazuh → Graylog 경보 | 24시간 `_exists_:wazuh_rule_id` 건수 | `syslog_output`(5140/udp) |
| Graylog 서버·입력 | 버전 · 입력 RUNNING 수 | System → Inputs 에서 Start |
| Graylog 이벤트 정의 | 개수 · S6 존재 | [158] 2장 |
| n8n 서버 · 활성 워크플로 | healthz · 112 IP 차단봇 Active | n8n 화면에서 Active |
| n8n 최근 실행(24시간) | 실행 이력의 성공/실패, 실패한 봇 이름 | Executions 에서 원인(대개 키·웹훅 주소) |
| 게시판 대응 결과 | 차단 IP·열린 티켓 수(`BOARD_API_KEY` 필요) | — |
| Zabbix 가용성 감시 | 버전(인증 불필요) · 감시 호스트·현재 문제(계정 있으면) | Zabbix 웹 → Problems |
| mini-xdr 수집 · 콘솔 · AI 설정 | 마지막 수집 경과 · `/healthz` · 지금 쓰는 AI | `docker compose ps`·`logs worker` |

docker 가 필요한 항목은 docker 가 없으면 ❌ 가 아니라 **⏭️ 건너뜀**으로 표시합니다.

**라이브 실측(2026-10-27)**: ✅ 15 · ⚠️ 2 · ❌ 0 · ⏭️ 0 — 게시판·DB·Wazuh(데몬 5·에이전트 board-host)·Graylog(입력 5/5·이벤트 정의 27)·n8n(활성 11)·mini-xdr(수집 9초 전) 모두 연결.
⚠️ 2건은 실제 문제였습니다.

- `n8n 최근 실행 … 실패 7건(129 Wazuh 경보봇)` → 원인: 129 봇의 게시판 호출 노드 3개 X-API-Key 가 **이식용 자리표시자 그대로**라 게시판이 401. 그 401 이 다시 `admin-auth-fail` 신호(127.0.0.1)로 남아 있었음. S6 에 쓰는 112·111·114 봇은 키 일치.
- `Zabbix … 현재 문제 19건` → 가용성 감시 쪽 미해결 문제(보안 이벤트와 별개) — Zabbix 화면에서 확인.

## 9. S6 끝-끝 확인

```powershell
python -m app.lab_s6 --ip 203.0.113.176          # 끝나면 이벤트 창(약 4분)을 기다렸다가 차단 해제·티켓 종료(원복)
python -m app.lab_s6 --ip 203.0.113.177 --keep   # 결과를 화면에서 보려고 남겨 둘 때(나중에 직접 원복)
```

케이스 S6([158], 관리자 API 키 추측 폭주)을 실제로 일으켜 **신호 → 탐지 → 대응 → mini-xdr 판정**이 모두 이어지는지 15초마다 확인합니다.

| 단계 | 확인 내용 | 필수 |
|---|---|---|
| 0 | 게시판 `/api/security/events` 에 **무작위 틀린 키**로 15회(출발지 = `X-Forwarded-For` 문서용 IP) → 401 ×15 | — |
| 1 | Graylog 에 `admin-auth-fail` 15건(그 IP) | ✅ |
| 2 | Wazuh 100260(게시판 호스트 로그 경로) — 같은 사건을 호스트 쪽에서도 | 선택 |
| 3 | Graylog 이벤트 `S6 관리자 API 무단 호출 폭주` 발동(1분마다 평가) | ✅ |
| 4 | n8n `112 IP 차단봇` 실행 성공 | ✅ |
| 5 | 게시판 `blocked_ips` 에 그 IP | ✅ |
| 6 | 게시판 티켓(112 봇은 만들지 않음 — 114 봇 몫) | 선택 |
| 7 | mini-xdr 인시던트(`ip:그 IP`) | ✅ |
| 8 | mini-xdr 판정(AI 또는 규칙) | ✅ |

- **문서용 대역만** 받습니다(192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24). 실제 주소는 거부.
- 이미 차단된 IP 면 시작하지 않습니다. 같은 IP 를 다시 쓰려면 원복 후에.
- ⚠️ **112 봇이 Slack·Discord·Telegram 으로 알림을 보냅니다.**
- 시도에 쓴 틀린 키는 매번 무작위이고 출력하지 않습니다.

**라이브 실측(2026-10-27, 출발지 203.0.113.176)** — 필수 6단계 + 선택(Wazuh) 모두 통과, **신호에서 AI 판정까지 31초**:

```text
+ 0초  게시판 401 ×15
+15초  Graylog admin-auth-fail 15건 · Wazuh 100260 12건 + 100261 3건(srcip 일치) · S6 이벤트 발동 · 112 봇 성공 · 게시판 차단
+31초  mini-xdr 인시던트(app 계층, 이벤트 30건, 규칙 하한 P2 — 100261 level 10)
       Gemini(gemini-3.5-flash-lite) 판정: P2 · true_positive · 권고 block_ip · 확신 0.90 (입력 4,620 / 출력 113 토큰, 1.65초)
```

> ★ **원복 함정(실측)**: S6 이벤트 정의는 제목은 "5분"이지만 실제로는 **창 3분·1분마다 평가**라, 같은 15건으로 **1분 간격 3번 발동**합니다.
> 그래서 31초 시점에 한 차단 해제를 1분 뒤 재차단이 덮어썼습니다. 지금 도구는 **창 + 평가 주기 + 15초(255초)** 를 기다린 뒤 원복하고,
> 다시 차단되지 않았는지 확인합니다. 손으로 원복할 때도 3~4분 뒤에 하세요.

## 10. 동작 원리 요약

| 단계 | 핵심 | 자세히 |
|---|---|---|
| 수집 | Graylog 검색 API 를 체크포인트로 이어 받기(overlap 60초, 멱등) — 출처별 계층 분류(app·host·network·data) | [188] |
| 상관 | 엔티티 키(IP > 계정 > 자산) · 10분 창 · 규칙 하한(Wazuh level 12↑ P1 · 10↑ P2 · 7↑ P3) · 지문(SHA-256) | [189] |
| 행위 이상 | 1시간 버킷 특징(이벤트·신호 종류·로그인 실패·404 비율·로그인 시각) · robust z · 개인→집단 2단 기준선 → `behavior` 계층 | [191] |
| 판정(깔때기) | G4 디바운스 → G1 화이트리스트 → G2 규칙 결론 → G3 지문 캐시 → 키 확인 → G6 묶음 → G5 예산 → G7 승급 | [192] |
| 가드레일 | 최종 우선순위 = max(AI, 규칙 하한) · 스키마 오류 1회 재시도 → 규칙 · 거절은 정상 분기 · 권고는 실행하지 않음 | [192] |

AI 에 보내는 것은 **카드**(신호 요약 12행·타임라인 15줄·이상 z≥3)뿐이고, IP·계정·자산·이메일은 `ip_1`·`user_1` 같은 토큰으로 가립니다.
고정 앞부분(역할·기준·신호 사전)은 바이트가 바뀌지 않게 스냅샷 테스트로 지켜 프롬프트 캐시를 탑니다.

## 11. 명령어 모음

| 하고 싶은 것 | 명령 |
|---|---|
| 단위 테스트 / DB 통합 테스트 | `python -m pytest` / `python -m pytest -m integration`(도커 필요) |
| 커밋 전 비밀 스캔 | `python -m app.secret_scan` → "비밀 스캔 통과" |
| 워커 한 주기 / 상시 | `python -m app.worker --once` / `python -m app.worker` |
| 콘솔 | `python -m app.console` |
| 판정 분포 미리 보기(호출·저장 없음) | `python -m app.triage --dry-run --recent 100000` |
| 최근 N건 실제 판정 | `python -m app.triage --recent 20` |
| 이상탐지 사후 분석 | `python -m app.detector --report` |
| 랩 연동 점검 | `python -m app.lab_check` |
| S6 끝-끝 확인 | `python -m app.lab_s6 --ip 203.0.113.176` |
| 컨테이너 켜기·로그·끄기 | `docker compose up -d --build` · `docker compose logs -f worker` · `docker compose down` |

## 12. 문제 해결

| 증상 | 원인 | 해결 |
|---|---|---|
| 한글이 `???`·깨진 글자 | Git Bash 파이프 인코딩 | `PYTHONIOENCODING=utf-8` 를 앞에 붙이거나 PowerShell |
| 화면 상단에 `AI 꺼짐 — 규칙 판정(… 키 없음)` | 키·모델 없음 | 7장대로 키 입력. 규칙 판정도 정상 동작임 |
| AI 설정 저장 시 403 | 다른 출처에서 POST(Origin 불일치) | 주소창에 `http://127.0.0.1:8099` 로 직접 열기 |
| AI 설정 저장 시 400 "보안 토큰" | 화면을 오래 열어 두었거나 콘솔 재시작 | 새로 고침 뒤 다시 |
| "SETTINGS_SECRET_KEY 가 없어…" | 열쇠 미설정 | 7장 ① |
| "웹 UI 에 저장된 키를 풀 열쇠가 없음" | 열쇠를 바꿨거나 지움 | 키를 다시 입력(또는 원래 열쇠 복구) |
| 콘솔·워커에 코드 변경이 안 보임 | 예전 이미지로 실행 중 | `docker compose up -d --build` |
| 인시던트가 안 생김 | 워커 멈춤 · 두 워커 경쟁 · Graylog 토큰 만료 | `docker compose logs worker` · 8장 점검 |
| 8장 점검에 `n8n 최근 실행 … 실패 N건(129 Wazuh 경보봇)` | 129 봇을 이식용 JSON 으로 가져온 뒤 **X-API-Key 자리표시자를 안 바꿈** → 게시판이 401 | n8n 에서 129 봇의 게시판 호출 노드 3개(IP 차단·보안 이벤트 기록·인시던트 생성) 헤더를 게시판 키로 |
| S6 에서 3단계(이벤트)가 늦음 | 이벤트 정의가 1분마다 평가, 창 3분 | 2분 정도 기다림(도구 기본 대기 8분) |

## 13. 보안 수칙(공개 저장소)

1. **`.env` 는 절대 커밋하지 않습니다.** `.gitignore` 가 `.env`·`.env.*` 를 막고 `.env.example` 만 허용(`tests/test_gitignore.py` 가 확인).
2. `.env.example` 에는 `<YOUR_API_KEY>` 같은 **자리표시자만** 둡니다.
3. **커밋 전 `python -m app.secret_scan`** — 키·토큰·개인키 패턴이 있으면 종료 코드 1(값은 출력하지 않음). `pytest` 에도 포함.
4. 랩 점검·S6 도구는 비밀 값을 출력하지 않고, S6 는 문서용 IP 만 씁니다.
5. 운영 서버에는 올리지 않습니다.

## 14. 진행 상태·폴더 구조

| 단계 | 내용 | 상태 |
|---|---|---|
| P0 | 골격·`.env` 차단·비밀 스캔·설정 로더·`mini_xdr` 스키마 | ✅ |
| P1 | 수집·정규화(Graylog Search API, 체크포인트) — 30일 백필 81,258건·실시간 2.1초 | ✅ |
| P2 | 상관·읽기 전용 콘솔·컨테이너 — 인시던트 1,630개(고유 지문 164종) | ✅ |
| P2+ | AI 키 교체·연결 테스트 화면 — 실제 Gemini 목록 46개·샘플 21/3 토큰 | ✅ |
| P3 | 행위 이상탐지(기준선·robust z) — 폭주 표식 → behavior 합류 22초 | ✅ |
| P4 | LLM 트리아지·호출 깔때기·캐싱·가드레일 — 과거 1,640건 중 LLM 8.7% | ✅ |
| 랩 연동 | 연동 점검 도구 · S6 끝-끝 도구 · AI 공급자 교체 화면 | ✅ |
| P5 | n8n 승인 대응 | 예정 |
| P6 | 레드팀 "AI 속이기"·최적화 전후 측정 | 예정 |

```text
_13_mini-xdr/
├── app/
│   ├── config.py            # 설정 로더(.env) — 키 없으면 규칙 판정
│   ├── graylog.py · collector.py · normalizer.py   # 수집·정규화
│   ├── correlator.py · fingerprint.py · timeline.py # 상관
│   ├── anomaly.py · detector.py                    # 행위 이상탐지
│   ├── masker.py · card.py · prompt.py · rule_dictionary.py · data/   # AI 입력(카드·고정 앞부분)
│   ├── triage_schema.py · llm_triage.py · gate.py · triage.py         # 판정·깔때기·가드레일
│   ├── llm_settings.py · llm_probe.py · settings_store.py · secret_box.py   # AI 설정·연결 테스트·암호화
│   ├── lab_check.py · lab_s6.py   # 랩 연동 점검 · S6 끝-끝 확인
│   ├── store.py · worker.py · schema.py · secret_scan.py
│   └── console/             # 웹 화면(사건 조회=읽기 전용, /settings=AI 설정)
├── sql/001_schema.sql       # mini_xdr DB·11개 테이블
├── Dockerfile · docker-compose.yml · .dockerignore
├── fixtures/ · tests/ · docs/plans/
├── .env.example             # 자리표시자만
└── requirements.txt · requirements-dev.txt · pytest.ini
```
