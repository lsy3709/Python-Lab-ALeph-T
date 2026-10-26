# _13_mini-xdr — 기존 SOAR 랩 위의 AI 분석 계층

> ⚠️ **개념 학습·대체 실습**입니다. 실제 XDR 은 SKT 상용 플랫폼이 우선이며, 이 폴더는 그 개념을
> 오픈소스와 자체 코드로 체험하기 위한 강의·캡스톤용 코드입니다 *(SKT 사전 싱크 필요)*.

이미 동작하는 SOAR 랩(Flask 게시판 `_7_board_test`·MySQL·Wazuh `_9_Wazuh`·Graylog `_9_graylog`·n8n) 위에
**여러 계층의 경보를 하나의 사건으로 묶고 → 평소와 다른 행동을 점수화하고 → Claude 가 우선순위와 근거를 판정**하는
분석 서비스를 덧붙입니다. 실제 대응(차단·잠금)은 기존 n8n 승인 게이트가 맡고, AI 는 실행 권한이 없습니다.

- 설계(기획서): 교안 저장소 `_local/186_미니XDR_AI탑재_기획서.md`
- 구축 과정 기록: 교안 저장소 `_local/187_…`(단계별)
- 단계별 계획: [`docs/plans/`](docs/plans/)

## 진행 상태

| 단계 | 내용 | 상태 |
|---|---|---|
| P0 | 골격·`.env` 차단·비밀 스캔·설정 로더·`mini_xdr` 스키마 | ✅ 완료 |
| P1 | 수집·정규화(Graylog Search API, 체크포인트) | ✅ 완료 — 30일 백필 81,258건·실시간 2.1초 |
| P2 | 상관(인시던트)·읽기 전용 콘솔·컨테이너화 | ✅ 완료 — 81,260건 → 인시던트 1,630개(고유 지문 164종)·약 4초 |
| P3 | 행위 이상탐지(기준선·z-score) | 예정 |
| P4 | LLM 트리아지·호출 깔때기(토큰 절약)·캐싱·가드레일 | 예정 |
| P5 | n8n 승인 대응 | 예정 |
| P6 | 레드팀 "AI 속이기"·최적화 전후 측정 | 예정 |

## 폴더 구조 (P2 시점)

```text
_13_mini-xdr/
├── app/
│   ├── config.py        # 환경설정 로더 — 키 없으면 규칙 판정 모드
│   ├── secret_scan.py   # 공개 저장소용 비밀 스캔(python -m app.secret_scan)
│   ├── schema.py        # 스키마 경로·테이블 목록
│   ├── normalizer.py    # Graylog 메시지 → 공통 스키마(출처·계층 분류)
│   ├── graylog.py       # Graylog 검색 API 클라이언트(토큰/계정 인증)
│   ├── collector.py     # 수집 한 주기(체크포인트·overlap·페이지·정체 방지)
│   ├── fingerprint.py   # 인시던트 지문(G3) — 시각·IP·횟수 제외
│   ├── correlator.py    # 상관 — 엔티티 키·10분 창·규칙 하한, 실행기 correlate_once
│   ├── timeline.py      # 타임라인 접기(콘솔·LLM 카드 공용)
│   ├── store.py         # MySQL 저장소(적재·체크포인트·상관 저장 트랜잭션, UTC)
│   ├── worker.py        # 분석 워커(python -m app.worker [--once]) — 재연결→수집→상관
│   └── console/         # 읽기 전용 콘솔(python -m app.console) — Flask + waitress
├── sql/001_schema.sql   # mini_xdr DB 와 10개 테이블(여러 번 적용해도 안전)
├── Dockerfile · docker-compose.yml · .dockerignore   # 워커·콘솔 컨테이너
├── fixtures/            # 실데이터 구조로 만든 표본(TEST-NET IP·테스트 계정만)
├── tests/               # pytest (integration 은 도커 필요)
├── docs/plans/          # 단계별 구현 계획
├── .env.example         # 설정 키 예시(자리표시자만)
├── requirements.txt / requirements-dev.txt
└── pytest.ini
```

## 빠른 시작 (Windows PowerShell)

```powershell
cd E:\0-Aleph-Python-Test\Python-Lab-ALeph-T\_13_mini-xdr
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

Copy-Item .env.example .env      # 값 채우기 — 키를 비워 두면 LLM 없이 규칙 판정 모드
python -m pytest                 # 단위 테스트(도커 불필요)
python -m pytest -m integration  # 일회용 MySQL 8.0 컨테이너에 스키마를 실제 적용해 검증(도커 필요)
python -m app.secret_scan        # 커밋 전 비밀 스캔 — "비밀 스캔 통과" 가 나와야 함
```

> Git Bash 에서 실행하면 한글 출력이 깨질 수 있습니다(파이프 출력 인코딩 문제). 이때는
> `PYTHONIOENCODING=utf-8 python -m app.secret_scan` 처럼 실행하거나 PowerShell 을 쓰세요.

## 랩 MySQL 에 스키마 적용

SOAR 랩의 MySQL 컨테이너에 전용 DB 를 만듭니다. 게시판 DB(`my_new_board_db`)는 건드리지 않습니다.

```powershell
docker ps --format "{{.Names}}" | Select-String mysql                       # MySQL 컨테이너 이름 확인
Get-Content -Raw sql\001_schema.sql | docker exec -i <MySQL컨테이너> mysql -uroot -p<루트비번>
docker exec -i <MySQL컨테이너> mysql -uroot -p<루트비번> -e "SHOW TABLES FROM mini_xdr;"   # 10개 확인
```

mini-xdr 전용 최소 권한 계정(비밀번호는 직접 정하고 `.env` 의 `MYSQL_PASSWORD` 에만 적습니다):

```sql
CREATE USER IF NOT EXISTS 'xdr'@'%' IDENTIFIED BY '<비밀번호>';
GRANT SELECT, INSERT, UPDATE, DELETE ON mini_xdr.* TO 'xdr'@'%';
```

## 수집 워커 실행 (P1)

`.env` 에 Graylog 인증(`GRAYLOG_TOKEN` 권장, 없으면 `GRAYLOG_USER`/`GRAYLOG_PASSWORD`)과 `xdr` 계정 비밀번호를 넣은 뒤:

```powershell
python -m app.worker --once   # 한 주기만 — 체크포인트가 없으면 COLLECT_BACKFILL_MIN 만큼 과거부터
python -m app.worker          # 상시 실행(POLL_INTERVAL_SEC 마다) — Ctrl+C 로 종료
```

출력 예: `[수집] 10-26 06:31:43~06:32:44Z 페이지 1 · 조회 1 · 적재 1 · 중복 0 · 건너뜀 0`

| 출처(source) | 계층(layer) | 판별 |
|---|---|---|
| wazuh | 룰 그룹으로 결정: `ids`→network · `mysql_audit`→data · `webapp`/`flask_board`/`web_scan`→app · 그 외 host | `wazuh_rule_id` 있음 |
| pfsense · suricata · snort · cloudflare | network | GELF `rule`(pfsense-block·ids-alert·snort-portscan·cf-waf) 또는 출처 |
| board | app | 그 밖의 GELF `rule`(게시판 신호·봇) |

라이브 실측(2026-10-26): 30일 백필 4주기 81,258건(25,000건당 약 3.2초), 따라잡기 중 overlap 생략으로 중복 재조회 11,846→647건, 표식 신호 적재까지 2.1초, 재실행 시 `적재 0 · 중복 N`(멱등).

## 상관 — 이벤트를 인시던트로 (P2)

워커는 한 주기마다 수집 뒤 상관까지 합니다. 출력 예: `[상관] 처리 81260 · 새 인시던트 1630 · 갱신 19 · 닫힘 0`

| 규칙 | 내용 |
|---|---|
| 엔티티 키 | 출발지 IP > 계정 > 자산 — `ip:203.0.113.7` · `user:alice` · `asset:board-host`(src_ip 없는 호스트 점검 경보) |
| 창 | 엔티티의 최근 인시던트 `[시작 − 10분, 마지막 + 10분]` 안이면 붙이고 아니면 새로 연다(`CORRELATION_WINDOW_MIN`). 10분 조용하면 닫힘 |
| 규칙 하한 | 최고 Wazuh level 12↑ P1 · 10↑ P2 · 7↑ P3 · 그 외 P4. AI 판정(P4)도 이 아래로 내리지 못함 |
| 지문 | SHA-256(엔티티 유형·계층·신호·이상점수 구간) — 시각·IP·횟수 제외, P4 지문 캐시(G3)의 열쇠 |
| 진행 위치 | `checkpoints('correlator').last_id` — 인시던트·연결·진행 위치를 한 트랜잭션으로 저장 |

라이브 실측(2026-10-26): 81,260건 → 인시던트 **1,630개**(약 4초, 재실행 처리 0), 다계층 20개, 우선순위 P1 62 · P2 75 · P3 343 · P4 1,150, **고유 지문 164종**(같은 종류 반복 — LLM 판정은 최대 164번이면 충분), 원본 81,264건 → 타임라인 4,930줄(16.5배) → 신호 요약 2,232행(36배).

## 읽기 전용 콘솔 (P2)

```powershell
python -m app.console          # http://127.0.0.1:8099 — 인시던트 목록(우선순위순)·상세(신호 요약·타임라인)
```

- DB 세션을 `transaction_read_only` 로 열어 쓰기가 불가능합니다(DELETE → 오류 1792).
- 로그 값(계정명 등)은 공격자가 넣을 수 있는 문자열이라 자동 이스케이프로만 출력, CSP `default-src 'none'`.
- `/healthz` — `{"ok":true,"events":…,"incidents":…,"open":…,"backlog":…}` (DB 오류 시 503, 내용 비노출)

## 컨테이너로 실행 (P2)

```powershell
docker compose up -d --build   # 워커 + 콘솔(127.0.0.1:8099)
docker compose logs -f worker  # [수집]·[상관] 로그
docker compose down            # 끄기(restart: "no" — 수업 때 명시적으로 켬)
```

- 기존 SOAR 컨테이너의 네트워크에는 붙지 않고, `host.docker.internal` 로 호스트 공개 포트(MySQL 3306·Graylog 9000)에 접속합니다.
- 비밀값은 이미지에 넣지 않습니다(`.dockerignore` 로 `.env` 차단 + 실행 때 `env_file: .env`). 비루트 사용자로 실행.
- 호스트 워커(`python -m app.worker`)와 컨테이너 워커를 **동시에 돌리지 마세요**(같은 진행 위치를 두고 경쟁).

라이브 실측: 이미지 206MB·빌드 10초, 같은 TEST-NET IP 의 앱·네트워크 표식 신호 → 컨테이너 워커가 **다계층 인시던트 1개**로 묶어 콘솔에 표시(두 번째 신호 후 28초, 워커 주기 30초 이내).

## 보안 수칙 (이 저장소는 공개입니다)

1. **`.env` 는 절대 커밋하지 않습니다.** 이 폴더의 `.gitignore` 가 `.env`·`.env.*` 를 막고 `.env.example` 만 허용합니다(`tests/test_gitignore.py` 가 실제로 확인).
2. `.env.example` 에는 `<YOUR_API_KEY>` 같은 **자리표시자만** 둡니다. 자리표시자는 "키 없음" 으로 취급되어 규칙 판정 모드로 동작합니다.
3. **커밋 전 `python -m app.secret_scan`** — API 키·토큰·개인키 패턴이 하나라도 있으면 종료코드 1(값은 출력하지 않음). `pytest` 도 같은 검사를 포함합니다.
4. 운영 서버에는 올리지 않습니다. 랩·가상 데이터만 사용합니다.
