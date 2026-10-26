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
| P2+ | 웹 콘솔 AI 키 교체·연결 테스트(`/settings`) | ✅ 완료 — 실제 Gemini 키로 목록 46개·샘플 호출 21/3 토큰 |
| P3 | 행위 이상탐지(기준선·robust z) | ✅ 완료 — 폭주 표식 → behavior 계층 인시던트 합류 22초 |
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
│   ├── anomaly.py       # 행위 이상탐지 — 1시간 버킷 특징·robust z·원형 시각·2단 기준선
│   ├── detector.py      # 이상탐지 실행기(기준선 캐시·채점·behavior 이벤트) · --report 사후 분석
│   ├── store.py         # MySQL 저장소(적재·체크포인트·상관 저장 트랜잭션, UTC)
│   ├── worker.py        # 분석 워커(python -m app.worker [--once]) — 재연결→수집→상관
│   ├── secret_box.py    # 웹 UI 저장 키 암호화(Fernet)·마스킹
│   ├── llm_settings.py  # AI 설정 계산 — 웹 UI 저장값 > .env
│   ├── llm_probe.py     # AI 연결 테스트(모델 목록 → 샘플 호출)
│   ├── settings_store.py# app_settings 저장소·연결 테스트 사용 기록
│   └── console/         # 콘솔(python -m app.console) — 사건 조회는 읽기 전용, /settings 는 AI 설정
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

라이브 실측(2026-10-26): 81,260건 → 인시던트 **1,630개**(약 4초, 재실행 처리 0), 다계층 20개, 우선순위 P1 62 · P2 75 · P3 343 · P4 1,150, **고유 지문 164종**(같은 종류 반복 — AI 가 판단할 사건 종류는 1,630이 아니라 164), 원본 81,264건 → 타임라인 4,930줄(16.5배) → 신호 요약 2,232행(36배).

## 행위 이상탐지 (P3) — LLM 없이 통계로

워커 주기 = 재연결 → 수집 → **이상탐지** → 상관. 출력 예: `[이상] 채점 버킷 5 · 이상 1 · 새 behavior 2 · 기준선 개인 6 / 집단 9`

| 특징(IP·계정, 1시간 버킷) | 판정 |
|---|---|
| `events` 시간당 이벤트 · `signals` 신호 종류 · `login_fail` 로그인 실패 수 · `ratio_404` 404 비율 | 큰 값만 이상(한쪽) |
| `login_hour` 계정 로그인 시각(KST) | 평소 시각과의 원형 거리(23시와 1시는 2시간 차이) |

- **robust z** = (값 − 중앙값) / max(1.4826 × MAD, 하한) — 폭주가 섞인 기준선에서도 중심이 끌려가지 않음. 임계 `ANOMALY_Z`(3.0).
- **2단 기준선**: 개인(표본 ≥ `BASELINE_MIN_SAMPLES` 30) → 없으면 같은 유형 전체(집단) → 그것도 부족하면 채점하지 않음. 학습 = `BASELINE_DAYS`(30일) 중 직전 버킷 이전, 채점 = 직전·현재 버킷.
- 이상이면 `behavior` 이벤트(`anomaly-<특징>-<z3|z5|z8>`)를 `events_norm` 에 넣고 같은 주기의 상관에서 그 IP 인시던트에 붙는다. 같은 버킷은 한 번만(결정적 `raw_ref`).
- `python -m app.detector --report` — 전체 기간 사후 분석(쓰기 없음). 콘솔 `/anomalies` — 기준선 요약·최근 이상.

라이브 실측(2026-10-26): 개인 기준선 가능 IP 2개(나머지 116개 엔티티는 집단 기준선), 사후 분석 474버킷 중 153개 이상(공격 실습 데이터 — z3 39 · z5 38 · z8 76), 새 TEST-NET IP 표식 160건 → 22초 뒤 `anomaly-events-z8`(z 8.71)·`anomaly-signals-z3` 가 같은 IP 인시던트에 `["app","behavior"]` 로 합류.

## 읽기 전용 콘솔 (P2)

```powershell
python -m app.console          # http://127.0.0.1:8099 — 인시던트 목록(우선순위순)·상세(신호 요약·타임라인)
```

- DB 세션을 `transaction_read_only` 로 열어 쓰기가 불가능합니다(DELETE → 오류 1792).
- 로그 값(계정명 등)은 공격자가 넣을 수 있는 문자열이라 자동 이스케이프로만 출력, CSP `default-src 'none'`.
- `/healthz` — `{"ok":true,"events":…,"incidents":…,"open":…,"backlog":…}` (DB 오류 시 503, 내용 비노출)

## AI 키 교체·연결 테스트 — 웹 콘솔 `/settings` (P2+)

1. `.env` 에 암호화 열쇠를 한 번 만들어 둡니다(값은 남에게 보이지 않게):
   ```powershell
   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
   # 출력값을 .env 의 SETTINGS_SECRET_KEY= 뒤에 붙여 넣고 콘솔을 다시 시작
   ```
2. http://127.0.0.1:8099/settings → 공급자(gemini·claude·none)·API 키 입력 → **저장**
3. **테스트**(체크 안 함) = 모델 목록 조회(토큰 0) → 목록에서 모델 ID 를 골라 저장
4. **샘플 호출까지** 체크 후 테스트 = 짧은 문장 1회 → 응답·입력/출력 토큰·지연 표시, `llm_calls` 에 `connection_test` 로 기록
5. **지우고 .env 로 되돌리기** = 웹 UI 저장값 삭제

| 보안 장치 | 내용 |
|---|---|
| 암호문 저장 | 키는 `app_settings` 에 `enc:v1:`(Fernet)로만, 열쇠는 `.env` 의 `SETTINGS_SECRET_KEY` |
| 화면 비노출 | 키는 다시 표시하지 않음(앞4…뒤4), 입력란 `type=password`, 오류 문구에서 키 가림 |
| 쓰기 보호 | CSRF 토큰(SameSite=Strict) · Origin 검사 · 모든 요청 Host 가 localhost 계열만(DNS 리바인딩 방지) |
| 우선순위 | 웹 UI 저장값 > `.env`·환경변수. 저장 키를 못 풀면 `.env` 로 조용히 넘어가지 않고 문제 표시 |

라이브 실측(2026-10-26): 가짜 키 → `HTTP 400: API key not valid`(키 원문 화면·DB 노출 0), 실제 Gemini 키(환경변수) → 모델 46개, `gemini-2.5-flash-lite` 는 목록에 있지만 호출 404(신규 사용자 미제공), `gemini-3.5-flash-lite` 샘플 호출 성공(응답 "연결 확인", 21/3 토큰, 1.2초).

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
