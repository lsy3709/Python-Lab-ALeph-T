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
| P1 | 수집·정규화(Graylog Search API, 체크포인트) | 예정 |
| P2 | 상관(인시던트)·콘솔 목록 | 예정 |
| P3 | 행위 이상탐지(기준선·z-score) | 예정 |
| P4 | LLM 트리아지·호출 깔때기(토큰 절약)·캐싱·가드레일 | 예정 |
| P5 | n8n 승인 대응 | 예정 |
| P6 | 레드팀 "AI 속이기"·최적화 전후 측정 | 예정 |

## 폴더 구조 (P0 시점)

```text
_13_mini-xdr/
├── app/
│   ├── config.py        # 환경설정 로더 — 키 없으면 규칙 판정 모드
│   ├── secret_scan.py   # 공개 저장소용 비밀 스캔(python -m app.secret_scan)
│   └── schema.py        # 스키마 경로·테이블 목록
├── sql/001_schema.sql   # mini_xdr DB 와 10개 테이블(여러 번 적용해도 안전)
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

## 보안 수칙 (이 저장소는 공개입니다)

1. **`.env` 는 절대 커밋하지 않습니다.** 이 폴더의 `.gitignore` 가 `.env`·`.env.*` 를 막고 `.env.example` 만 허용합니다(`tests/test_gitignore.py` 가 실제로 확인).
2. `.env.example` 에는 `<YOUR_API_KEY>` 같은 **자리표시자만** 둡니다. 자리표시자는 "키 없음" 으로 취급되어 규칙 판정 모드로 동작합니다.
3. **커밋 전 `python -m app.secret_scan`** — API 키·토큰·개인키 패턴이 하나라도 있으면 종료코드 1(값은 출력하지 않음). `pytest` 도 같은 검사를 포함합니다.
4. 운영 서버에는 올리지 않습니다. 랩·가상 데이터만 사용합니다.
