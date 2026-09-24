# 실습 게시판 (`_7_board_test`) — 다른 PC 에서 처음부터 띄우기

SOAR 실습([108]~[114]·[129]·[140])의 **대상 웹앱**이다. 공격을 받고, 보안 이벤트를 남기고,
n8n 봇이 호출하는 관리 API 를 제공한다.

> 강의장 PC 에서 `git pull` 만으로는 안 된다 — **파이썬 패키지·`.env`·MySQL** 세 가지를 준비해야 한다.
> 아래 순서대로 하면 5~10분이면 뜬다.

---

## 0. 필요한 것

| 항목 | 버전/비고 |
|---|---|
| Python | 3.11 이상 (강사 PC 는 3.13) |
| MySQL | 8.x — 도커로 띄워도 된다 |
| (선택) Docker | Graylog·n8n·Wazuh 연동 실습을 함께 할 때 |

---

## 1. 가상환경 + 패키지

```bash
cd _7_board_test
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

> `requirements.txt` 는 **ASCII 전용**으로 유지한다. 한글 주석을 넣으면 한국어 Windows 의 pip 가
> cp949 로 읽어 `UnicodeDecodeError` 로 설치가 실패한다(2026-09-25 실측).

---

## 2. MySQL 준비

도커로 띄우는 예:

```bash
docker run -d --name mysql-server -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=<루트비번> \
  -e MYSQL_DATABASE=my_new_board_db \
  mysql:8
```

이미 MySQL 이 있다면 데이터베이스만 만든다.

```sql
CREATE DATABASE my_new_board_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

표(table)는 앱이 처음 뜰 때 `db.create_all()` 로 **자동 생성**되므로 따로 만들지 않아도 된다.
기존 표 구조가 바뀐 경우만 `docs/001_security_events_테이블_생성.md` 를 참고한다.

---

## 3. `.env` 만들기

`.env` 는 비밀이라 git 에 올라가지 않는다. 같은 폴더의 **`.env.example`** 또는
**`.env 강사용예시`** 를 복사해서 값을 채운다.

```bash
copy ".env 강사용예시" .env      # Windows
```

| 키 | 설명 |
|---|---|
| `DATABASE_URL` | `mysql+pymysql://<user>:<password>@localhost:3306/my_new_board_db` |
| `SECURITY_API_KEY` | n8n 봇이 쓰는 공유 비밀. 길고 무작위로. |
| `ADMIN_API_KEY` | 관리자 API 용(없으면 `SECURITY_API_KEY` 로 대체) |
| `JWT_SECRET_KEY` | 로그인 토큰 서명 키 |

> 비밀번호에 `@ : / #` 같은 문자가 있으면 URL 파싱이 깨진다 — **URL 안전한 문자**로 만들거나 퍼센트 인코딩한다.

---

## 4. 실행

```bash
python app.py
```

- 기본 `http://localhost:5000`
- `app.run(host='0.0.0.0')` 이라 같은 공유기의 다른 기기에서도 접속된다.
- 도커 안 n8n 에서는 `http://host.docker.internal:5000` 으로 부른다.

**확인**

| 주소 | 내용 |
|---|---|
| `/` | 게시판 메인 |
| `/dashboard` | 보안 대시보드 — 이벤트 + **인시던트 티켓** |
| `/admin` | 회원 역할(인가) 관리 |
| `GET /api/security/incidents/summary` | 신 코드인지 한 줄로 확인(404 면 옛 코드) |

---

## 5. 테스트

```bash
python -m pytest tests/ -q
```

2026-09-25 기준 **32개 통과**. 깨끗한 새 가상환경에서도 동일하게 통과하는 것을 확인했다.

---

## 6. 자주 막히는 곳

| 증상 | 원인 / 해결 |
|---|---|
| `pip install` 이 `UnicodeDecodeError` | `requirements.txt` 에 한글이 들어감 → ASCII 로 유지 |
| `ModuleNotFoundError: flask` | 가상환경을 활성화하지 않고 실행 |
| 기동 시 DB 접속 오류 | `.env` 의 `DATABASE_URL` · MySQL 기동 여부 · 비밀번호 특수문자 |
| 게시판 전체가 **403 차단된 IP** | 실습 중 SOAR 가 내 IP 를 차단한 것. `POST /api/admin/unblock` 으로 해제(관리자 API 는 차단돼도 통한다). 자세히는 문서 [143] |
| 관리 API 가 401 | `X-API-Key` 헤더 누락/불일치 |
| `/api/admin/lock` 이 404 | 잠글 **계정이 없음** — `POST /api/auth/register` 로 먼저 만든다 |
| 이벤트가 안 쌓임 | `/block`·`/lock` 응답의 `"changed": true` 확인(이미 차단/잠김이면 200 이어도 기록 안 남음) |

---

## 7. 안전

- 격리된 실습 환경에서만 쓴다. 인터넷에 그대로 노출하지 않는다.
- `.env`·API 키·웹훅 URL 은 git·문서·채팅에 올리지 않는다.
- 로그(`logs/security.log`)에는 IP·계정명이 남는다 — 보존기간과 접근권한을 정해 둔다.
