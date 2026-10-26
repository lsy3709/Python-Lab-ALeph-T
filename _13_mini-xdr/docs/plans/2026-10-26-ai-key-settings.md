# 미니 XDR — 웹 콘솔 AI 키 교체·연결 테스트 구현 계획

> **에이전트 작업자용:** 필수 하위 스킬 — `superpowers:subagent-driven-development`(권장) 또는 `superpowers:executing-plans` 로 작업 단위 실행. 단계는 체크박스(`- [ ]`)로 추적.

**목표:** 콘솔 `/settings` 화면에서 AI 공급자(claude·gemini·none)·모델·API 키를 바꾸고, "연결 테스트"(모델 목록 → 샘플 호출)로 실제 사용 가능 여부와 토큰 사용량을 확인한다.

**설계:** 웹 UI 에서 받은 값은 `mini_xdr.app_settings` 에 저장하고 `.env` 보다 우선한다. API 키는 **Fernet 암호문**으로만 저장하고 복호화 열쇠 `SETTINGS_SECRET_KEY` 는 `.env` 에만 둔다. 사건 조회 화면의 읽기 전용 연결은 그대로 두고, 설정 쓰기는 별도 연결·별도 라우트에서 CSRF·Origin·Host 검사를 거친다.

**기술:** cryptography(Fernet) · anthropic 공식 SDK(`client.models.list()`·`messages.create`) · httpx(Gemini REST, `x-goog-api-key` 헤더) · Flask 세션(CSRF 토큰)

## 사용자 요청 (2026-10-26)

"웹 UI 에서 AI 키 교체 가능하게 하고, 샘플 제미나이 키로 이용 테스트 확인 가능하게."

## 설계 결정

1. **우선순위**: 웹 UI 저장값(DB) > 환경변수·`.env`. "웹 UI 설정 지우기" 로 `.env` 로 되돌린다. 키를 비워 두고 저장하면 기존 저장 키를 유지(모델만 바꾸기).
2. **암호문 저장**: `enc:v1:` + Fernet 토큰. DB 를 읽을 수 있어도(콘솔 읽기 전용 연결 포함) 키 원문을 알 수 없다. 열쇠가 없으면 저장 버튼을 막고 생성 명령을 안내한다. 열쇠가 바뀌어 풀 수 없으면 조용히 `.env` 로 넘어가지 않고 문제를 표시한다.
3. **화면 노출 최소화**: 키는 다시 표시하지 않는다(`앞4…뒤4`), 입력란은 `type=password`·`autocomplete=off`. 오류 메시지에서 키 문자열을 지운다(`[가림]`). Gemini 키는 URL 이 아니라 **헤더**로 보내 로그·예외에 남지 않게 한다.
4. **쓰기 보호**: CSRF 토큰(세션, `SameSite=Strict`, `hmac.compare_digest`) · Origin 이 있으면 localhost 계열만 · 모든 요청의 Host 가 `127.0.0.1`·`localhost`·`[::1]` 만(DNS 리바인딩 방지) · 입력 검증(공급자 화이트리스트, 모델 ID `^[A-Za-z0-9._/-]{1,128}$`, 키 20~256자·공백 없음).
5. **연결 테스트 2단계**: ① 모델 목록(토큰 0) — 모델 ID 는 추측하지 않고 API 가 알려 준 목록에서 고른다. ② 샘플 호출(선택, 짧은 고정 문장) — 응답·입력/출력 토큰·지연 시간 표시, `llm_calls` 에 `gate_reason='connection_test'` 로 기록. 비용 추정은 단가를 아는 Claude 모델만(haiku-5-5 $0.10/$0.50, sonnet-5-5 $2/$10 per 1M), Gemini 는 0(단가 미입력).
6. **SDK 사용**: Claude 는 공식 SDK(`anthropic.Anthropic(api_key=…, timeout=15, max_retries=0)`), Gemini 는 REST(httpx). SDK 오류는 `status_code` 로 분류(401 인증 실패·403 권한·404 모델 없음·429 한도).
7. **실제 키 시험**: 에이전트가 실제 API 키를 입력란에 넣지 않는다. 사용자가 이미 설정한 환경변수 `GEMINI_API_KEY` 를 앱이 읽는 경로(호스트 실행 콘솔)로 실제 호출을 검증하고, 입력·교체·실패 흐름은 가짜 키로 검증한다.

## 파일 구조

| 파일 | 책임 |
|---|---|
| `app/secret_box.py` | `SecretBox`(seal/open, Fernet)·`mask()` |
| `app/llm_settings.py` | `LLMConfig`·`effective_llm_config()`·`save_llm()`·`reset_llm()`·입력 검증 |
| `app/llm_probe.py` | `ProbeResult`·`probe_gemini()`·`probe_claude()`·`estimate_cost()` |
| `app/settings_store.py` | `MySQLSettingsRepo`(app_settings 읽기/쓰기/삭제)·`record_llm_call()` |
| `app/console/security.py` | Host·Origin 검사, CSRF 토큰 |
| `app/console/settings_views.py` | `/settings` 화면·저장·되돌리기·연결 테스트 |
| `app/console/templates/settings.html` | 설정 화면 |
| `sql/001_schema.sql`·`app/schema.py` (수정) | 11번째 테이블 `app_settings` |
| `app/config.py`·`.env.example` (수정) | `SETTINGS_SECRET_KEY` |
| 테스트 | `test_secret_box`·`test_llm_settings`·`test_llm_probe`·`test_settings_store_mysql`(통합)·`test_console_settings`·`test_schema_static`(보강) |

## 작업

- [ ] Task 1: 비밀값 상자(Fernet)·마스킹·설정 키 — RED → GREEN → 커밋
- [ ] Task 2: 유효 설정 계산·저장·되돌리기·입력 검증(가짜 저장소) — RED → GREEN → 커밋
- [ ] Task 3: 연결 테스트(Gemini MockTransport·Claude 가짜 클라이언트)·비용 추정 — RED → GREEN → 커밋
- [ ] Task 4: `app_settings` 스키마·MySQL 저장소·사용 기록(통합) — RED → GREEN → 커밋
- [ ] Task 5: 콘솔 보안(Host·Origin·CSRF)·설정 화면 — RED → GREEN → 커밋
- [ ] Task 6: 라이브 — 랩 스키마 적용·열쇠 생성(.env, 값 미출력)·컨테이너 재기동, 가짜 키 교체 흐름(브라우저), 환경변수 실제 키로 모델 목록·샘플 호출, DB 에 암호문만 있는지 확인 → README·교안 [190]·노션
