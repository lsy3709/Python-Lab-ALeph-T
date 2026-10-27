# 미니 XDR P4 — LLM 트리아지·호출 깔때기·캐싱·가드레일 구현 계획

> **에이전트 작업자용:** 필수 하위 스킬 — `superpowers:subagent-driven-development`(권장) 또는 `superpowers:executing-plans` 로 작업 단위 실행. 단계는 체크박스(`- [ ]`)로 추적.

**목표:** 인시던트를 마스킹된 카드로 만들어 LLM 이 우선순위·판정·근거·권고 플레이북을 고정 JSON 으로 답하게 한다. 그 앞에 호출 깔때기 G1~G7 을 두어 LLM 은 회색지대에만 쓰고, 규칙 하한·거절·스키마 오류·예산 초과는 규칙 판정으로 대체한다. 판정은 콘솔 상세와 `/usage` 에서 본다.

**설계:** [186] 4-1(카드·스키마)·4-3(마스킹)·4-4(인젝션 5겹 방어)·5(G1~G7·캐싱·다이어트·측정). 공급자·모델·키는 [190] 웹 UI 설정(`effective_llm_config`)을 매 주기 읽어 바로 반영한다. 워커 주기 = 재연결 → 수집 → 이상탐지 → 상관 → **트리아지**.

**기술:** anthropic 공식 SDK(`messages.parse` + Pydantic, `cache_control`, `output_config.effort`) · Gemini REST(`responseSchema`) · pydantic · 기존 PyMySQL·Flask

## 라이브 랩에서 확인한 사실 (2026-10-27)

| 항목 | 값 |
|---|---|
| 공급자 설정 | 웹 UI: gemini · `gemini-3.5-flash-lite`. 실제 키는 사용자 환경변수(호스트에서만), 컨테이너는 키 없음 → 규칙 판정 모드. Claude 키 없음(실호출 불가 — 모의 클라이언트로만 검증) |
| Wazuh 룰 | 60개. Graylog 의 `wazuh_rule_description` 에서 설명·MITRE 를 모음 |
| **룰 번호 재사용** | `100230` = 대부분 "Flask 게시판 HTTP 404", 일부 "저속 브루트포스" / `100231`·`100233` 도 두 뜻 — 매니저를 바꿔 가며 실습한 흔적 → 사전에 주된 뜻·다른 뜻을 함께 |
| 설명 속 개인정보 | Chrome 원격 데스크톱 룰 설명에 이메일, Snort 룰 설명에 IP → 사전 만들 때 걸러야 함(공개 저장소·외부 LLM) |
| Claude SDK | `client.messages.parse(..., output_format=Pydantic)` → `parsed_output`, 숫자·길이 제약은 SDK 가 클라이언트에서 검증 / `system=[{..., "cache_control": {"type": "ephemeral"[, "ttl": "1h"]}}]` / `output_config={"effort": "low"}` / `stop_reason == "refusal"` + `stop_details` |

## 설계 결정

1. **카드(입력 다이어트)**: 엔티티·계층·이벤트 수·지속 분·규칙 하한·최고 level, 신호 요약 상위 12행(level·건수 순), **타임라인 앞 15줄**(시간 순 — "실패 뒤 성공" 같은 순서가 판정에 중요), 이상 점수(z ≥ 3, 최대 3개), 계정 토큰 최대 5개. 문자열은 제어문자 제거·80자. 원본 로그 본문은 보내지 않는다.
2. **마스킹**: IP·계정·자산(호스트명)·이메일을 일관 토큰(`ip_1`·`user_1`·`asset_1`·`email_1`)으로, 키 모양 문자열은 `[키]`. 복원표는 로컬 메모리에만. 응답 근거(`reasoning_ko`)는 저장 전에 복원. **계정명이 토큰으로 바뀌므로 "계정명에 지시문" 인젝션은 LLM 에 닿지도 않는다**. 누출 테스트: 실제 페이로드에 원본 IP·계정·이메일 0건.
3. **고정 앞부분(프롬프트 캐싱)**: 역할·규칙(인젝션 경고 포함)·우선순위 기준·플레이북·계층 설명·**신호 사전**(룰 60개 + 게시판 GELF 신호 + behavior)·예시 2개. 시각·ID 없음, JSON 은 `sort_keys`. **SHA-256 스냅샷 테스트**로 바이트 고정. Claude 는 `cache_control`(TTL 은 `PROMPT_CACHE_TTL`), Gemini 는 암묵 캐시(`cachedContentTokenCount` 로 확인).
4. **출력 스키마**: `results[]` = ref·priority(P1~P4)·verdict(true_positive·benign·needs_review)·false_positive_likelihood·reasoning_ko·recommended_playbook(block_ip·lock_account·monitor·none)·confidence. 한 건도 배열로(묶음과 같은 경로). 확률은 0~1 로 자르고 근거는 600자로 자른다(실패 대신 보정).
5. **호출 깔때기**

| 관문 | 동작 | 기록 gate |
|---|---|---|
| G4 디바운스(먼저) | 마지막 판정 후 실질 상태(계층·하한·이상 구간·이벤트 수 2배 구간)가 같으면 건너뜀. 바뀌어도 5분 쿨다운(하한이 오르면 즉시) | (기록 없음) |
| G1 화이트리스트 | `WHITELIST_CIDRS`(기본 127.0.0.1/32) | G1 |
| G2 규칙 결론 | ① 같은 엔티티에서 로그인 실패 뒤 성공 → P1·true_positive·lock_account ② 단일 계층·최고 level<5·이상 없음 → P4·needs_review·monitor | G2 |
| G3 지문 캐시 | 같은 지문이 24시간 안에 LLM 판정됐으면 재사용(적중 수 증가) | G3 |
| (키 없음) | LLM 을 쓸 수 없으면 규칙 판정 | NOKEY |
| G5 예산 | 일 호출 `MAX_DAILY_LLM_CALLS`·시간당 `MAX_HOURLY_LLM_CALLS`, 최근 10분 연속 오류 3회면 서킷 열림 | G5 |
| G6 묶음 | 하한 P1·P2 는 단건 즉시, P3·P4 는 최대 `TRIAGE_BATCH`(5)건 한 요청 | — |
| G7 라우팅 | 하한 P1 이거나 계층 ≥ 3 이면 승급 모델, 응답 확신도 < 0.6 이면 승급 모델로 1회 재질문(승급 모델이 있을 때만) | LLM |

6. **가드레일**: 최종 우선순위 = max(LLM, 규칙 하한) — 하한이 이기면 gate `LLM-FLOOR` 로 기록(위반 0 을 셀 수 있게). 스키마 오류 1회 재시도 → 규칙. 거절 → 규칙(source=refusal). 오류 → 규칙(서킷 집계). AI 는 판정만, 실행은 P5 승인 게이트.
7. **규칙 판정(대체)**: 우선순위 = max(하한, 계층 ≥ 2 또는 이상 z5↑ 이면 P3), verdict needs_review, playbook = P1·P2 이고 IP 엔티티면 block_ip, 아니면 monitor.
8. **대상 선택**: 열린 인시던트 + 마지막 이벤트가 `TRIAGE_LOOKBACK_MIN`(60분) 안인 인시던트 중 G4 를 통과한 것. 과거 1,632건은 자동으로 판정하지 않는다(비용) — `python -m app.triage --dry-run` 으로 관문 분포만 추정, `--recent N` 으로 최근 N건만 실제 판정.
9. **저장**: `triage_results`(복원한 근거), `incidents`(current_priority·last_triaged_at·material_state), `verdict_cache`(LLM 판정만, 24시간), `llm_calls`(gate_reason·토큰·캐시 토큰·비용·지연·status).
10. **콘솔**: 상세에 최신 판정(출처·관문·모델·근거·권고), `/usage` 에 판정 출처·관문 분포, LLM 호출률, 지문 캐시 적중률, 프롬프트 캐시 읽기 비율, 토큰·비용, 하한 적용 수.

## 파일 구조

| 파일 | 책임 |
|---|---|
| `app/rule_dictionary.py`·`app/data/rule_dictionary.json` | 신호 사전 — Graylog 에서 만들기(`--build`, 개인정보 거름)·읽기, 게시판 GELF·behavior 설명 |
| `app/masker.py` | 일관 토큰 마스킹·문자열 정리·복원·누출 검사 |
| `app/card.py` | 인시던트 카드(입력 다이어트) |
| `app/triage_schema.py` | Pydantic 출력 스키마·Gemini responseSchema·보정·규칙 판정 |
| `app/prompt.py` | 고정 앞부분(시스템 프롬프트)·사용자 메시지 |
| `app/llm_triage.py` | `ClaudeTriager`(SDK)·`GeminiTriager`(REST) → `LLMResult` |
| `app/gate.py` | 실질 상태·이상 구간·실패 뒤 성공·G1/G2 판단 |
| `app/triage.py` | 실행기(깔때기·묶음·라우팅·가드레일·저장)·CLI(`--dry-run`·`--recent`) |
| `app/store.py` (수정) | 대상·카드 입력·판정 저장·지문 캐시·호출 집계 |
| `app/worker.py`·`app/config.py`·`.env.example` (수정) | 트리아지 단계·설정 |
| `app/console/` (수정) | 상세의 판정·`/usage` |

## 작업

- [ ] Task 1: 신호 사전(만들기·거름·읽기) + 마스킹 — RED → GREEN → 커밋
- [ ] Task 2: 카드·출력 스키마·규칙 판정·고정 앞부분(스냅샷) — RED → GREEN → 커밋
- [ ] Task 3: LLM 어댑터(Claude 가짜 클라이언트·Gemini MockTransport — 성공·스키마 오류·거절·최대 토큰·HTTP 오류·캐시 토큰) — RED → GREEN → 커밋
- [ ] Task 4: 관문(G1·G2·G4 실질 상태·구간·실패 뒤 성공) — RED → GREEN → 커밋
- [ ] Task 5: 실행기(G3·G5·G6·G7·가드레일·재시도·복원, 가짜 저장소·가짜 LLM) — RED → GREEN → 커밋
- [ ] Task 6: MySQL 저장(대상·카드 입력·판정·캐시·호출 집계, 통합) — RED → GREEN → 커밋
- [ ] Task 7: 워커 단계·설정·콘솔(상세 판정·`/usage`) — RED → GREEN → 커밋
- [ ] Task 8: 라이브 — 과거 1,632건 관문 분포(dry-run), 실제 Gemini 로 표식 시나리오(회색지대 → LLM, 같은 지문 다른 IP → G3, 재수집 → G4), 프롬프트 캐시 토큰 확인, 컨테이너(키 없음 → 규칙 판정) → README·교안 [192]·노션
