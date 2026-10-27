"""LLM 트리아지 어댑터 — 같은 입력(고정 앞부분 + 카드 메시지)·같은 출력(LLMResult)으로 Claude 와 Gemini 를 바꿔 쓴다.

- Claude: 공식 SDK `messages.parse(output_format=TriageBatch)`, 고정 앞부분에 cache_control(프롬프트 캐싱),
  effort low, 샘플링 파라미터 없음(2026-10-21 부터 400). 거절(stop_reason=refusal)은 오류가 아닌 정상 분기.
- Gemini: REST generateContent, systemInstruction + responseSchema(JSON 강제), 키는 x-goog-api-key 헤더.
  암묵 캐시는 usageMetadata.cachedContentTokenCount 로 확인한다.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

import httpx
from pydantic import ValidationError

from app.llm_probe import CLAUDE_PRICES, GEMINI_BASE, MODEL_ID_RE, _clean, _gemini_error, _sdk_error
from app.triage_schema import GEMINI_SCHEMA, TriageBatch, Verdict, normalize

MAX_OUTPUT_TOKENS = 2048       # 묶음 5건 × 근거 3문장을 넉넉히 — 잘림은 status=max_tokens 로 확인
GEMINI_REFUSALS = {"SAFETY", "PROHIBITED_CONTENT", "BLOCKLIST", "SPII", "RECITATION"}


@dataclass
class LLMResult:
    provider: str
    model: str
    status: str                                   # ok · invalid · refusal · error · max_tokens
    verdicts: dict[str, Verdict] = field(default_factory=dict)
    input_tokens: int = 0                         # 캐시에서 읽지 않은 입력
    output_tokens: int = 0
    cache_read: int = 0
    cache_write: int = 0
    latency_ms: int | None = None
    error: str | None = None
    refusal_category: str | None = None


def estimate_call_cost(r: LLMResult, cache_ttl: str = "5m") -> float:
    """Claude 단가(claude-api 레퍼런스): 캐시 읽기는 입력가의 0.1배, 쓰기는 1.25배(5분)·2배(1시간). Gemini 는 0(단가 미입력)."""
    price = CLAUDE_PRICES.get(r.model) if r.provider == "claude" else None
    if not price:
        return 0.0
    p_in, p_out = price
    write = 2.0 if cache_ttl == "1h" else 1.25
    return (r.input_tokens * p_in + r.cache_read * p_in * 0.1 + r.cache_write * p_in * write
            + r.output_tokens * p_out) / 1_000_000


def _verdicts(batch: TriageBatch) -> dict[str, Verdict]:
    return {v.ref: normalize(v) for v in batch.results}


class GeminiTriager:
    provider = "gemini"

    def __init__(self, api_key: str, *, transport: httpx.BaseTransport | None = None, timeout: float = 30.0) -> None:
        self._key, self._transport, self._timeout = api_key, transport, timeout

    def triage(self, system: str, user: str, model: str) -> LLMResult:
        name = model.removeprefix("models/")
        if not MODEL_ID_RE.match(name):
            return LLMResult(self.provider, model, "error", error="모델 ID 형식이 올바르지 않습니다")
        body = {"systemInstruction": {"parts": [{"text": system}]},
                "contents": [{"role": "user", "parts": [{"text": user}]}],
                "generationConfig": {"responseMimeType": "application/json", "responseSchema": GEMINI_SCHEMA,
                                     "maxOutputTokens": MAX_OUTPUT_TOKENS}}
        started = time.perf_counter()
        try:
            with httpx.Client(base_url=GEMINI_BASE, headers={"x-goog-api-key": self._key}, timeout=self._timeout,
                              transport=self._transport) as client:
                r = client.post(f"/models/{name}:generateContent", json=body)
        except httpx.HTTPError as exc:
            return LLMResult(self.provider, name, "error", error=f"연결 실패({type(exc).__name__})")
        res = LLMResult(self.provider, name, "ok", latency_ms=int((time.perf_counter() - started) * 1000))
        if r.status_code != 200:
            res.status, res.error = "error", _gemini_error(r, self._key)
            return res
        data = r.json()
        usage = data.get("usageMetadata", {})
        res.cache_read = usage.get("cachedContentTokenCount", 0)
        res.input_tokens = max(usage.get("promptTokenCount", 0) - res.cache_read, 0)
        res.output_tokens = usage.get("candidatesTokenCount", 0) + usage.get("thoughtsTokenCount", 0)
        block = data.get("promptFeedback", {}).get("blockReason")
        candidate = (data.get("candidates") or [{}])[0]
        finish = candidate.get("finishReason")
        if block or finish in GEMINI_REFUSALS:
            res.status, res.refusal_category = "refusal", block or finish
            return res
        if finish == "MAX_TOKENS":
            res.status = "max_tokens"
            return res
        text = "".join(p.get("text", "") for p in candidate.get("content", {}).get("parts", []))
        try:
            res.verdicts = _verdicts(TriageBatch.model_validate_json(text))
        except ValidationError:
            res.status = "invalid"
        return res


class ClaudeTriager:
    provider = "claude"

    def __init__(self, api_key: str, *, client=None, cache_ttl: str = "5m", timeout: float = 30.0) -> None:
        if client is None:
            import anthropic  # 실제 호출 때만

            client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=1)
        self._client, self._key = client, api_key
        self._cache = {"type": "ephemeral", **({"ttl": "1h"} if cache_ttl == "1h" else {})}

    def triage(self, system: str, user: str, model: str) -> LLMResult:
        started = time.perf_counter()
        try:
            resp = self._client.messages.parse(
                model=model, max_tokens=MAX_OUTPUT_TOKENS,
                system=[{"type": "text", "text": system, "cache_control": self._cache}],
                messages=[{"role": "user", "content": user}],
                output_format=TriageBatch, output_config={"effort": "low"})
        except ValidationError:
            return LLMResult(self.provider, model, "invalid")
        except Exception as exc:  # SDK 오류는 status_code 로 분류, 문구에서 키를 가린다
            return LLMResult(self.provider, model, "error", error=_clean(_sdk_error(exc, self._key), self._key))
        u = resp.usage
        res = LLMResult(self.provider, model, "ok", input_tokens=u.input_tokens, output_tokens=u.output_tokens,
                        cache_read=getattr(u, "cache_read_input_tokens", 0) or 0,
                        cache_write=getattr(u, "cache_creation_input_tokens", 0) or 0,
                        latency_ms=int((time.perf_counter() - started) * 1000))
        if resp.stop_reason == "refusal":
            res.status = "refusal"
            res.refusal_category = getattr(resp.stop_details, "category", None) if resp.stop_details else None
        elif resp.stop_reason == "max_tokens":
            res.status = "max_tokens"
        elif resp.parsed_output is None:
            res.status = "invalid"
        else:
            res.verdicts = _verdicts(resp.parsed_output)
        return res
