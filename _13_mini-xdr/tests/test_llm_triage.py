"""LLM 어댑터 — Gemini(REST 모의)·Claude(가짜 SDK 클라이언트): 성공·스키마 오류·거절·최대 토큰·HTTP 오류·캐시 토큰."""
import json
from types import SimpleNamespace

import httpx

from app.llm_triage import ClaudeTriager, GeminiTriager
from app.triage_schema import TriageBatch

KEY = "AIza" + "TRIAGEFAKE" * 3 + "k9"  # 테스트용 가짜 키
SYSTEM, USER = "고정 앞부분", "카드"


def verdict(ref, **kw):
    v = {"ref": ref, "priority": "P3", "verdict": "needs_review", "false_positive_likelihood": 0.3,
         "reasoning_ko": "근거", "recommended_playbook": "monitor", "confidence": 0.8}
    v.update(kw)
    return v


def gemini(calls, *, status=200, body=None):
    def handler(request):
        calls.append(request)
        return httpx.Response(status, json=body)
    return GeminiTriager(KEY, transport=httpx.MockTransport(handler))


def gemini_ok(results, finish="STOP", usage=None):
    return {"candidates": [{"content": {"parts": [{"text": json.dumps({"results": results})}]}, "finishReason": finish}],
            "usageMetadata": usage or {"promptTokenCount": 1500, "cachedContentTokenCount": 1200,
                                       "candidatesTokenCount": 90, "thoughtsTokenCount": 10}}


def test_gemini_success_parses_batch_and_cache_tokens():
    calls = []
    r = gemini(calls, body=gemini_ok([verdict("INC-1", confidence=1.4), verdict("INC-2", priority="P2")])) \
        .triage(SYSTEM, USER, "gemini-3.5-flash-lite")
    assert r.status == "ok" and set(r.verdicts) == {"INC-1", "INC-2"} and r.verdicts["INC-1"].confidence == 1.0
    assert (r.input_tokens, r.cache_read, r.output_tokens) == (300, 1200, 100)
    req = calls[0]
    body = json.loads(req.content)
    assert req.url.path.endswith("/models/gemini-3.5-flash-lite:generateContent") and KEY not in str(req.url)
    assert req.headers["x-goog-api-key"] == KEY
    assert body["systemInstruction"]["parts"][0]["text"] == SYSTEM
    assert body["generationConfig"]["responseMimeType"] == "application/json" and "responseSchema" in body["generationConfig"]


def test_gemini_invalid_json_max_tokens_and_safety():
    bad = {"candidates": [{"content": {"parts": [{"text": "{not json"}]}, "finishReason": "STOP"}]}
    assert gemini([], body=bad).triage(SYSTEM, USER, "m").status == "invalid"
    assert gemini([], body=gemini_ok([], finish="MAX_TOKENS")).triage(SYSTEM, USER, "m").status == "max_tokens"
    safety = gemini([], body=gemini_ok([], finish="SAFETY")).triage(SYSTEM, USER, "m")
    assert safety.status == "refusal" and safety.refusal_category == "SAFETY"
    blocked = gemini([], body={"promptFeedback": {"blockReason": "PROHIBITED_CONTENT"}}).triage(SYSTEM, USER, "m")
    assert blocked.status == "refusal" and blocked.refusal_category == "PROHIBITED_CONTENT"


def test_gemini_http_error_hides_key():
    r = gemini([], status=429, body={"error": {"message": f"quota exceeded for {KEY}"}}).triage(SYSTEM, USER, "m")
    assert r.status == "error" and "HTTP 429" in r.error and KEY not in r.error


class FakeMessages:
    def __init__(self, response=None, error=None):
        self.response, self.error, self.kwargs = response, error, None

    def parse(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise self.error
        return self.response


def claude_response(stop_reason="end_turn", parsed=True, category=None):
    batch = TriageBatch.model_validate({"results": [verdict("INC-1")]}) if parsed else None
    return SimpleNamespace(parsed_output=batch, stop_reason=stop_reason,
                           stop_details=SimpleNamespace(category=category) if category else None,
                           usage=SimpleNamespace(input_tokens=210, output_tokens=150, cache_read_input_tokens=4000,
                                                 cache_creation_input_tokens=0))


def claude(messages, ttl="5m"):
    return ClaudeTriager(KEY, client=SimpleNamespace(messages=messages), cache_ttl=ttl)


def test_claude_success_uses_parse_cache_control_and_low_effort():
    fm = FakeMessages(claude_response())
    r = claude(fm, ttl="1h").triage(SYSTEM, USER, "claude-haiku-5-5")
    assert r.status == "ok" and r.verdicts["INC-1"].priority == "P3"
    assert (r.input_tokens, r.output_tokens, r.cache_read, r.cache_write) == (210, 150, 4000, 0)
    kw = fm.kwargs
    assert kw["model"] == "claude-haiku-5-5" and kw["output_format"] is TriageBatch
    assert kw["system"] == [{"type": "text", "text": SYSTEM, "cache_control": {"type": "ephemeral", "ttl": "1h"}}]
    assert kw["output_config"] == {"effort": "low"} and "temperature" not in kw


def test_claude_default_ttl_has_no_ttl_field():
    fm = FakeMessages(claude_response())
    claude(fm).triage(SYSTEM, USER, "claude-haiku-5-5")
    assert fm.kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}


def test_claude_refusal_max_tokens_invalid_and_errors():
    r = claude(FakeMessages(claude_response("refusal", parsed=False, category="cyber"))).triage(SYSTEM, USER, "m")
    assert r.status == "refusal" and r.refusal_category == "cyber"
    assert claude(FakeMessages(claude_response("max_tokens", parsed=False))).triage(SYSTEM, USER, "m").status == "max_tokens"
    assert claude(FakeMessages(claude_response(parsed=False))).triage(SYSTEM, USER, "m").status == "invalid"

    class AuthError(Exception):
        status_code = 401

    r = claude(FakeMessages(error=AuthError(f"bad {KEY}"))).triage(SYSTEM, USER, "m")
    assert r.status == "error" and "인증 실패" in r.error and KEY not in r.error


def test_estimate_call_cost_includes_cache_reads_and_writes():
    from app.llm_triage import LLMResult, estimate_call_cost
    r = LLMResult("claude", "claude-haiku-5-5", "ok", input_tokens=1000, output_tokens=200, cache_read=4000)
    assert abs(estimate_call_cost(r) - 0.00024) < 1e-12           # (1000×0.10 + 4000×0.01 + 200×0.50) / 1M
    w = LLMResult("claude", "claude-haiku-5-5", "ok", cache_write=4000)
    assert abs(estimate_call_cost(w, "1h") - 0.0008) < 1e-12      # 1시간 TTL 쓰기는 입력가의 2배
    assert estimate_call_cost(LLMResult("gemini", "gemini-3.5-flash-lite", "ok", input_tokens=9999)) == 0.0
