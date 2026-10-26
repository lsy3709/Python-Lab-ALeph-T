"""연결 테스트 — Gemini(REST 모의)·Claude(가짜 SDK 클라이언트). 키는 헤더로만, 오류 문구에 키 미노출."""
import json
from types import SimpleNamespace

import httpx
import pytest

from app.llm_probe import SAMPLE_PROMPT, estimate_cost, probe_claude, probe_gemini

KEY = "AIza" + "FAKEPROBE" * 4 + "zz"  # 테스트용 가짜 키


def gemini_transport(calls, *, fail_status=None):
    def handler(request):
        calls.append(request)
        if fail_status:  # 일부러 오류 문구에 키를 섞어 가림 처리를 확인
            return httpx.Response(fail_status, json={"error": {"code": fail_status, "status": "INVALID_ARGUMENT",
                                                              "message": f"API key not valid. {KEY}"}})
        if request.method == "GET":
            return httpx.Response(200, json={"models": [
                {"name": "models/gem-flash", "supportedGenerationMethods": ["generateContent", "countTokens"]},
                {"name": "models/gem-embed", "supportedGenerationMethods": ["embedContent"]},
                {"name": "models/gem-pro", "supportedGenerationMethods": ["generateContent"]}]})
        return httpx.Response(200, json={
            "candidates": [{"content": {"parts": [{"text": "연결 확인\n"}]}, "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": 21, "candidatesTokenCount": 3, "thoughtsTokenCount": 5}})
    return httpx.MockTransport(handler)


def test_gemini_lists_generate_models_with_key_in_header_only():
    calls = []
    r = probe_gemini(KEY, transport=gemini_transport(calls))
    assert r.ok and r.step == "모델 목록" and r.models == ["gem-flash", "gem-pro"]
    assert calls[0].headers["x-goog-api-key"] == KEY and KEY not in str(calls[0].url)


def test_gemini_sample_call_reports_reply_and_tokens():
    calls = []
    r = probe_gemini(KEY, "models/gem-flash", transport=gemini_transport(calls))
    assert r.ok and r.step == "샘플 호출" and r.model == "gem-flash" and r.reply == "연결 확인"
    assert (r.input_tokens, r.output_tokens) == (21, 8) and r.latency_ms is not None
    assert calls[1].url.path.endswith("/models/gem-flash:generateContent")
    assert json.loads(calls[1].content)["contents"][0]["parts"][0]["text"] == SAMPLE_PROMPT


def test_gemini_invalid_key_message_hides_key():
    r = probe_gemini(KEY, transport=gemini_transport([], fail_status=400))
    assert not r.ok and "HTTP 400" in r.error and "API key not valid" in r.error and KEY not in r.error


def test_gemini_network_error():
    def boom(request):
        raise httpx.ConnectError("dns fail")

    r = probe_gemini(KEY, transport=httpx.MockTransport(boom))
    assert not r.ok and "연결 실패" in r.error


def test_gemini_rejects_unsafe_model_id():
    r = probe_gemini(KEY, "../v1/x", transport=gemini_transport([]))
    assert not r.ok and "모델 ID" in r.error


class FakeClaude:
    def __init__(self, fail=None):
        self.fail, self.created = fail, None
        self.models = SimpleNamespace(list=self._list)
        self.messages = SimpleNamespace(create=self._create)

    def _list(self):
        if self.fail:
            raise self.fail
        return [SimpleNamespace(id="claude-sonnet-5-5"), SimpleNamespace(id="claude-haiku-5-5")]

    def _create(self, **kw):
        self.created = kw
        return SimpleNamespace(content=[SimpleNamespace(type="text", text="연결 확인")], stop_reason="end_turn",
                               usage=SimpleNamespace(input_tokens=30, output_tokens=4))


class FakeStatusError(Exception):
    status_code = 401


def test_claude_models_and_sample():
    fc = FakeClaude()
    r = probe_claude(KEY, "claude-haiku-5-5", client=fc)
    assert r.ok and r.models == ["claude-haiku-5-5", "claude-sonnet-5-5"] and r.reply == "연결 확인"
    assert (r.input_tokens, r.output_tokens) == (30, 4)
    assert fc.created["model"] == "claude-haiku-5-5" and fc.created["max_tokens"] <= 64
    assert "temperature" not in fc.created  # 2026-10-21 부터 샘플링 파라미터는 400


def test_claude_auth_error_is_classified_without_key():
    r = probe_claude(KEY, client=FakeClaude(fail=FakeStatusError(f"bad key {KEY}")))
    assert not r.ok and "인증 실패" in r.error and KEY not in r.error


def test_estimate_cost():
    assert estimate_cost("claude", "claude-haiku-5-5", 1_000_000, 1_000_000) == pytest.approx(0.60)
    assert estimate_cost("claude", "claude-sonnet-5-5", 1000, 100) == pytest.approx(0.003)
    assert estimate_cost("gemini", "gem-flash", 1000, 100) == 0
