"""AI 연결 테스트 — ① 모델 목록(토큰 0) ② 샘플 호출(짧은 고정 문장, 토큰 소량).

- 모델 ID 는 추측하지 않는다: 공급자 API 가 알려 준 목록에서 고른다.
- Gemini 키는 URL(?key=)이 아니라 헤더(x-goog-api-key)로 보낸다 → 로그·예외 문구에 남지 않는다.
- Claude 는 공식 SDK(anthropic)를 쓴다. 샘플링 파라미터(temperature 등)는 2026-10-21 부터 400 이라 넣지 않는다.
- 오류 문구에서는 키 문자열을 지우고(가림) 200자로 자른다.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

import httpx

GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta"
SAMPLE_PROMPT = "보안 관제 콘솔 연결 테스트입니다. '연결 확인' 이라고만 답하세요."
MODEL_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
# 100만 토큰당 (입력, 출력) USD — claude-api 레퍼런스로 확인한 값. Gemini 는 단가를 넣지 않았다(0).
CLAUDE_PRICES = {"claude-haiku-5-5": (0.10, 0.50), "claude-sonnet-5-5": (2.0, 10.0)}
_SDK_ERRORS = {401: "인증 실패(키 확인)", 403: "권한 없음", 404: "모델 없음", 429: "사용량 한도 초과"}


@dataclass
class ProbeResult:
    provider: str
    ok: bool
    step: str                      # "모델 목록" · "샘플 호출"
    models: list[str] = field(default_factory=list)
    model: str | None = None
    reply: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    latency_ms: int | None = None
    error: str | None = None


def _clean(text: str | None, secret: str) -> str:
    text = (text or "").replace(secret, "[가림]") if secret else (text or "")
    return re.sub(r"[\x00-\x1f\x7f]+", " ", text).strip()[:200]


def estimate_cost(provider: str, model: str | None, input_tokens: int, output_tokens: int) -> float:
    price = CLAUDE_PRICES.get(model or "") if provider == "claude" else None
    if not price:
        return 0.0
    return (input_tokens * price[0] + output_tokens * price[1]) / 1_000_000


def _gemini_error(r: httpx.Response, key: str) -> str:
    try:
        message = r.json()["error"]["message"]
    except (ValueError, KeyError, TypeError):
        message = ""
    return _clean(f"HTTP {r.status_code}: {message}" if message else f"HTTP {r.status_code}", key)


def probe_gemini(api_key: str, model: str | None = None, *, transport: httpx.BaseTransport | None = None,
                 timeout: float = 15.0) -> ProbeResult:
    with httpx.Client(base_url=GEMINI_BASE, headers={"x-goog-api-key": api_key}, timeout=timeout,
                      transport=transport) as client:
        try:
            r = client.get("/models", params={"pageSize": 1000})
        except httpx.HTTPError as exc:
            return ProbeResult("gemini", False, "모델 목록", error=f"연결 실패({type(exc).__name__})")
        if r.status_code != 200:
            return ProbeResult("gemini", False, "모델 목록", error=_gemini_error(r, api_key))
        models = sorted(m["name"].removeprefix("models/") for m in r.json().get("models", [])
                        if "generateContent" in m.get("supportedGenerationMethods", []))
        if not model:
            return ProbeResult("gemini", True, "모델 목록", models=models)
        name = model.removeprefix("models/")
        if not MODEL_ID_RE.match(name):
            return ProbeResult("gemini", False, "샘플 호출", models=models, error="모델 ID 형식이 올바르지 않습니다")
        body = {"contents": [{"role": "user", "parts": [{"text": SAMPLE_PROMPT}]}],
                "generationConfig": {"maxOutputTokens": 256}}
        started = time.perf_counter()
        try:
            r = client.post(f"/models/{name}:generateContent", json=body)
        except httpx.HTTPError as exc:
            return ProbeResult("gemini", False, "샘플 호출", models=models, model=name,
                               error=f"연결 실패({type(exc).__name__})")
        latency = int((time.perf_counter() - started) * 1000)
        if r.status_code != 200:
            return ProbeResult("gemini", False, "샘플 호출", models=models, model=name, latency_ms=latency,
                               error=_gemini_error(r, api_key))
        data = r.json()
        candidate = (data.get("candidates") or [{}])[0]
        text = "".join(p.get("text", "") for p in candidate.get("content", {}).get("parts", []))
        usage = data.get("usageMetadata", {})
        reply = _clean(text, api_key) or f"(빈 응답 — finishReason {candidate.get('finishReason', '?')})"
        return ProbeResult("gemini", True, "샘플 호출", models=models, model=name, reply=reply, latency_ms=latency,
                           input_tokens=usage.get("promptTokenCount", 0),
                           output_tokens=usage.get("candidatesTokenCount", 0) + usage.get("thoughtsTokenCount", 0))


def _sdk_error(exc: Exception, key: str) -> str:
    code = getattr(exc, "status_code", None)
    if code:
        return f"{_SDK_ERRORS.get(code, '요청 실패')} (HTTP {code})"
    return _clean(f"연결 실패({type(exc).__name__})", key)


def probe_claude(api_key: str, model: str | None = None, *, client=None, timeout: float = 15.0) -> ProbeResult:
    if client is None:
        import anthropic  # 실제 호출 때만 불러온다

        client = anthropic.Anthropic(api_key=api_key, timeout=timeout, max_retries=0)
    try:
        models = sorted(m.id for m in client.models.list())  # 페이지 객체를 그대로 순회(자동 페이지 넘김)
    except Exception as exc:  # SDK 오류는 status_code 로 분류
        return ProbeResult("claude", False, "모델 목록", error=_sdk_error(exc, api_key))
    if not model:
        return ProbeResult("claude", True, "모델 목록", models=models)
    if not MODEL_ID_RE.match(model):
        return ProbeResult("claude", False, "샘플 호출", models=models, error="모델 ID 형식이 올바르지 않습니다")
    started = time.perf_counter()
    try:
        resp = client.messages.create(model=model, max_tokens=32,
                                      messages=[{"role": "user", "content": SAMPLE_PROMPT}])
    except Exception as exc:
        return ProbeResult("claude", False, "샘플 호출", models=models, model=model, error=_sdk_error(exc, api_key))
    latency = int((time.perf_counter() - started) * 1000)
    text = "".join(b.text for b in resp.content if getattr(b, "type", "") == "text")
    reply = _clean(text, api_key) or f"(빈 응답 — stop_reason {resp.stop_reason})"
    return ProbeResult("claude", True, "샘플 호출", models=models, model=model, reply=reply, latency_ms=latency,
                       input_tokens=resp.usage.input_tokens, output_tokens=resp.usage.output_tokens)
