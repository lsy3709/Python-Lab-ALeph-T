"""AI(LLM) 설정 — 웹 UI 에서 저장한 값(DB)이 .env 보다 우선한다.

API 키는 SecretBox 로 암호화한 값만 저장한다. 웹 UI 설정을 지우면 .env(환경변수)로 되돌아간다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Protocol

from app.config import Settings, _has
from app.secret_box import SecretBox, SecretBoxError, mask

PROVIDERS = ("claude", "gemini", "none")
KEY_NAMES = {"claude": "claude_api_key", "gemini": "gemini_api_key"}
MODEL_NAMES = {"claude": "claude_model", "gemini": "gemini_model"}
ALL_NAMES = ("llm_provider", *KEY_NAMES.values(), *MODEL_NAMES.values())
MODEL_RE = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")
KEY_RE = re.compile(r"^\S{20,256}$")


class SettingsRepo(Protocol):
    def get_all(self) -> dict[str, str]: ...
    def put(self, name: str, value: str, is_secret: bool) -> None: ...
    def delete(self, name: str) -> None: ...


@dataclass(frozen=True)
class LLMConfig:
    provider: str
    model: str | None
    api_key: str | None = field(repr=False)
    key_source: str | None        # "ui"(웹 UI 저장) · "env"(.env·환경변수) · None
    provider_source: str          # "ui" · "env"
    problem: str | None = None    # 저장 키를 풀 수 없는 등

    @property
    def key_mask(self) -> str:
        return mask(self.api_key)

    @property
    def disabled_reason(self) -> str | None:
        """LLM 을 쓸 수 없는 이유. 쓸 수 있으면 None."""
        if self.provider == "none":
            return "LLM_PROVIDER=none"
        if self.problem:
            return self.problem
        if not self.api_key:
            return f"{self.provider} API 키 없음"
        if not self.model:
            return f"{self.provider} 모델 없음"
        return None


def _model_or_none(value: str | None) -> str | None:
    value = (value or "").strip()
    return value if value and not value.startswith("<") else None


def _env_key(settings: Settings, provider: str) -> str | None:
    secret = settings.anthropic_api_key if provider == "claude" else settings.gemini_api_key
    return secret.get_secret_value().strip() if _has(secret) else None


def _env_model(settings: Settings, provider: str) -> str | None:
    return _model_or_none(settings.claude_model if provider == "claude" else settings.gemini_model)


def effective_llm_config(settings: Settings, repo: SettingsRepo, box: SecretBox | None) -> LLMConfig:
    stored = repo.get_all()
    provider = stored.get("llm_provider") or settings.llm_provider
    provider_source = "ui" if stored.get("llm_provider") else "env"
    if provider == "none":
        return LLMConfig("none", None, None, None, provider_source)
    return _config_for(settings, stored, box, provider, provider_source)


def config_for_provider(settings: Settings, repo: SettingsRepo, box: SecretBox | None, provider: str) -> LLMConfig:
    """사용 중이 아니어도 그 공급자의 설정(연결 테스트용)."""
    return _config_for(settings, repo.get_all(), box, provider, "ui")


def provider_status(settings: Settings, repo: SettingsRepo, box: SecretBox | None) -> dict[str, dict]:
    """화면용 — 사용 중이 아닌 공급자까지 키·모델 상태를 보여 준다(교체 전에 무엇이 준비됐는지)."""
    stored = repo.get_all()
    active = stored.get("llm_provider") or settings.llm_provider
    out = {}
    for provider in KEY_NAMES:
        cfg = _config_for(settings, stored, box, provider, "ui")
        out[provider] = {"active": provider == active, "model": cfg.model, "key_mask": cfg.key_mask,
                         "key_source": cfg.key_source, "problem": cfg.problem,
                         "ready": cfg.api_key is not None and cfg.model is not None}
    return out


def _config_for(settings: Settings, stored: dict, box: SecretBox | None, provider: str,
                provider_source: str) -> LLMConfig:
    model = _model_or_none(stored.get(MODEL_NAMES[provider])) or _env_model(settings, provider)
    sealed = stored.get(KEY_NAMES[provider])
    if sealed:  # 웹 UI 저장 키가 있으면 그것만 쓴다 — 풀 수 없다고 .env 로 조용히 넘어가지 않는다
        if box is None:
            return LLMConfig(provider, model, None, "ui", provider_source,
                             problem="웹 UI 에 저장된 키를 풀 열쇠가 없음 — .env 의 SETTINGS_SECRET_KEY 확인")
        try:
            return LLMConfig(provider, model, box.open(sealed), "ui", provider_source)
        except SecretBoxError as exc:
            return LLMConfig(provider, model, None, "ui", provider_source, problem=str(exc))
    key = _env_key(settings, provider)
    return LLMConfig(provider, model, key, "env" if key else None, provider_source)


def save_llm(repo: SettingsRepo, box: SecretBox | None, *, provider: str, model: str, api_key: str,
             activate: bool = True) -> None:
    """입력을 모두 검증한 뒤에만 저장한다. 키를 비워 두면 기존 저장 키를 유지한다.
    activate=False 면 키·모델만 저장하고 사용 중인 공급자는 바꾸지 않는다(미리 넣어 두기)."""
    model, api_key = (model or "").strip(), (api_key or "").strip()
    if provider not in PROVIDERS:
        raise ValueError("공급자는 claude · gemini · none 중 하나")
    if model and (not MODEL_RE.match(model) or ".." in model):
        raise ValueError("모델 ID 는 영문·숫자·. _ / - 만(128자 이하)")
    if api_key:
        if provider == "none":
            raise ValueError("none 에는 키를 저장하지 않습니다")
        if not KEY_RE.match(api_key):
            raise ValueError("API 키는 공백 없이 20~256자")
        if box is None:
            raise ValueError("SETTINGS_SECRET_KEY 가 없어 키를 저장할 수 없습니다 — .env 에 먼저 설정하세요")
    if activate or provider == "none":
        repo.put("llm_provider", provider, False)
    if provider != "none" and model:
        repo.put(MODEL_NAMES[provider], model, False)
    if api_key:
        repo.put(KEY_NAMES[provider], box.seal(api_key), True)


def set_active_provider(repo: SettingsRepo, provider: str) -> None:
    """사용할 AI 만 바꾼다(저장된 키·모델은 그대로)."""
    if provider not in PROVIDERS:
        raise ValueError("공급자는 claude · gemini · none 중 하나")
    repo.put("llm_provider", provider, False)


def clear_provider_key(repo: SettingsRepo, provider: str) -> None:
    """한 공급자의 웹 UI 저장 키만 지운다(그 공급자는 .env 키로 돌아간다)."""
    if provider not in KEY_NAMES:
        raise ValueError("키를 지울 공급자는 claude · gemini 중 하나")
    repo.delete(KEY_NAMES[provider])


def reset_llm(repo: SettingsRepo) -> None:
    """웹 UI 에서 저장한 AI 설정을 모두 지운다 → .env(환경변수) 값으로 되돌아간다."""
    for name in ALL_NAMES:
        repo.delete(name)
