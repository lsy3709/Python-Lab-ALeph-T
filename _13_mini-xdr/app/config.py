"""mini-xdr 설정 — 환경변수(.env)에서 읽는다.

API 키가 없거나 자리표시자(<YOUR_API_KEY>)면 LLM 을 끄고 규칙 판정으로 동작한다
(키 없는 학생도 수업 참여 가능 — [186] 설계 원칙 4).
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


def _has(secret: SecretStr | None) -> bool:
    if secret is None:
        return False
    value = secret.get_secret_value().strip()
    return bool(value) and not value.startswith("<")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # LLM
    llm_provider: Literal["claude", "gemini", "none"] = "claude"
    anthropic_api_key: SecretStr | None = None
    claude_model: str = "claude-haiku-5-5"
    claude_escalate_model: str = "claude-sonnet-5-5"
    gemini_api_key: SecretStr | None = None
    gemini_model: str | None = None
    max_daily_llm_calls: int = Field(200, ge=0)
    prompt_cache_ttl: Literal["5m", "1h"] = "5m"

    # 수집·상관
    graylog_url: str = "http://localhost:9000"
    graylog_token: SecretStr | None = None
    graylog_user: str | None = None
    graylog_password: SecretStr | None = None
    graylog_query: str = "_exists_:wazuh_rule_id OR _exists_:rule"
    poll_interval_sec: int = Field(30, ge=5)
    collect_page_size: int = Field(500, ge=10, le=1000)
    collect_backfill_min: int = Field(1440, ge=1)
    collect_overlap_sec: int = Field(60, ge=0)
    collect_max_pages: int = Field(50, ge=1)
    correlation_window_min: int = Field(10, ge=1)

    # 저장소
    mysql_host: str = "localhost"
    mysql_port: int = 3306
    mysql_user: str = "xdr"
    mysql_password: SecretStr | None = None
    mysql_db: str = "mini_xdr"

    # 대응
    n8n_webhook_url: str | None = None

    # 콘솔(읽기 전용 웹) — 기본은 이 PC 에서만 접속
    console_host: str = "127.0.0.1"
    console_port: int = Field(8099, ge=1, le=65535)

    @property
    def llm_disabled_reason(self) -> str | None:
        """LLM 을 쓸 수 없는 이유. 쓸 수 있으면 None."""
        if self.llm_provider == "none":
            return "LLM_PROVIDER=none"
        if self.llm_provider == "claude" and not _has(self.anthropic_api_key):
            return "ANTHROPIC_API_KEY 없음"
        if self.llm_provider == "gemini":
            if not _has(self.gemini_api_key):
                return "GEMINI_API_KEY 없음"
            if not self.gemini_model:
                return "GEMINI_MODEL 없음"
        return None

    @property
    def llm_enabled(self) -> bool:
        return self.llm_disabled_reason is None

    def graylog_credentials(self) -> tuple[str | None, str | None, str | None]:
        """(토큰, 계정, 비밀번호) — 토큰이 있으면 토큰만. 자리표시자는 없는 것으로 본다."""
        if _has(self.graylog_token):
            return self.graylog_token.get_secret_value(), None, None
        if self.graylog_user and _has(self.graylog_password):
            return None, self.graylog_user, self.graylog_password.get_secret_value()
        return None, None, None
