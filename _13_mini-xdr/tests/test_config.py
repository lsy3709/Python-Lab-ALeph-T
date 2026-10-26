"""설정 로더 — 키가 없거나 자리표시자면 LLM 을 끄고 규칙 판정으로 동작해야 한다."""
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings

FAKE_KEY = "sk-" + "ant-" + "t" * 32
EXAMPLE = Path(__file__).resolve().parent.parent / ".env.example"


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """개발 PC 의 실제 환경변수가 테스트에 섞이지 않게 한다."""
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)


def make(**values) -> Settings:
    return Settings(_env_file=None, **values)


def test_defaults():
    s = make()
    assert s.llm_provider == "claude"
    assert s.claude_model == "claude-haiku-5-5"
    assert s.claude_escalate_model == "claude-sonnet-5-5"
    assert s.max_daily_llm_calls == 200
    assert s.prompt_cache_ttl == "5m"
    assert s.mysql_db == "mini_xdr"


def test_no_key_disables_llm():
    s = make()
    assert s.llm_enabled is False
    assert s.llm_disabled_reason == "ANTHROPIC_API_KEY 없음"


def test_placeholder_key_counts_as_missing():
    assert make(anthropic_api_key="<YOUR_API_KEY>").llm_enabled is False


def test_claude_with_key_enables_llm():
    s = make(anthropic_api_key=FAKE_KEY)
    assert s.llm_enabled is True
    assert s.llm_disabled_reason is None


def test_provider_none_disables_llm_even_with_key():
    s = make(llm_provider="none", anthropic_api_key=FAKE_KEY)
    assert s.llm_disabled_reason == "LLM_PROVIDER=none"


def test_gemini_needs_key_and_model():
    assert make(llm_provider="gemini").llm_disabled_reason == "GEMINI_API_KEY 없음"
    assert make(llm_provider="gemini", gemini_api_key="g" * 39).llm_disabled_reason == "GEMINI_MODEL 없음"
    assert make(llm_provider="gemini", gemini_api_key="g" * 39, gemini_model="m").llm_enabled is True


def test_invalid_provider_rejected():
    with pytest.raises(ValidationError):
        make(llm_provider="openai")


def test_poll_interval_lower_bound():
    with pytest.raises(ValidationError):
        make(poll_interval_sec=1)


def test_secrets_never_appear_in_repr():
    s = make(anthropic_api_key=FAKE_KEY, mysql_password="pw-should-hide")
    assert FAKE_KEY not in repr(s) and FAKE_KEY not in str(s)
    assert "pw-should-hide" not in repr(s)


def test_reads_environment_variables(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "none")
    monkeypatch.setenv("POLL_INTERVAL_SEC", "60")
    s = make()
    assert s.llm_provider == "none" and s.poll_interval_sec == 60


def test_env_example_loads_in_rules_mode():
    s = Settings(_env_file=EXAMPLE)
    assert s.llm_provider == "claude"
    assert s.llm_enabled is False  # 자리표시자뿐이므로


def test_env_example_matches_settings_fields():
    keys = {
        line.split("=", 1)[0].strip().lower()
        for line in EXAMPLE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }
    assert keys == set(Settings.model_fields)
