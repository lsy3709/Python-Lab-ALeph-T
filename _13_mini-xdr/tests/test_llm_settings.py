"""AI 설정 — 웹 UI 저장값(DB)이 .env 보다 우선, 키는 암호문으로만 저장, 입력 검증, 되돌리기."""
import pytest

from app.config import Settings
from app.llm_settings import effective_llm_config, reset_llm, save_llm
from app.secret_box import SecretBox

FAKE_GEMINI = "AIza" + "FAKEGEMINI" * 3 + "abcd"   # 테스트용 가짜 키
FAKE_CLAUDE = "sk-" + "fakeclaude" * 3 + "wxyz"    # 비밀 스캔 패턴(sk-ant-)에 걸리지 않게 조립


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)


class FakeRepo:
    def __init__(self):
        self.rows = {}

    def get_all(self):
        return {k: v for k, (v, _) in self.rows.items()}

    def put(self, name, value, is_secret):
        self.rows[name] = (value, is_secret)

    def delete(self, name):
        self.rows.pop(name, None)


def env(**kw):
    return Settings(_env_file=None, **kw)


@pytest.fixture
def box():
    return SecretBox(SecretBox.generate_key())


def test_env_only_config(box):
    cfg = effective_llm_config(env(llm_provider="gemini", gemini_api_key=FAKE_GEMINI, gemini_model="m-1"),
                               FakeRepo(), box)
    assert (cfg.provider, cfg.model, cfg.key_source, cfg.provider_source) == ("gemini", "m-1", "env", "env")
    assert cfg.api_key == FAKE_GEMINI and cfg.key_mask == "AIza…abcd" and cfg.disabled_reason is None


def test_placeholders_count_as_missing(box):
    cfg = effective_llm_config(env(llm_provider="gemini", gemini_api_key="<YOUR_GEMINI_API_KEY>",
                                   gemini_model="<YOUR_GEMINI_MODEL_ID>"), FakeRepo(), box)
    assert cfg.api_key is None and cfg.model is None
    assert cfg.disabled_reason == "gemini API 키 없음"


def test_ui_values_override_env_and_key_is_stored_encrypted(box):
    repo = FakeRepo()
    save_llm(repo, box, provider="gemini", model="models/m-2", api_key=FAKE_GEMINI)
    stored, is_secret = repo.rows["gemini_api_key"]
    assert is_secret and stored.startswith("enc:v1:") and FAKE_GEMINI not in stored
    cfg = effective_llm_config(env(llm_provider="claude"), repo, box)
    assert (cfg.provider, cfg.model, cfg.key_source, cfg.provider_source) == ("gemini", "models/m-2", "ui", "ui")
    assert cfg.api_key == FAKE_GEMINI


def test_saving_without_key_keeps_stored_key_and_changes_model(box):
    repo = FakeRepo()
    save_llm(repo, box, provider="gemini", model="m-1", api_key=FAKE_GEMINI)
    save_llm(repo, box, provider="gemini", model="m-9", api_key="")
    cfg = effective_llm_config(env(), repo, box)
    assert cfg.model == "m-9" and cfg.api_key == FAKE_GEMINI


def test_reset_returns_to_env(box):
    repo = FakeRepo()
    save_llm(repo, box, provider="gemini", model="m-1", api_key=FAKE_GEMINI)
    reset_llm(repo)
    assert repo.rows == {}
    cfg = effective_llm_config(env(llm_provider="claude", anthropic_api_key=FAKE_CLAUDE), repo, box)
    assert (cfg.provider, cfg.key_source, cfg.model) == ("claude", "env", "claude-haiku-5-5")


def test_undecryptable_ui_key_is_reported_not_silently_replaced(box):
    repo = FakeRepo()
    save_llm(repo, box, provider="gemini", model="m-1", api_key=FAKE_GEMINI)
    other = SecretBox(SecretBox.generate_key())
    cfg = effective_llm_config(env(gemini_api_key="AIza" + "ENVKEY" * 6), repo, other)
    assert cfg.api_key is None and cfg.key_source == "ui"
    assert "SETTINGS_SECRET_KEY" in cfg.disabled_reason
    assert "SETTINGS_SECRET_KEY" in effective_llm_config(env(), repo, None).disabled_reason


def test_provider_none_disables(box):
    repo = FakeRepo()
    save_llm(repo, box, provider="none", model="", api_key="")
    cfg = effective_llm_config(env(gemini_api_key=FAKE_GEMINI), repo, box)
    assert cfg.provider == "none" and cfg.disabled_reason == "LLM_PROVIDER=none"


@pytest.mark.parametrize("kw", [
    {"provider": "openai", "model": "x", "api_key": ""},                        # 공급자 화이트리스트
    {"provider": "gemini", "model": "../../etc", "api_key": ""},                 # 경로 문자
    {"provider": "gemini", "model": "m<script>", "api_key": ""},
    {"provider": "gemini", "model": "m", "api_key": "short"},                    # 너무 짧은 키
    {"provider": "gemini", "model": "m", "api_key": FAKE_GEMINI[:10] + " " + FAKE_GEMINI[10:]},  # 공백
])
def test_invalid_input_rejected(box, kw):
    repo = FakeRepo()
    with pytest.raises(ValueError):
        save_llm(repo, box, **kw)
    assert repo.rows == {}


def test_saving_key_without_secret_box_is_refused():
    repo = FakeRepo()
    with pytest.raises(ValueError, match="SETTINGS_SECRET_KEY"):
        save_llm(repo, None, provider="gemini", model="m", api_key=FAKE_GEMINI)
    assert repo.rows == {}


def test_repr_never_shows_key(box):
    cfg = effective_llm_config(env(llm_provider="gemini", gemini_api_key=FAKE_GEMINI, gemini_model="m"),
                               FakeRepo(), box)
    assert FAKE_GEMINI not in repr(cfg)
