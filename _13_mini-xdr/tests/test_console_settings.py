"""콘솔 AI 설정 화면 — 키 비노출·CSRF·Origin·Host·저장/되돌리기/연결 테스트 흐름."""
import re
from contextlib import contextmanager

import pytest

from app.config import Settings
from app.console import create_app
from app.console.settings_views import SettingsDeps
from app.llm_probe import ProbeResult
from app.secret_box import SecretBox
from tests.test_console import FakeQueries
from tests.test_llm_settings import FakeRepo

FAKE = "AIza" + "CONSOLEFAKE" * 3 + "9z8y"  # 테스트용 가짜 키
ORIGIN = {"Origin": "http://127.0.0.1:8099"}


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)


class Harness:
    def __init__(self, *, box=True, env=None):
        self.repo, self.calls, self.recorded = FakeRepo(), [], []
        self.box = SecretBox(SecretBox.generate_key()) if box else None

        def fake_probe(key, model=None, **kw):
            self.calls.append((key, model))
            if model:
                return ProbeResult("gemini", True, "샘플 호출", models=["gem-flash", "gem-pro"], model=model,
                                   reply="연결 확인", input_tokens=21, output_tokens=8, latency_ms=300)
            return ProbeResult("gemini", True, "모델 목록", models=["gem-flash", "gem-pro"])

        @contextmanager
        def open_conn():
            yield object()

        @contextmanager
        def queries():
            yield FakeQueries()

        deps = SettingsDeps(env=env or Settings(_env_file=None), open_conn=open_conn, box=self.box,
                            probes={"gemini": fake_probe, "claude": fake_probe},
                            repo_factory=lambda conn: self.repo,
                            recorder=lambda conn, r: self.recorded.append(r))
        self.client = create_app(queries, deps).test_client()

    def token(self):
        html = self.client.get("/settings").get_data(as_text=True)
        return re.search(r'name="csrf" value="([^"]+)"', html).group(1)

    def post(self, path, data):
        return self.client.post(path, data=data, headers=ORIGIN)


def test_settings_page_shows_status_and_password_field():
    h = Harness()
    html = h.client.get("/settings").get_data(as_text=True)
    assert 'type="password"' in html and 'autocomplete="off"' in html and "API 키 없음" in html
    assert 'href="/settings"' in h.client.get("/").get_data(as_text=True)  # 상단 메뉴


def test_save_requires_csrf_token():
    h = Harness()
    r = h.post("/settings/llm", {"provider": "gemini", "model": "gem-flash", "api_key": FAKE})
    assert r.status_code == 400 and h.repo.rows == {}


def test_save_rejects_foreign_origin():
    h = Harness()
    t = h.token()
    r = h.client.post("/settings/llm", data={"csrf": t, "provider": "gemini", "model": "gem-flash", "api_key": FAKE},
                      headers={"Origin": "https://evil.example"})
    assert r.status_code == 403 and h.repo.rows == {}


def test_foreign_host_header_is_rejected():  # DNS 리바인딩 방지
    h = Harness()
    assert h.client.get("/settings", headers={"Host": "evil.example:8099"}).status_code == 400
    assert h.client.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert h.client.get("/settings", headers={"Host": "127.0.0.1:8099"}).status_code == 200


def test_host_and_origin_edge_cases():
    from app.console.security import host_allowed, origin_allowed
    assert all(host_allowed(h) for h in ("127.0.0.1:8099", "localhost", "LOCALHOST:8099", "[::1]:8099"))
    assert not any(host_allowed(h) for h in ("127.0.0.1.evil.com", "localhost.evil.com:8099", "", "evil:80:1"))
    assert origin_allowed(None) and origin_allowed("http://localhost:8099")
    assert not origin_allowed("null") and not origin_allowed("http://127.0.0.1.evil.com")


def test_save_then_page_shows_mask_never_the_key():
    h = Harness()
    t = h.token()
    r = h.post("/settings/llm", {"csrf": t, "provider": "gemini", "model": "gem-flash", "api_key": FAKE})
    assert r.status_code == 303
    assert h.repo.rows["gemini_api_key"][0].startswith("enc:v1:")
    html = h.client.get("/settings?msg=saved").get_data(as_text=True)
    assert FAKE not in html and "AIza…9z8y" in html and "웹 UI 저장" in html and "저장했습니다" in html


def test_invalid_input_shows_error_without_echoing_key():
    h = Harness()
    t = h.token()
    r = h.post("/settings/llm", {"csrf": t, "provider": "gemini", "model": "gem-flash", "api_key": FAKE + " x"})
    html = r.get_data(as_text=True)
    assert r.status_code == 400 and "공백 없이" in html and FAKE not in html and h.repo.rows == {}


def test_save_blocked_without_secret_box():
    h = Harness(box=False)
    t = h.token()
    assert "SETTINGS_SECRET_KEY" in h.client.get("/settings").get_data(as_text=True)
    r = h.post("/settings/llm", {"csrf": t, "provider": "gemini", "model": "gem-flash", "api_key": FAKE})
    assert r.status_code == 400 and h.repo.rows == {}


def test_connection_test_lists_models_then_sample_records_usage():
    h = Harness()
    t = h.token()
    h.post("/settings/llm", {"csrf": t, "provider": "gemini", "model": "", "api_key": FAKE})
    html = h.post("/settings/llm/test", {"csrf": t}).get_data(as_text=True)
    assert h.calls[-1] == (FAKE, None) and "gem-pro" in html and "모델 2개" in html and h.recorded == []
    html = h.post("/settings/llm/test", {"csrf": t, "model": "gem-flash", "sample": "1"}).get_data(as_text=True)
    assert h.calls[-1] == (FAKE, "gem-flash") and "연결 확인" in html and "21" in html
    assert len(h.recorded) == 1 and FAKE not in html


def test_connection_test_without_key_explains():
    h = Harness(env=Settings(_env_file=None, llm_provider="gemini"))
    t = h.token()
    html = h.post("/settings/llm/test", {"csrf": t}).get_data(as_text=True)
    assert "API 키 없음" in html and h.calls == []


def test_reset_returns_to_env():
    h = Harness(env=Settings(_env_file=None, llm_provider="gemini", gemini_api_key="AIza" + "ENVONLY" * 5 + "kkkk"))
    t = h.token()
    h.post("/settings/llm", {"csrf": t, "provider": "gemini", "model": "gem-flash", "api_key": FAKE})
    r = h.post("/settings/llm/reset", {"csrf": t})
    assert r.status_code == 303 and h.repo.rows == {}
    html = h.client.get("/settings").get_data(as_text=True)
    assert ".env" in html and "AIza…kkkk" in html
