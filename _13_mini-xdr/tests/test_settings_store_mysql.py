"""설정 저장소 — 실제 스키마에서 app_settings 왕복과 연결 테스트 사용 기록(llm_calls)을 확인한다."""
import pytest

from app.config import Settings
from app.llm_probe import ProbeResult
from app.llm_settings import effective_llm_config, reset_llm, save_llm
from app.secret_box import SecretBox
from app.settings_store import MySQLSettingsRepo, connect_writable, record_llm_call
from tests._mysql import ROOT_PW

pytestmark = pytest.mark.integration

FAKE = "AIza" + "STOREFAKE" * 4 + "q1w2"  # 테스트용 가짜 키


@pytest.fixture
def conn(fresh_db):
    c = connect_writable(host="127.0.0.1", port=fresh_db["port"], user="root", password=ROOT_PW,
                         database=fresh_db["name"])
    yield c
    c.close()


def q(conn, sql, *args):
    with conn.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchall()


def test_settings_roundtrip_stores_only_ciphertext(conn, monkeypatch):
    for name in Settings.model_fields:
        monkeypatch.delenv(name.upper(), raising=False)
    repo, box = MySQLSettingsRepo(conn), SecretBox(SecretBox.generate_key())
    save_llm(repo, box, provider="gemini", model="gem-flash", api_key=FAKE)
    rows = dict((name, (value, secret)) for name, value, secret in
                q(conn, "SELECT name, value, is_secret FROM app_settings"))
    assert rows["llm_provider"] == ("gemini", 0) and rows["gemini_model"] == ("gem-flash", 0)
    assert rows["gemini_api_key"][1] == 1 and rows["gemini_api_key"][0].startswith("enc:v1:")
    assert FAKE not in rows["gemini_api_key"][0]
    cfg = effective_llm_config(Settings(_env_file=None), repo, box)
    assert (cfg.provider, cfg.model, cfg.api_key, cfg.key_source) == ("gemini", "gem-flash", FAKE, "ui")
    save_llm(repo, box, provider="gemini", model="gem-pro", api_key="")  # 덮어쓰기(upsert)
    assert repo.get_all()["gemini_model"] == "gem-pro"
    reset_llm(repo)
    assert q(conn, "SELECT COUNT(*) FROM app_settings")[0][0] == 0


def test_record_llm_call_for_sample_probe(conn):
    ok = ProbeResult("claude", True, "샘플 호출", model="claude-haiku-5-5", reply="연결 확인",
                     input_tokens=1000, output_tokens=100, latency_ms=420)
    bad = ProbeResult("gemini", False, "샘플 호출", model="gem-flash", error="HTTP 400")
    record_llm_call(conn, ok)
    record_llm_call(conn, bad)
    record_llm_call(conn, ProbeResult("gemini", True, "모델 목록", models=["gem-flash"]))  # 토큰 0 — 기록 안 함
    rows = q(conn, "SELECT provider, model, input_tokens, output_tokens, cost_usd_est, latency_ms, status, gate_reason "
                   "FROM llm_calls ORDER BY id")
    assert len(rows) == 2
    assert rows[0][:4] == ("claude", "claude-haiku-5-5", 1000, 100) and float(rows[0][4]) == pytest.approx(0.00015)
    assert rows[0][5:] == (420, "ok", "connection_test")
    assert rows[1][0] == "gemini" and rows[1][6] == "error"
