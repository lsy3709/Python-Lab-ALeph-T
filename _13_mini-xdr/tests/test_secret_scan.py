"""비밀 스캔 — 테스트 파일 자체가 걸리지 않도록 가짜 키는 실행 중에 조립한다."""
from pathlib import Path

from app.secret_scan import main, scan_path, scan_text

FAKE_ANTHROPIC = "sk-" + "ant-" + "a" * 32
FAKE_GOOGLE = "AI" + "za" + "B" * 35
FAKE_PRIVATE = "-----BEGIN " + "RSA PRIVATE KEY-----"


def test_detects_anthropic_key():
    assert scan_text(f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}") == [(1, "anthropic_api_key")]


def test_detects_google_key_and_private_key_on_their_lines():
    hits = set(scan_text(f"x\nkey={FAKE_GOOGLE}\n{FAKE_PRIVATE}\n"))
    assert (2, "google_api_key") in hits
    assert (3, "private_key_block") in hits


def test_placeholder_is_not_flagged():
    assert scan_text("ANTHROPIC_API_KEY=<YOUR_API_KEY>") == []


def test_skips_real_env_files_but_scans_example(tmp_path):
    for name in (".env", ".env.local", ".env.example"):
        (tmp_path / name).write_text(f"ANTHROPIC_API_KEY={FAKE_ANTHROPIC}\n", encoding="utf-8")
    assert [f.path.name for f in scan_path(tmp_path)] == [".env.example"]


def test_cli_exit_code_and_never_prints_value(tmp_path, capsys):
    (tmp_path / "ok.py").write_text("x = 1\n", encoding="utf-8")
    assert main([str(tmp_path)]) == 0
    (tmp_path / "bad.md").write_text(FAKE_ANTHROPIC, encoding="utf-8")
    assert main([str(tmp_path)]) == 1
    assert FAKE_ANTHROPIC not in capsys.readouterr().out


def test_project_has_no_secrets():
    root = Path(__file__).resolve().parent.parent
    assert scan_path(root) == []
