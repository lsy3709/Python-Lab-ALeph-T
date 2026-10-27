"""마스킹 — 일관 토큰·문자열 정리·복원·누출 검사."""
from app.masker import Masker, clip, find_leaks

FAKE_KEY = "AIza" + "MASKTEST" * 4 + "x1"  # 테스트용 가짜 키


def test_same_value_same_token_and_kinds_are_separate():
    m = Masker()
    assert m.token("ip", "203.0.113.9") == "ip_1"
    assert m.token("ip", "198.51.100.7") == "ip_2"
    assert m.token("ip", "203.0.113.9") == "ip_1"
    assert m.token("user", "zz_alice") == "user_1" and m.token("asset", "board-host") == "asset_1"
    assert m.token("user", None) is None


def test_scrub_replaces_ips_emails_keys_and_known_values():
    m = Masker()
    m.token("user", "zz_alice")
    text = f"from 203.0.113.9 to 10.0.0.5 by zz_alice mail admin@example.com key {FAKE_KEY} hex {'ab' * 20}"
    out = m.scrub(text)
    for original in ("203.0.113.9", "10.0.0.5", "zz_alice", "admin@example.com", FAKE_KEY, "ab" * 20):
        assert original not in out
    assert "ip_1" in out and "ip_2" in out and "user_1" in out and "email_1" in out and "[키]" in out


def test_scrub_keeps_times_and_ordinary_words():
    m = Masker()
    assert m.scrub("+3m05s 17:28:40 login-bruteforce zz_alice2") == "+3m05s 17:28:40 login-bruteforce zz_alice2"


def test_unmask_restores_values_longest_token_first():
    m = Masker()
    for i in range(12):
        m.token("ip", f"203.0.113.{i}")
    assert m.unmask("ip_12 와 ip_1 이 같은 공격") == "203.0.113.11 와 203.0.113.0 이 같은 공격"


def test_clip_removes_control_chars_and_limits_length():
    assert clip("a\nb\x00c\td" + "x" * 200) == "a b c d" + "x" * 73
    assert len(clip("가" * 100)) == 80 and clip(None) == ""


def test_find_leaks():
    assert find_leaks('{"entity": "ip_1"}', ["203.0.113.9", "zz_alice"]) == []
    assert find_leaks('{"entity": "203.0.113.9"}', ["203.0.113.9", "zz_alice"]) == ["203.0.113.9"]
