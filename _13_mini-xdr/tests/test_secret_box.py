"""비밀값 상자 — 암호문 왕복, 원문 비노출, 다른 열쇠로는 못 풂, 마스킹."""
import pytest

from app.secret_box import SecretBox, SecretBoxError, mask

FAKE = "AIza" + "TESTKEY" * 5 + "wxyz"  # 테스트용 가짜 키(실제 키 아님)


def test_seal_open_roundtrip_and_ciphertext_hides_plaintext():
    box = SecretBox(SecretBox.generate_key())
    sealed = box.seal(FAKE)
    assert sealed.startswith("enc:v1:") and FAKE not in sealed and "TESTKEY" not in sealed
    assert box.open(sealed) == FAKE
    assert box.seal(FAKE) != sealed  # 같은 값도 매번 다른 암호문(무작위 IV)


def test_other_key_cannot_open():
    sealed = SecretBox(SecretBox.generate_key()).seal(FAKE)
    with pytest.raises(SecretBoxError, match="SETTINGS_SECRET_KEY"):
        SecretBox(SecretBox.generate_key()).open(sealed)


def test_rejects_malformed_key_and_plain_values():
    with pytest.raises(SecretBoxError):
        SecretBox("not-a-fernet-key")
    with pytest.raises(SecretBoxError):
        SecretBox(SecretBox.generate_key()).open("plain-text")


def test_mask_shows_only_edges():
    assert mask(FAKE) == "AIza…wxyz"
    assert mask("short") == "••••••••"
    assert mask(None) == "-" and mask("") == "-"
