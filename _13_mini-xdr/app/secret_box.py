"""비밀값 상자 — 웹 UI 에서 받은 AI 키를 DB 에 암호문(Fernet)으로만 저장한다.

복호화 열쇠(SETTINGS_SECRET_KEY)는 .env 에만 둔다 → DB 를 읽을 수 있어도 키 원문은 알 수 없다.
열쇠 만들기: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"


class SecretBoxError(Exception):
    """열쇠가 없거나 틀렸거나, 암호문 형식이 아닐 때."""


class SecretBox:
    def __init__(self, key: str) -> None:
        try:
            self._fernet = Fernet(key.encode())
        except (ValueError, TypeError):
            raise SecretBoxError("SETTINGS_SECRET_KEY 형식이 올바르지 않습니다(Fernet 키, 44자)") from None

    @staticmethod
    def generate_key() -> str:
        return Fernet.generate_key().decode()

    def seal(self, plain: str) -> str:
        return PREFIX + self._fernet.encrypt(plain.encode()).decode()

    def open(self, sealed: str) -> str:
        if not sealed.startswith(PREFIX):
            raise SecretBoxError("암호문 형식이 아닙니다")
        try:
            return self._fernet.decrypt(sealed[len(PREFIX):].encode()).decode()
        except InvalidToken:
            raise SecretBoxError("복호화 실패 — SETTINGS_SECRET_KEY 가 저장할 때와 다릅니다") from None


def mask(value: str | None) -> str:
    """화면 표시용 — 앞 4자와 뒤 4자만. 짧으면 전부 가린다."""
    if not value:
        return "-"
    v = value.strip()
    if len(v) < 12:
        return "•" * 8
    return f"{v[:4]}…{v[-4:]}"
