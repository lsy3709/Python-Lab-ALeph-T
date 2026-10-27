"""마스킹 — LLM 에 보내기 전에 IP·계정·자산·이메일을 일관 토큰으로, 키 모양 문자열은 [키] 로 바꾼다([186] 4-3).

같은 값은 항상 같은 토큰(ip_1)이 되어 LLM 이 "같은 출발지" 관계는 볼 수 있지만 실제 값은 모른다.
복원표는 이 객체(로컬 메모리)에만 있고, 응답 근거를 저장하기 전에 unmask() 로 되돌린다.
"""
from __future__ import annotations

import re

KINDS = ("ip", "user", "asset", "email")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){4,7}[0-9A-Fa-f]{1,4}(?![\w:])|(?<![\w:])[0-9A-Fa-f:]*::[0-9A-Fa-f:]+")
KEY_RE = re.compile(r"AIza[0-9A-Za-z_-]{30,}|sk-[A-Za-z0-9_-]{16,}|(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])"
                    r"|(?<![A-Za-z0-9_-])[A-Za-z0-9_-]{40,}(?![A-Za-z0-9_-])")
TOKEN_RE = re.compile(r"\b(ip|user|asset|email)_(\d+)\b")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]+")
MAX_TEXT = 80


def clip(text: str | None, size: int = MAX_TEXT) -> str:
    """제어문자를 공백으로 바꾸고 길이를 자른다(로그 인젝션·토큰 낭비 방지)."""
    return CONTROL_RE.sub(" ", text or "")[:size]


class Masker:
    def __init__(self) -> None:
        self._forward: dict[str, dict[str, str]] = {k: {} for k in KINDS}
        self._reverse: dict[str, str] = {}

    def token(self, kind: str, value: str | None) -> str | None:
        if not value:
            return None
        table = self._forward[kind]
        if value not in table:
            table[value] = f"{kind}_{len(table) + 1}"
            self._reverse[table[value]] = value
        return table[value]

    def scrub(self, text: str | None) -> str:
        """자유 문자열 속 이메일·키·IP·이미 본 계정/자산 값을 토큰으로."""
        out = EMAIL_RE.sub(lambda m: self.token("email", m.group(0)), text or "")
        out = KEY_RE.sub("[키]", out)
        out = IPV4_RE.sub(lambda m: self.token("ip", m.group(0)), out)
        out = IPV6_RE.sub(lambda m: self.token("ip", m.group(0)), out)
        for kind in ("user", "asset"):
            for value, tok in sorted(self._forward[kind].items(), key=lambda kv: -len(kv[0])):
                out = re.sub(rf"(?<![\w.@-]){re.escape(value)}(?![\w.@-])", tok, out)
        return out

    def unmask(self, text: str | None) -> str:
        return TOKEN_RE.sub(lambda m: self._reverse.get(m.group(0), m.group(0)), text or "")

    def originals(self) -> list[str]:
        return [v for table in self._forward.values() for v in table]


def find_leaks(payload: str, originals: list[str]) -> list[str]:
    """실제로 보낼 페이로드에 원본 값이 남아 있는지 — 누출 방지 테스트·실행 직전 점검용."""
    return [v for v in originals if v and v in payload]
