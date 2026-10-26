"""콘솔 요청 보안 — Host 검사(DNS 리바인딩), Origin 검사·CSRF 토큰(설정 쓰기).

콘솔은 127.0.0.1 에만 열려 있지만, 사용자가 브라우저로 연 '다른 사이트'가 이 PC 의 콘솔로
요청을 보내게 만들 수 있다(CSRF). 또 공격자 도메인을 127.0.0.1 로 바꿔 같은 출처처럼 보이게 할 수도 있다
(DNS 리바인딩) → Host 가 localhost 계열이 아니면 모든 요청을 거부한다.
"""
from __future__ import annotations

import hmac
import secrets
from urllib.parse import urlsplit

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


def host_allowed(host: str | None) -> bool:
    host = (host or "").strip().lower()
    if host.startswith("["):              # [::1]:8099
        name = host[1:host.find("]")] if "]" in host else ""
    elif host.count(":") == 1:            # 127.0.0.1:8099
        name = host.rsplit(":", 1)[0]
    else:
        name = host
    return name in LOCAL_HOSTS


def origin_allowed(origin: str | None) -> bool:
    """Origin 이 없으면 통과(CSRF 토큰이 1차 방어), 있으면 localhost 계열만. 'null' 은 거부."""
    if not origin:
        return True
    if origin == "null":
        return False
    return (urlsplit(origin).hostname or "") in LOCAL_HOSTS


def csrf_token(session) -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def csrf_valid(session, submitted: str | None) -> bool:
    expected = session.get("csrf")
    return bool(expected and submitted) and hmac.compare_digest(expected, submitted)
