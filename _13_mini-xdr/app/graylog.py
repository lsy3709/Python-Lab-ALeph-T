"""Graylog 검색 API 클라이언트(동기). 인증은 API 토큰 우선, 없으면 계정."""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

import httpx


class GraylogError(RuntimeError):
    """Graylog 호출 실패(상태 코드만 담고 인증 정보는 담지 않는다)."""


def _iso(ts: datetime) -> str:
    utc = ts.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


class GraylogClient:
    def __init__(self, base_url: str, *, token: str | None = None, user: str | None = None,
                 password: str | None = None, timeout: float = 15.0,
                 transport: httpx.BaseTransport | None = None) -> None:
        if token:
            auth = (token, "token")  # Graylog 토큰 인증 규칙: 사용자명=토큰, 비밀번호="token"
        elif user and password:
            auth = (user, password)
        else:
            raise ValueError("Graylog 인증 정보가 없습니다(GRAYLOG_TOKEN 또는 GRAYLOG_USER/PASSWORD)")
        self._http = httpx.Client(
            base_url=base_url.rstrip("/"), auth=auth, timeout=timeout, transport=transport,
            headers={"Accept": "application/json", "X-Requested-By": "mini-xdr"},
        )

    def search_absolute(self, query: str, frm: datetime, to: datetime, *, limit: int = 500,
                        offset: int = 0, fields: Sequence[str] | None = None) -> list[dict[str, Any]]:
        params = {"query": query, "from": _iso(frm), "to": _iso(to), "limit": str(limit),
                  "offset": str(offset), "sort": "timestamp:asc"}
        if fields:
            params["fields"] = ",".join(fields)
        try:
            resp = self._http.get("/api/search/universal/absolute", params=params)
        except httpx.HTTPError as exc:
            raise GraylogError(f"Graylog 연결 실패: {type(exc).__name__}") from None
        if resp.status_code != 200:
            raise GraylogError(f"Graylog 검색 실패: HTTP {resp.status_code}")
        return [m["message"] for m in resp.json().get("messages", [])]

    def close(self) -> None:
        self._http.close()
