"""Graylog 검색 클라이언트 — 실제 네트워크 없이 httpx.MockTransport 로 요청 모양을 검증한다."""
import base64
from datetime import datetime, timezone

import httpx
import pytest

from app.graylog import GraylogClient, GraylogError

T0 = datetime(2026, 10, 22, 2, 55, 0, tzinfo=timezone.utc)
T1 = datetime(2026, 10, 22, 2, 56, 0, tzinfo=timezone.utc)


def _client(handler, **kw):
    return GraylogClient("http://graylog:9000", transport=httpx.MockTransport(handler), **kw)


def _capture_auth(seen):
    def handler(request):
        seen["auth"] = request.headers["Authorization"]
        return httpx.Response(200, json={"messages": []})
    return handler


def test_absolute_search_sends_required_headers_and_params():
    seen = {}

    def handler(request):
        seen["req"] = request
        return httpx.Response(200, json={"messages": [{"message": {"gl2_message_id": "a"}}], "total_results": 1})

    msgs = _client(handler, token="tok").search_absolute("q:1", T0, T1, limit=500, offset=0, fields=["timestamp", "rule"])
    req = seen["req"]
    assert req.url.path == "/api/search/universal/absolute"
    assert req.headers["Accept"] == "application/json"
    assert req.headers["X-Requested-By"] == "mini-xdr"
    p = req.url.params
    assert (p["query"], p["limit"], p["offset"], p["sort"]) == ("q:1", "500", "0", "timestamp:asc")
    assert (p["from"], p["to"]) == ("2026-10-22T02:55:00.000Z", "2026-10-22T02:56:00.000Z")
    assert p["fields"] == "timestamp,rule"
    assert msgs == [{"gl2_message_id": "a"}]


def test_token_auth_uses_token_as_username():
    seen = {}
    _client(_capture_auth(seen), token="tok").search_absolute("*", T0, T1)
    assert base64.b64decode(seen["auth"].split()[1]) == b"tok:token"


def test_user_password_auth_when_no_token():
    seen = {}
    _client(_capture_auth(seen), user="u", password="p").search_absolute("*", T0, T1)
    assert base64.b64decode(seen["auth"].split()[1]) == b"u:p"


def test_http_error_raises_without_leaking_credentials():
    with pytest.raises(GraylogError) as err:
        _client(lambda r: httpx.Response(401, text="unauthorized"), token="tok").search_absolute("*", T0, T1)
    assert "401" in str(err.value) and "tok" not in str(err.value)


def test_connection_error_is_wrapped():
    def boom(request):
        raise httpx.ConnectError("refused")
    with pytest.raises(GraylogError):
        _client(boom, token="tok").search_absolute("*", T0, T1)


def test_requires_some_credentials():
    with pytest.raises(ValueError):
        GraylogClient("http://graylog:9000")
