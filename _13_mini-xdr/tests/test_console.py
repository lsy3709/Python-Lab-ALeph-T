"""읽기 전용 콘솔 — 가짜 조회 객체로 화면·필터·이스케이프·보안 헤더를 확인한다."""
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import pytest

from app.console import create_app
from app.correlator import EventRow

T0 = datetime(2026, 10, 26, 5, 0, 0)  # DB 에서 오는 값처럼 naive UTC (KST 14:00)
XSS = "<script>alert(1)</script>"


def inc_row(iid=1, **kw):
    row = {"id": iid, "entity_key": "ip:203.0.113.9", "status": "closed", "opened_at": T0,
           "last_event_at": T0 + timedelta(minutes=3), "layers": ["app", "network"], "event_count": 4,
           "max_level": 10, "rule_floor": "P2", "current_priority": "P2", "fingerprint": "ab" * 32}
    row.update(kw)
    return row


def ev(i, sec, event_type="login-bruteforce", *, layer="app", source="board", user=None):
    return EventRow(id=i, ts=(T0 + timedelta(seconds=sec)).replace(tzinfo=timezone.utc), layer=layer,
                    source=source, event_type=event_type, user_name=user)


class FakeQueries:
    def __init__(self):
        self.rows = [inc_row()]
        self.events = []
        self.user_list = []
        self.filters = None

    def list_incidents(self, *, status, priority, multi, page):
        self.filters = (status, priority, multi, page)
        return self.rows, len(self.rows)

    def stats(self):
        return {"events": 81260, "incidents": 1630, "open_incidents": 3, "multi_layer": 20, "backlog": 0}

    def get_incident(self, iid):
        return next((r for r in self.rows if r["id"] == iid), None)

    def signal_summary(self, iid):
        return [{"layer": "app", "source": "board", "sig": "login-bruteforce", "n": 7, "first": T0,
                 "last": T0 + timedelta(seconds=9), "max_level": None, "mitre": None}]

    def incident_events(self, iid):
        return self.events

    def users(self, iid):
        return self.user_list


@pytest.fixture
def fake():
    return FakeQueries()


def client_for(fake, fail=False):
    @contextmanager
    def opener():
        if fail:
            raise ConnectionError("db down 10.0.0.5")
        yield fake

    return create_app(opener).test_client()


def test_list_shows_priority_entity_layers_stats_in_kst(fake):
    html = client_for(fake).get("/").get_data(as_text=True)
    assert "ip:203.0.113.9" in html and "p-P2" in html and "l-network" in html
    assert "81,260" in html and "1,630" in html
    assert "10-26 14:00:00" in html  # UTC 05:00 → KST 14:00


def test_list_filters_are_whitelisted(fake):
    client_for(fake).get("/?status=evil&priority=P9&page=-3&multi=yes")
    assert fake.filters == ("all", "", False, 1)
    client_for(fake).get("/?status=open&priority=P1&page=2&multi=1")
    assert fake.filters == ("open", "P1", True, 2)


def test_detail_collapses_timeline_and_shows_offsets(fake):
    fake.events = [ev(1, 0, user="zz_a"), ev(2, 5), ev(3, 9), ev(4, 40, "ids-alert", layer="network", source="suricata")]
    html = client_for(fake).get("/incidents/1").get_data(as_text=True)
    assert "+0s" in html and "+40s" in html
    assert "<td>3</td>" in html          # 같은 신호 3건이 한 줄로 접힘
    assert "AI 판정" in html and "zz_a" in html


def test_unknown_incident_is_404(fake):
    assert client_for(fake).get("/incidents/999").status_code == 404


def test_log_values_are_escaped(fake):
    fake.rows = [inc_row(entity_key=f"user:{XSS}")]
    fake.user_list = [XSS]
    fake.events = [ev(1, 0, XSS, user=XSS)]
    for path in ("/", "/incidents/1"):
        html = client_for(fake).get(path).get_data(as_text=True)
        assert XSS not in html and "&lt;script&gt;" in html


def test_security_headers(fake):
    r = client_for(fake).get("/")
    assert "default-src 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_healthz_ok_and_hides_errors(fake):
    r = client_for(fake).get("/healthz")
    assert r.status_code == 200 and r.get_json()["ok"] is True and r.get_json()["incidents"] == 1630
    r = client_for(fake, fail=True).get("/healthz")
    assert r.status_code == 503 and r.get_json() == {"ok": False}
    assert "10.0.0.5" not in r.get_data(as_text=True)
