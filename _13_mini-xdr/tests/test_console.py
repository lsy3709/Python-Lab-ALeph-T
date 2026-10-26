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

    def list_anomalies(self, limit=100):
        return self.anomalies

    def baseline_summary(self, min_samples=30):
        return {"population": [{"entity_type": "ip", "feature": "events", "mean": 18.0, "std": 17.79, "n": 380,
                                "updated_at": T0}],
                "individual": [{"entity_type": "ip", "entity": "192.168.120.1", "features": 4}], "insufficient": 7}

    anomalies = [{"id": 1, "entity_type": "ip", "entity": "203.0.113.50", "ts": T0, "score": 126.8,
                  "features": {"events": {"value": 200, "z": 126.8, "kind": "population", "center": 12, "scale": 1.48},
                               "signals": {"value": 1, "z": 0.0, "kind": "population", "center": 1, "scale": 1.0}}}]


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


def test_anomalies_page_shows_baselines_and_recent_scores(fake):
    html = client_for(fake).get("/anomalies").get_data(as_text=True)
    assert "ip:events" in html and "17.79" in html and "380" in html          # 집단 기준선
    assert "192.168.120.1" in html and "기준선 부족" in html                    # 개인 기준선·부족 수
    assert "203.0.113.50" in html and "126.8" in html and "집단" in html       # 최근 이상
    assert "z 0.0" not in html                                                  # 임계 미만 특징은 숨김
    assert 'href="/anomalies"' in client_for(fake).get("/").get_data(as_text=True)


def test_anomalies_page_escapes_entity(fake):
    fake.anomalies = [dict(FakeQueries.anomalies[0], entity_type="user", entity=XSS)]
    html = client_for(fake).get("/anomalies").get_data(as_text=True)
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
