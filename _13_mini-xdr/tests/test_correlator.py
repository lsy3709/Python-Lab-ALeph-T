"""상관 순수 로직 — 엔티티 키·창·규칙 하한·지문·늦게 온 이벤트."""
from datetime import datetime, timedelta, timezone

from app.correlator import EventRow, IncidentState, correlate, entity_key, higher, rule_floor

T0 = datetime(2026, 10, 26, 5, 0, 0, tzinfo=timezone.utc)
W = timedelta(minutes=10)
NOW = T0 + timedelta(hours=1)


def ev(i, minutes, *, layer="app", source="board", event_type="web-scan", ip="203.0.113.9", user=None,
       asset=None, rule_id=None, level=None):
    return EventRow(id=i, ts=T0 + timedelta(minutes=minutes), layer=layer, source=source, event_type=event_type,
                    src_ip=ip, user_name=user, asset=asset, rule_id=rule_id, level=level)


def test_entity_key_prefers_ip_then_user_then_asset():
    assert entity_key(ev(1, 0)) == "ip:203.0.113.9"
    assert entity_key(ev(1, 0, ip=None, user="zz_alice")) == "user:zz_alice"
    assert entity_key(ev(1, 0, ip=None, asset="board-host")) == "asset:board-host"
    assert entity_key(ev(1, 0, ip=None, source="wazuh")) == "asset:wazuh"


def test_rule_floor_and_higher():
    assert [rule_floor(x) for x in (None, 5, 7, 10, 12, 15)] == ["P4", "P4", "P3", "P2", "P1", "P1"]
    assert higher(None, "P3") == "P3" and higher("P4", "P2") == "P2" and higher("P1", "P3") == "P1"


def test_same_entity_within_window_joins_across_layers():
    batch = correlate([ev(1, 0), ev(2, 3, layer="network", source="suricata", event_type="ids-alert")], {}, W, NOW)
    assert batch.created == 1 and len(batch.touched) == 1
    inc = batch.touched[0]
    assert inc.layers == {"app", "network"} and inc.event_count == 2
    assert inc.signals == {"app/board/web-scan", "network/suricata/ids-alert"}
    assert [eid for _, eid in batch.links] == [1, 2]


def test_gap_longer_than_window_opens_new_incident():
    batch = correlate([ev(1, 0), ev(2, 9), ev(3, 20)], {}, W, NOW)  # 9분 뒤는 붙고, 그 뒤 11분 쉬면 새로
    assert batch.created == 2
    assert [i.event_count for i in batch.touched] == [2, 1]


def test_different_entities_are_separate():
    batch = correlate([ev(1, 0), ev(2, 1, ip="198.51.100.7"), ev(3, 2, ip=None, asset="board-host")], {}, W, NOW)
    assert sorted(i.entity_key for i in batch.touched) == ["asset:board-host", "ip:198.51.100.7", "ip:203.0.113.9"]


def test_attaches_to_existing_incident_and_keeps_its_id():
    old = IncidentState(entity_key="ip:203.0.113.9", id=41, opened_at=T0, last_event_at=T0 + timedelta(minutes=2),
                        layers={"app"}, signals={"app/board/web-scan"}, event_count=5, current_priority="P4")
    latest = {"ip:203.0.113.9": old}
    batch = correlate([ev(9, 8, layer="host", source="wazuh", event_type="wazuh-alert", rule_id="5710", level=10)],
                      latest, W, NOW)
    assert batch.created == 0 and batch.touched == [old] and old.id == 41
    assert old.event_count == 6 and old.layers == {"app", "host"} and old.max_level == 10
    assert old.rule_floor == "P2" and old.current_priority == "P2"


def test_status_closed_when_quiet_longer_than_window():
    batch = correlate([ev(1, 0), ev(2, 55)], {}, W, NOW)  # NOW = T0+60분
    assert [i.status for i in batch.touched] == ["closed", "open"]


def test_priority_never_drops_below_floor_but_keeps_higher_value():
    inc = IncidentState(entity_key="ip:203.0.113.9", opened_at=T0, last_event_at=T0, current_priority="P1")
    correlate([ev(1, 1, level=3)], {"ip:203.0.113.9": inc}, W, NOW)
    assert inc.current_priority == "P1"  # AI 가 올려 둔 P1 은 하한(P4) 때문에 내려가지 않는다


def test_fingerprint_ignores_ip_and_counts():
    a = correlate([ev(1, 0), ev(2, 1)], {}, W, NOW).touched[0]
    b = correlate([ev(3, 0, ip="198.51.100.7")], {}, W, NOW).touched[0]
    assert a.fingerprint == b.fingerprint


def test_late_past_event_does_not_replace_latest_incident():
    recent = IncidentState(entity_key="ip:203.0.113.9", id=7, opened_at=T0 + timedelta(minutes=40),
                           last_event_at=T0 + timedelta(minutes=45), layers={"app"}, event_count=3)
    latest = {"ip:203.0.113.9": recent}
    batch = correlate([ev(1, 0), ev(2, 46)], latest, W, NOW)  # 0분은 늦게 온 과거 → 새 인시던트, 46분은 최근 것에
    assert batch.created == 1 and latest["ip:203.0.113.9"] is recent and recent.event_count == 4
