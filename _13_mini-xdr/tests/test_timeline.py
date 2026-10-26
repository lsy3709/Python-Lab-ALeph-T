"""타임라인 — 이어지는 같은 신호는 한 줄, 끊기면 새 줄, 상한을 넘으면 잘림 표시."""
from datetime import datetime, timedelta, timezone

from app.correlator import EventRow
from app.timeline import build_timeline, offset_label

T0 = datetime(2026, 10, 26, 5, 0, 0, tzinfo=timezone.utc)


def ev(i, sec, event_type="login-bruteforce", *, layer="app", source="board", user=None, rule_id=None, level=None,
       mitre=None):
    return EventRow(id=i, ts=T0 + timedelta(seconds=sec), layer=layer, source=source, event_type=event_type,
                    user_name=user, rule_id=rule_id, level=level, mitre=mitre)


def test_runs_of_same_signal_collapse_into_one_item():
    items, cut = build_timeline([ev(1, 0, user="zz_a"), ev(2, 5, user="zz_b"), ev(3, 9, user="zz_a"),
                                 ev(4, 40, "wazuh-alert", layer="host", source="wazuh", rule_id="100211",
                                    level=10, mitre="T1110"),
                                 ev(5, 95, "login-success", user="zz_a")])
    assert not cut
    assert [(i.signal, i.count) for i in items] == [("login-bruteforce", 3), ("100211", 1), ("login-success", 1)]
    assert items[0].users == ["zz_a", "zz_b"] and items[0].last == T0 + timedelta(seconds=9)
    assert items[1].max_level == 10 and items[1].mitre == "T1110"


def test_interrupted_run_starts_a_new_item():
    items, _ = build_timeline([ev(1, 0), ev(2, 1, "web-scan"), ev(3, 2)])
    assert [i.signal for i in items] == ["login-bruteforce", "web-scan", "login-bruteforce"]


def test_max_items_truncates():
    items, cut = build_timeline([ev(i, i, "a" if i % 2 else "b") for i in range(10)], max_items=4)
    assert cut and len(items) == 4


def test_users_are_capped_at_three():
    items, _ = build_timeline([ev(i, i, user=f"zz_{i}") for i in range(6)])
    assert items[0].users == ["zz_0", "zz_1", "zz_2"]


def test_offset_label():
    assert [offset_label(s) for s in (0, 40, 185, 7800)] == ["+0s", "+40s", "+3m05s", "+2h10m"]
