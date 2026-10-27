"""호출 깔때기 관문 — 실질 상태(G4)·디바운스·화이트리스트(G1)·실패 뒤 성공·규칙 결론(G2)."""
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network

from app.gate import anomaly_band, debounce, in_whitelist, material_state, rule_conclusion, takeover

NOW = datetime(2026, 10, 27, 2, 0, 0, tzinfo=timezone.utc)
COOLDOWN = timedelta(minutes=5)


def inc(**kw):
    row = {"id": 1, "entity_key": "ip:203.0.113.9", "layers": ["app"], "event_count": 12, "max_level": None,
           "rule_floor": "P4", "last_triaged_at": None, "material_state": None}
    row.update(kw)
    return row


def test_anomaly_band_takes_strongest():
    assert anomaly_band(["web-scan", "anomaly-events-z3", "anomaly-signals-z8"]) == "z8"
    assert anomaly_band(["web-scan"]) is None


def test_material_state_uses_count_bands():
    m = material_state(inc(layers=["network", "app"], event_count=12), band=None)
    assert m == {"layers": ["app", "network"], "floor": "P4", "band": "none", "count_band": 3}
    assert material_state(inc(event_count=15), None)["count_band"] == 3      # 12→15 는 같은 구간
    assert material_state(inc(event_count=16), None)["count_band"] == 4      # 두 배 구간을 넘으면 실질 변화


def test_debounce_rules():
    m = material_state(inc(), None)
    assert debounce(inc(), m, NOW, COOLDOWN) is None                                       # 처음
    seen = inc(last_triaged_at=NOW - timedelta(minutes=1), material_state=m)
    assert debounce(seen, m, NOW, COOLDOWN) == "unchanged"
    changed = material_state(inc(layers=["app", "behavior"]), "z5")
    assert debounce(seen, changed, NOW, COOLDOWN) == "cooldown"
    old = inc(last_triaged_at=NOW - timedelta(minutes=6), material_state=m)
    assert debounce(old, changed, NOW, COOLDOWN) is None
    rose = material_state(inc(rule_floor="P2", max_level=10), None)
    assert debounce(seen, rose, NOW, COOLDOWN) is None                                     # 하한이 오르면 즉시


def test_whitelist_only_for_ip_entities():
    nets = [ip_network("127.0.0.1/32"), ip_network("10.10.0.0/16")]
    assert in_whitelist("ip:10.10.3.4", nets) and in_whitelist("ip:127.0.0.1", nets)
    assert not in_whitelist("ip:203.0.113.9", nets) and not in_whitelist("user:zz_a", nets)
    assert not in_whitelist("ip:not-an-ip", nets)


def test_takeover_needs_failure_before_success():
    assert takeover(["login-bruteforce", "100211", "login-success"])
    assert takeover(["100210", "web-scan", "login-success"])
    assert not takeover(["login-success", "login-bruteforce"])
    assert not takeover(["web-scan"])


def test_rule_conclusion():
    d = rule_conclusion(inc(layers=["app"], rule_floor="P2", max_level=10), None,
                        ["login-bruteforce", "login-success"])
    assert (d.gate, d.priority, d.verdict, d.recommended_playbook) == ("G2", "P1", "true_positive", "lock_account")
    d = rule_conclusion(inc(), None, ["web-scan"])
    assert (d.priority, d.recommended_playbook) == ("P4", "monitor")
    assert rule_conclusion(inc(layers=["app", "network"]), None, ["web-scan"]) is None      # 다계층 → 회색지대
    assert rule_conclusion(inc(max_level=10, rule_floor="P2"), None, ["100211"]) is None   # 높은 등급
    assert rule_conclusion(inc(), "z5", ["web-scan"]) is None                               # 행위 이상 있음
