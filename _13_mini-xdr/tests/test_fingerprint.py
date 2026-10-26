"""지문 — 같은 종류의 사건이면 같은 값, 시각·IP·횟수는 영향 없음."""
from app.fingerprint import fingerprint, signal_of


def test_signal_uses_rule_id_for_wazuh_and_rule_for_gelf():
    assert signal_of("host", "wazuh", "5710", "wazuh-alert") == "host/wazuh/5710"
    assert signal_of("app", "board", None, "login-bruteforce") == "app/board/login-bruteforce"


def test_order_and_duplicates_do_not_matter():
    a = fingerprint("ip", ["app", "network"], ["app/board/web-scan", "network/suricata/ids-alert"])
    b = fingerprint("ip", ["network", "app", "app"], ["network/suricata/ids-alert", "app/board/web-scan"])
    assert a == b and len(a) == 64


def test_changes_with_layers_signals_entity_type_and_anomaly_band():
    base = fingerprint("ip", ["app"], ["app/board/web-scan"])
    assert fingerprint("ip", ["app", "host"], ["app/board/web-scan"]) != base
    assert fingerprint("ip", ["app"], ["app/board/login-bruteforce"]) != base
    assert fingerprint("asset", ["app"], ["app/board/web-scan"]) != base
    assert fingerprint("ip", ["app"], ["app/board/web-scan"], anomaly_band="high") != base
