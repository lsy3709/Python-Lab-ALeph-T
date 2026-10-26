"""정규화 — 실데이터 구조 표본으로 출처·계층·필드 매핑을 확인한다."""
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.normalizer import normalize

FIX = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "graylog_messages.json").read_text(encoding="utf-8"))


def test_wazuh_bruteforce_is_app_layer_with_mitre_and_user():
    e = normalize(FIX["wazuh_bruteforce"])
    assert (e.source, e.layer, e.event_type) == ("wazuh", "app", "wazuh-alert")
    assert (e.rule_id, e.level, e.mitre) == ("100211", 10, "T1110")
    assert (e.src_ip, e.user_name, e.asset) == ("198.51.100.77", "victim", "ha-board-container")
    assert e.raw_ref == "01M5GRJ89N00001RXERQFFTX3Z"
    assert e.ts == datetime(2026, 10, 22, 2, 55, 39, 317000, tzinfo=timezone.utc)


@pytest.mark.parametrize("key, layer", [
    ("wazuh_suricata_sqlmap", "network"),
    ("wazuh_mysql_audit", "data"),
    ("wazuh_sca", "host"),
    ("wazuh_http404", "app"),
])
def test_wazuh_layer_follows_rule_groups(key, layer):
    assert normalize(FIX[key]).layer == layer


def test_wazuh_without_srcip_keeps_none():
    e = normalize(FIX["wazuh_sca"])
    assert e.src_ip is None and e.mitre is None


def test_board_signal_is_app_layer_with_rule_as_event_type():
    e = normalize(FIX["board_login_fail"])
    assert (e.source, e.layer, e.event_type) == ("board", "app", "login-bruteforce")
    assert (e.src_ip, e.user_name, e.asset) == ("203.0.113.99", "zz_probe", "board")
    assert e.rule_id is None and e.level is None


def test_bot_signal_uses_user_field_and_host_as_asset():
    e = normalize(FIX["bot_priv"])
    assert (e.source, e.event_type, e.user_name, e.asset) == ("board", "priv-unauthorized-admin", "zz_s9v", "LAB-BOT-HOST")


def test_pfsense_and_suricata_are_network():
    p = normalize(FIX["pfsense_block"])
    s = normalize(FIX["suricata_ids"])
    assert (p.source, p.layer, p.event_type, p.asset) == ("pfsense", "network", "pfsense-block", "pfSense")
    assert (s.source, s.layer, s.event_type, s.asset) == ("suricata", "network", "ids-alert", "suricata")


@pytest.mark.parametrize("key, source, event_type, asset", [
    ("snort_portscan", "snort", "snort-portscan", "snort-kali"),
    ("cloudflare_waf", "cloudflare", "cf-waf", "cloudflare-edge"),
])
def test_gelf_network_and_edge_sensors_are_network_not_board(key, source, event_type, asset):
    # 라이브 백필에서 발견: GELF rule 로 들어오는 Snort·Cloudflare 신호가 board/app 으로 잘못 분류됐었다
    e = normalize(FIX[key])
    assert (e.source, e.layer, e.event_type, e.asset) == (source, "network", event_type, asset)
    assert e.src_ip == FIX[key]["src_ip"]


def test_message_without_security_fields_is_skipped():
    assert normalize(FIX["plain_syslog"]) is None


def test_mitre_already_list_and_long_values_are_trimmed():
    msg = dict(FIX["wazuh_bruteforce"], wazuh_rule_mitre_id=["T1110", "T1078"], wazuh_data_dstuser="u" * 300)
    e = normalize(msg)
    assert e.mitre == "T1110,T1078"
    assert len(e.user_name) == 128


def test_missing_message_id_falls_back_to_index_id():
    msg = {k: v for k, v in FIX["board_web_scan"].items() if k != "gl2_message_id"}
    msg["_id"] = "dbdfa190-c932-11f1-b38a-26acc1b822e4"
    assert normalize(msg).raw_ref == "dbdfa190-c932-11f1-b38a-26acc1b822e4"
