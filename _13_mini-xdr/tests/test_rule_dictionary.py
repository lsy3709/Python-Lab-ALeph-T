"""신호 사전 — 설명 정리(개인정보 거름)·주된 뜻/다른 뜻·커밋된 사전 검사·설명 찾기."""
import json
import re
from collections import Counter

from app.rule_dictionary import DATA_PATH, build_entries, describe, load, sanitize


def test_sanitize_removes_emails_ips_and_trims():
    # 이메일 뒤의 세션 식별자까지 지워야 같은 뜻이 하나로 모인다(랩 실측: 60605 가 식별자마다 다른 뜻처럼 갈라짐)
    assert sanitize("Chrome remote desktop (someone@example.com/chromoting_ftl_984abc)") == "Chrome remote desktop ([이메일])"
    assert sanitize("threshold exceeded from 203.0.113.44") == "threshold exceeded from [IP]"
    assert len(sanitize("가" * 200)) == 70 and sanitize(None) == ""


def test_build_entries_keeps_main_and_alternative_meanings():
    samples = {"100230": Counter({("Flask 게시판 HTTP 404 발생", ()): 1544,
                                  ("저속 브루트포스 의심", ("T1110.001",)): 3}),
               "5710": Counter({("sshd: attempt to login using a non-existent user", ("T1110",)): 9})}
    entries = build_entries(samples, levels={"100230": 10, "5710": 5})
    assert entries["100230"] == {"desc": "Flask 게시판 HTTP 404 발생", "alt": ["저속 브루트포스 의심"], "mitre": [],
                                 "level": 10}
    assert entries["5710"]["mitre"] == ["T1110"] and entries["5710"]["alt"] == []


def test_committed_dictionary_has_no_personal_data():
    text = DATA_PATH.read_text(encoding="utf-8")
    data = json.loads(text)
    assert len(data["rules"]) >= 50
    assert "@" not in text
    assert not re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)


def test_load_includes_board_network_and_behavior_signals():
    d = load()
    assert d["rules"]["100211"]["desc"].startswith("연습 웹앱 브루트포스")
    assert "web-scan" in d["gelf"] and "pfsense-block" in d["gelf"]
    assert "anomaly-<특징>-<구간>" in d["behavior"]


def test_describe_signal():
    assert "404" in describe("app", "board", None, "web-scan")
    assert describe("app", "wazuh", "100230", "wazuh-alert").startswith("Flask 게시판 HTTP 404")
    assert "행위 이상" in describe("behavior", "anomaly", None, "anomaly-events-z8")
    assert describe("app", "board", None, "xdr-unknown") == ""
