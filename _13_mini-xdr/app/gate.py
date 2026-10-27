"""호출 깔때기의 판단 함수(순수) — G4 디바운스, G1 화이트리스트, G2 규칙 결론([186] 5-1).

LLM 은 마지막 수단이다: 바뀐 게 없으면 다시 묻지 않고(G4), 알려진 정상은 끝내고(G1),
규칙으로 답이 정해지는 경우(실패 뒤 성공 = 탈취, 단일 계층·낮은 등급 = 잡음)는 규칙이 답한다(G2).
"""
from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import datetime, timedelta
from ipaddress import ip_address

from app.correlator import PRIORITIES, higher
from app.triage_schema import Decision

BANDS = ("z3", "z5", "z8")
FAIL_SIGNALS = {"login-bruteforce", "100210", "100211"}   # 게시판 로그인 실패·Wazuh 실패/브루트포스
SUCCESS_SIGNALS = {"login-success"}


def anomaly_band(signals: Iterable[str]) -> str | None:
    found = [s.rsplit("-", 1)[-1] for s in signals if s.startswith("anomaly-")]
    found = [b for b in found if b in BANDS]
    return max(found, key=BANDS.index) if found else None


def material_state(inc: dict, band: str | None) -> dict:
    """실질 상태 — 이게 바뀔 때만 다시 판정한다. 이벤트 수는 2배 구간(log2)으로만 본다."""
    return {"layers": sorted(inc["layers"]), "floor": inc["rule_floor"] or "P4", "band": band or "none",
            "count_band": int(math.log2(max(1, inc["event_count"])))}


def debounce(inc: dict, material: dict, now: datetime, cooldown: timedelta) -> str | None:
    """건너뛸 이유(unchanged·cooldown). None 이면 판정한다."""
    last, prev = inc["last_triaged_at"], inc["material_state"]
    if last is None:
        return None
    if prev == material:
        return "unchanged"
    if prev and PRIORITIES.index(material["floor"]) < PRIORITIES.index(prev["floor"]):
        return None  # 하한이 올랐다 — 쿨다운을 기다리지 않는다
    if now - last < cooldown:
        return "cooldown"
    return None


def in_whitelist(entity_key: str, networks: list) -> bool:
    if not entity_key.startswith("ip:"):
        return False
    try:
        addr = ip_address(entity_key[3:])
    except ValueError:
        return False
    return any(addr in net for net in networks)


def takeover(timeline_signals: list[str]) -> bool:
    """시간 순 신호에서 로그인 실패 뒤 성공이 있는가."""
    failed = False
    for s in timeline_signals:
        if s in FAIL_SIGNALS:
            failed = True
        elif s in SUCCESS_SIGNALS and failed:
            return True
    return False


def rule_conclusion(inc: dict, band: str | None, timeline_signals: list[str]) -> Decision | None:
    floor = inc["rule_floor"] or "P4"
    if takeover(timeline_signals):
        return Decision("rule", "G2", higher(floor, "P1"), "true_positive", "lock_account",
                        "규칙 결론: 로그인 실패 뒤 성공 — 계정 탈취 정황")
    if len(inc["layers"]) == 1 and (inc["max_level"] or 0) < 5 and band is None:
        return Decision("rule", "G2", floor, "needs_review", "monitor",
                        "규칙 결론: 단일 계층·낮은 등급·행위 이상 없음 — 감시만")
    return None
