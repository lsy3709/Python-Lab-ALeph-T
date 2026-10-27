"""인시던트 카드 — LLM 에 보내는 유일한 입력(입력 다이어트 + 마스킹, [186] 4-1·5-2).

원본 로그 본문은 보내지 않는다. 신호는 룰 번호·신호 이름만(설명은 고정 앞부분의 사전에), 문자열은
제어문자를 지우고 80자로 자른 뒤 마스킹한다. 타임라인은 시간 순 앞 15줄 — "실패 뒤 성공" 같은 순서가 판정 근거다.
"""
from __future__ import annotations

from datetime import datetime

from app.masker import Masker, clip
from app.timeline import TimelineItem, offset_label

MAX_SIGNALS, MAX_TIMELINE, MAX_USERS, MAX_ANOMALY = 12, 15, 5, 3
ANOMALY_MIN_Z = 3.0
ENTITY_KIND = {"ip": "ip", "user": "user", "asset": "asset"}


def _anomaly(rows: list[dict]) -> list[dict]:
    best: dict[str, dict] = {}
    for row in rows:
        for name, f in row["features"].items():
            if f["z"] >= ANOMALY_MIN_Z and f["z"] > best.get(name, {}).get("z", -1):
                best[name] = {"feature": name, "value": f["value"], "z": round(f["z"], 2), "base": f["kind"]}
    return sorted(best.values(), key=lambda a: -a["z"])[:MAX_ANOMALY]


def build_card(ref: str, inc: dict, summary: list[dict], timeline: list[TimelineItem], start: datetime | None,
               anomalies: list[dict], users: list[str], masker: Masker) -> dict:
    etype, entity = inc["entity_key"].split(":", 1)
    entity_token = masker.token(ENTITY_KIND.get(etype, "asset"), entity)
    user_tokens = [masker.token("user", u) for u in users[:MAX_USERS]]
    signals = sorted(summary, key=lambda s: (-(s["max_level"] or 0), -s["n"]))[:MAX_SIGNALS]
    duration = (inc["last_event_at"] - inc["opened_at"]).total_seconds() / 60
    return {
        "ref": ref,
        "entity": entity_token,
        "entity_type": etype,
        "layers": list(inc["layers"]),
        "events": inc["event_count"],
        "duration_min": round(duration, 1),
        "rule_floor": inc["rule_floor"],
        "max_level": inc["max_level"],
        "users": user_tokens,
        "signals": [{"layer": s["layer"], "source": s["source"], "signal": masker.scrub(clip(s["sig"])),
                     "count": s["n"], "level": s["max_level"], "mitre": s["mitre"]} for s in signals],
        "timeline": [{"t": offset_label((t.first - start).total_seconds()) if start else "+0s", "layer": t.layer,
                      "signal": masker.scrub(clip(t.signal)), "count": t.count,
                      "users": [masker.token("user", u) for u in t.users]} for t in timeline[:MAX_TIMELINE]],
        "anomaly": _anomaly(anomalies),
    }
