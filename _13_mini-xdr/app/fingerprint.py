"""인시던트 지문(호출 깔때기 G3) — '같은 종류의 사건'이면 같은 값.

넣는 것: 엔티티 유형·계층 집합·신호 집합·이상점수 구간.
넣지 않는 것: 시각·IP·계정·횟수 — 같은 공격이 IP 만 바꿔 와도 같은 지문이어야 판정을 재사용할 수 있다.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable


def signal_of(layer: str, source: str, rule_id: str | None, event_type: str) -> str:
    """신호 이름 — Wazuh 는 룰 번호, 그 밖에는 rule(event_type)."""
    return f"{layer}/{source}/{rule_id or event_type}"


def fingerprint(entity_type: str, layers: Iterable[str], signals: Iterable[str], anomaly_band: str = "none") -> str:
    canon = json.dumps({"entity": entity_type, "layers": sorted(set(layers)), "signals": sorted(set(signals)),
                        "anomaly": anomaly_band}, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()
