"""Graylog 메시지 → 공통 스키마(events_norm) 정규화.

계층(layer)은 센서가 아니라 '내용' 기준이다. Wazuh 가 게시판 로그를 읽어 낸 경보는 app 으로 둬서,
같은 사건을 게시판 GELF 와 Wazuh 가 함께 봐도 다계층으로 부풀지 않게 한다.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

APP_GROUPS = {"webapp", "flask_board", "web_scan"}


@dataclass(frozen=True)
class NormalizedEvent:
    ts: datetime          # UTC aware
    layer: str            # app · host · network · data
    source: str           # wazuh · board · pfsense · suricata
    event_type: str
    raw_ref: str
    src_ip: str | None = None
    user_name: str | None = None
    asset: str | None = None
    rule_id: str | None = None
    level: int | None = None
    mitre: str | None = None


def _cut(value: Any, size: int) -> str | None:
    if value is None or value == "":
        return None
    return str(value)[:size]


def _as_list(value: Any) -> list[str]:
    """Graylog 는 배열 필드를 JSON 문자열('["T1110"]')로 줄 때가 있다."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return [str(value)]
    return [str(v) for v in parsed] if isinstance(parsed, list) else [str(parsed)]


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _wazuh_layer(groups: list[str]) -> str:
    g = set(groups)
    if "ids" in g:
        return "network"
    if "mysql_audit" in g:
        return "data"
    if g & APP_GROUPS:
        return "app"
    return "host"


def normalize(msg: dict[str, Any]) -> NormalizedEvent | None:
    raw_ref = msg.get("gl2_message_id") or msg.get("_id")
    if not raw_ref or "timestamp" not in msg:
        return None
    ts = _parse_ts(msg["timestamp"])

    if msg.get("wazuh_rule_id"):
        groups = _as_list(msg.get("wazuh_rule_groups"))
        mitre = ",".join(_as_list(msg.get("wazuh_rule_mitre_id"))) or None
        level = msg.get("wazuh_rule_level")
        return NormalizedEvent(
            ts=ts, layer=_wazuh_layer(groups), source="wazuh", event_type="wazuh-alert", raw_ref=raw_ref,
            src_ip=_cut(msg.get("wazuh_data_srcip"), 45),
            user_name=_cut(msg.get("wazuh_data_dstuser") or msg.get("wazuh_data_srcuser"), 128),
            asset=_cut(msg.get("wazuh_agent_name"), 128),
            rule_id=_cut(msg["wazuh_rule_id"], 16),
            level=int(level) if level not in (None, "") else None,
            mitre=_cut(mitre, 64),
        )

    rule = msg.get("rule")
    origin = msg.get("source")
    if rule == "pfsense-block" or origin == "pfSense":
        return NormalizedEvent(ts=ts, layer="network", source="pfsense", event_type="pfsense-block",
                               raw_ref=raw_ref, src_ip=_cut(msg.get("src_ip"), 45), asset="pfSense")
    if rule == "ids-alert" or origin == "suricata":
        return NormalizedEvent(ts=ts, layer="network", source="suricata", event_type="ids-alert",
                               raw_ref=raw_ref, src_ip=_cut(msg.get("src_ip"), 45), asset="suricata")
    if rule:
        return NormalizedEvent(
            ts=ts, layer="app", source="board", event_type=_cut(rule, 64), raw_ref=raw_ref,
            src_ip=_cut(msg.get("src_ip"), 45),
            user_name=_cut(msg.get("username") or msg.get("user"), 128),
            asset=_cut(origin, 128),
        )
    return None
