"""트리아지 출력 스키마·판정 단위·규칙 판정·하한([186] 4-1·4-4).

LLM 은 results[] 배열만 답한다(한 건도 배열 — 묶음 G6 과 같은 경로). 확률은 0~1 로, 근거는 600자로
'보정'한다(스키마 실패로 버리지 않음). 최종 우선순위는 언제나 규칙 하한 이상이다.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, get_args

from pydantic import BaseModel

from app.correlator import higher

Priority = Literal["P1", "P2", "P3", "P4"]
VerdictName = Literal["true_positive", "benign", "needs_review"]
Playbook = Literal["block_ip", "lock_account", "monitor", "none"]
REASON_MAX = 600


class Verdict(BaseModel):
    ref: str
    priority: Priority
    verdict: VerdictName
    false_positive_likelihood: float
    reasoning_ko: str
    recommended_playbook: Playbook
    confidence: float


class TriageBatch(BaseModel):
    results: list[Verdict]


def _enum(name: str) -> list[str]:
    return list(get_args(Verdict.model_fields[name].annotation))


# Gemini responseSchema(OpenAPI 부분집합) — Pydantic 모델에서 enum 을 가져와 둘이 어긋나지 않게
GEMINI_SCHEMA = {
    "type": "OBJECT",
    "properties": {"results": {"type": "ARRAY", "items": {
        "type": "OBJECT",
        "properties": {
            "ref": {"type": "STRING"},
            "priority": {"type": "STRING", "enum": _enum("priority")},
            "verdict": {"type": "STRING", "enum": _enum("verdict")},
            "false_positive_likelihood": {"type": "NUMBER"},
            "reasoning_ko": {"type": "STRING"},
            "recommended_playbook": {"type": "STRING", "enum": _enum("recommended_playbook")},
            "confidence": {"type": "NUMBER"},
        },
        "required": list(Verdict.model_fields),
    }}},
    "required": ["results"],
}


def normalize(v: Verdict) -> Verdict:
    clamp = lambda x: min(max(float(x), 0.0), 1.0)  # noqa: E731
    return v.model_copy(update={"false_positive_likelihood": clamp(v.false_positive_likelihood),
                                "confidence": clamp(v.confidence), "reasoning_ko": v.reasoning_ko[:REASON_MAX]})


def apply_floor(priority: str, floor: str) -> tuple[str, bool]:
    """(최종 우선순위, 하한이 이겼는지) — AI 가 하한보다 낮춰도 하한으로 올린다."""
    final = higher(priority, floor)
    return final, final != priority


@dataclass
class Decision:
    """인시던트 1건의 최종 판정(triage_results 1행)."""
    source: str                 # llm · cache · rule · refusal
    gate: str                   # G1 · G2 · G3 · G5 · NOKEY · LLM · LLM-FLOOR · LLM-ERR ...
    priority: str
    verdict: str
    recommended_playbook: str
    reasoning_ko: str
    false_positive_likelihood: float | None = None
    confidence: float | None = None
    model: str | None = None


def rule_decision(inc: dict, *, band: str | None, gate: str, reason: str) -> Decision:
    """LLM 없이 내리는 판정 — 하한, 다계층·강한 이상이면 최소 P3."""
    floor = inc["rule_floor"] or "P4"
    layers = inc["layers"]
    priority = floor
    if len(layers) >= 2 or band in ("z5", "z8"):
        priority = higher(priority, "P3")
    is_ip = inc["entity_key"].startswith("ip:")
    playbook = "block_ip" if priority in ("P1", "P2") and is_ip else "monitor"
    note = f"규칙 판정({reason}): 하한 {floor}, 계층 {len(layers)}개" + (f", 행위 이상 {band}" if band else "")
    return Decision("rule", gate, priority, "needs_review", playbook, note)
