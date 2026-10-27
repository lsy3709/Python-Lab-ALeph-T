"""트리아지 실행기 — 호출 깔때기 G1~G7 을 거친 회색지대만 LLM 에 묻고, 모든 판정에 규칙 하한을 건다([186] 4·5).

순서: G4 디바운스 → G1 화이트리스트 → G2 규칙 결론 → G3 지문 캐시 → (키 없음) → 같은 주기 같은 지문은 한 번만
     → G6 묶음(하한 P1·P2·3계층은 단건) → G5 예산·서킷 → G7 라우팅 → 스키마 오류 1회 재시도 → 확신 낮으면 승급 재질문.
사후 추정: python -m app.triage --dry-run [--recent N]   (LLM 호출·저장 없이 관문 분포만)
실제 판정: python -m app.triage --recent N
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol

from app.card import build_card
from app.correlator import higher
from app.gate import anomaly_band, debounce, in_whitelist, material_state, rule_conclusion
from app.masker import Masker, find_leaks
from app.prompt import system_prompt, user_message
from app.timeline import build_timeline
from app.triage_schema import Decision, apply_floor, rule_decision

TIMELINE_SCAN = 200   # 실패 뒤 성공 판정·카드용 타임라인을 접을 최대 줄 수


@dataclass(frozen=True)
class TriageConfig:
    lookback: timedelta = timedelta(minutes=60)
    cooldown: timedelta = timedelta(minutes=5)
    batch_size: int = 5
    cache_ttl: timedelta = timedelta(hours=24)
    max_daily: int = 200
    max_hourly: int = 60
    breaker_errors: int = 3
    escalate_below: float = 0.6
    whitelist: tuple = ()


@dataclass
class LLMRoute:
    triager: Any                    # ClaudeTriager · GeminiTriager
    model: str
    escalate_model: str | None = None


@dataclass
class TriageReport:
    candidates: int = 0
    skipped: Counter = field(default_factory=Counter)
    gates: Counter = field(default_factory=Counter)
    llm_requests: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    tokens_cache: int = 0

    @property
    def tokens(self) -> tuple[int, int, int]:
        return self.tokens_in, self.tokens_out, self.tokens_cache


class TriageStore(Protocol):
    def triage_candidates(self, since: datetime | None, limit: int | None) -> list[dict]: ...
    def card_inputs(self, incident_id: int) -> dict: ...
    def get_cached_verdict(self, fingerprint: str, now: datetime) -> dict | None: ...
    def hit_cached_verdict(self, fingerprint: str) -> None: ...
    def put_cached_verdict(self, fingerprint: str, verdict: dict, model: str, expires_at: datetime) -> None: ...
    def llm_usage(self, now: datetime) -> dict: ...
    def record_llm_call(self, result, incidents_in_batch: int, gate_reason: str) -> None: ...
    def save_decision(self, inc: dict, decision: Decision, material: dict, now: datetime) -> None: ...


@dataclass
class _Item:
    inc: dict
    data: dict
    timeline: list
    material: dict
    band: str | None

    @property
    def floor(self) -> str:
        return self.inc["rule_floor"] or "P4"

    @property
    def urgent(self) -> bool:
        return self.floor in ("P1", "P2") or len(self.inc["layers"]) >= 3


def _from_cache(cached: dict) -> Decision:
    return Decision("cache", "G3", cached["priority"], cached["verdict"], cached["recommended_playbook"],
                    cached["reasoning_ko"] + " (지문 캐시 재사용)", cached.get("false_positive_likelihood"),
                    cached.get("confidence"), cached.get("model"))


def _cache_dict(verdict, model: str) -> dict:
    """캐시에는 가린 근거(토큰)를 넣는다 — 다른 엔티티가 재사용하므로 원본 값이 있으면 안 된다."""
    return {"priority": verdict.priority, "verdict": verdict.verdict, "recommended_playbook": verdict.recommended_playbook,
            "reasoning_ko": verdict.reasoning_ko, "false_positive_likelihood": verdict.false_positive_likelihood,
            "confidence": verdict.confidence, "model": model}


class _Runner:
    def __init__(self, store, route: LLMRoute | None, cfg: TriageConfig, now: datetime, dry_run: bool) -> None:
        self.store, self.route, self.cfg, self.now, self.dry = store, route, cfg, now, dry_run
        self.rep = TriageReport()
        self.usage = store.llm_usage(now) if route is not None and not dry_run else {}

    # ── 공통 ───────────────────────────────────────────
    def finish(self, it: _Item, d: Decision) -> None:
        d = replace(d, priority=higher(d.priority, it.floor))   # 어떤 관문이든 규칙 하한 이상
        self.rep.gates[d.gate] += 1
        if not self.dry:
            self.store.save_decision(it.inc, d, it.material, self.now)

    def pre_llm(self, it: _Item) -> Decision | None:
        if in_whitelist(it.inc["entity_key"], list(self.cfg.whitelist)):
            return Decision("rule", "G1", "P4", "benign", "none", "화이트리스트(G1) — 알려진 정상 출발지")
        decided = rule_conclusion(it.inc, it.band, [t.signal for t in it.timeline])
        if decided:
            return decided
        cached = self.store.get_cached_verdict(it.inc["fingerprint"], self.now)
        if cached:
            if not self.dry:
                self.store.hit_cached_verdict(it.inc["fingerprint"])
            return _from_cache(cached)
        if self.route is None and not self.dry:
            return rule_decision(it.inc, band=it.band, gate="NOKEY", reason="LLM 키 없음")
        return None

    # ── LLM ────────────────────────────────────────────
    def budget_ok(self) -> bool:
        u = self.usage
        return (u.get("day", 0) < self.cfg.max_daily and u.get("hour", 0) < self.cfg.max_hourly
                and u.get("recent_errors", 0) < self.cfg.breaker_errors)

    def call(self, user: str, model: str, n: int, reason: str):
        res = self.route.triager.triage(system_prompt(), user, model)
        self.store.record_llm_call(res, n, reason)
        self.usage["day"] = self.usage.get("day", 0) + 1
        self.usage["hour"] = self.usage.get("hour", 0) + 1
        self.usage["recent_errors"] = self.usage.get("recent_errors", 0) + 1 if res.status == "error" else 0
        self.rep.llm_requests += 1
        self.rep.tokens_in += res.input_tokens
        self.rep.tokens_out += res.output_tokens
        self.rep.tokens_cache += res.cache_read
        return res

    def groups(self, queued: list[_Item]) -> list[tuple[list[_Item], str, str]]:
        r = self.route
        out = []
        for it in (x for x in queued if x.urgent):   # G6: 급한 것은 단건 즉시
            escalate = r is not None and r.escalate_model and (it.floor == "P1" or len(it.inc["layers"]) >= 3)
            reason = ("escalate_floor" if it.floor == "P1" else "escalate_layers") if escalate else "gray_zone"
            out.append(([it], r.escalate_model if escalate else (r.model if r else ""), reason))
        normal = [x for x in queued if not x.urgent]
        for i in range(0, len(normal), self.cfg.batch_size):
            out.append((normal[i:i + self.cfg.batch_size], r.model if r else "", "gray_zone"))
        return out

    def ask(self, group: list[_Item], model: str, reason: str) -> tuple[dict[int, Decision], dict[str, dict]]:
        if not self.budget_ok():  # G5
            return {it.inc["id"]: rule_decision(it.inc, band=it.band, gate="G5", reason="예산·서킷") for it in group}, {}
        masker = Masker()  # 묶음 안에서 토큰을 공유 — 카드마다 ip_1 을 새로 매기면 서로 다른 IP 가 같은 토큰이 된다
        cards = [build_card(f"INC-{it.inc['id']}", it.inc, it.data["summary"], it.timeline,
                            it.data["events"][0].ts if it.data["events"] else None, it.data["anomalies"],
                            it.data["users"], masker) for it in group]
        user = user_message(cards)
        if find_leaks(user, masker.originals()):  # 보내기 직전 마지막 점검
            return {it.inc["id"]: rule_decision(it.inc, band=it.band, gate="MASK-LEAK", reason="마스킹 누출 차단")
                    for it in group}, {}
        res = self.call(user, model, len(group), reason)
        if res.status == "invalid":
            res = self.call(user, model, len(group), "retry_invalid")
        decisions, cache = {}, {}
        for it, card in zip(group, cards):
            iid = it.inc["id"]
            if res.status == "refusal":
                decisions[iid] = replace(rule_decision(it.inc, band=it.band, gate="LLM-REFUSAL", reason="LLM 거절"),
                                         source="refusal")
                continue
            verdict = res.verdicts.get(card["ref"]) if res.status == "ok" else None
            if verdict is None:
                decisions[iid] = rule_decision(it.inc, band=it.band, gate="LLM-ERR", reason=f"LLM {res.status}")
                continue
            used = model
            r = self.route
            if (verdict.confidence < self.cfg.escalate_below and r.escalate_model and model != r.escalate_model
                    and self.budget_ok()):  # G7: 확신이 낮으면 승급 모델로 한 번 더
                again = self.call(user_message([card]), r.escalate_model, 1, "escalate_low_conf")
                if again.status == "ok" and card["ref"] in again.verdicts:
                    verdict, used = again.verdicts[card["ref"]], r.escalate_model
            final, floored = apply_floor(verdict.priority, it.floor)
            decisions[iid] = Decision("llm", "LLM-FLOOR" if floored else "LLM", final, verdict.verdict,
                                      verdict.recommended_playbook, masker.unmask(verdict.reasoning_ko),
                                      verdict.false_positive_likelihood, verdict.confidence, used)
            cache[it.inc["fingerprint"]] = _cache_dict(verdict, used)
        return decisions, cache

    # ── 실행 ───────────────────────────────────────────
    def run(self, candidates: list[dict]) -> TriageReport:
        queued: list[_Item] = []
        leaders: dict[str, _Item] = {}
        followers: dict[str, list[_Item]] = defaultdict(list)
        for inc in candidates:
            self.rep.candidates += 1
            data = self.store.card_inputs(inc["id"])
            band = anomaly_band(data["signals"])
            material = material_state(inc, band)
            skip = debounce(inc, material, self.now, self.cfg.cooldown)
            if skip:
                self.rep.skipped[skip] += 1
                continue
            timeline, _ = build_timeline(data["events"], TIMELINE_SCAN)
            it = _Item(inc, data, timeline, material, band)
            decided = self.pre_llm(it)
            if decided:
                self.finish(it, decided)
                continue
            fp = inc["fingerprint"]
            if fp in leaders:  # 같은 주기 같은 지문 — 한 번만 묻고 답을 나눠 쓴다
                followers[fp].append(it)
                continue
            leaders[fp] = it
            queued.append(it)
        verdict_by_fp: dict[str, dict] = {}
        results: dict[int, Decision] = {}
        for group, model, reason in self.groups(queued):
            if self.dry:
                self.rep.llm_requests += 1
                self.rep.gates["LLM"] += len(group)
                continue
            decisions, cache = self.ask(group, model, reason)
            for it in group:
                self.finish(it, decisions[it.inc["id"]])
                results[it.inc["id"]] = decisions[it.inc["id"]]
            for fp, v in cache.items():
                verdict_by_fp[fp] = v
                self.store.put_cached_verdict(fp, v, v["model"], self.now + self.cfg.cache_ttl)
        for fp, items in followers.items():
            for it in items:
                if self.dry:
                    self.rep.gates["G3"] += 1
                elif fp in verdict_by_fp:
                    self.finish(it, _from_cache(verdict_by_fp[fp]))
                else:
                    lead = results.get(leaders[fp].inc["id"])
                    self.finish(it, rule_decision(it.inc, band=it.band, gate=lead.gate if lead else "LLM-ERR",
                                                  reason="같은 지문의 LLM 판정 실패"))
        return self.rep


def run_triage(store: TriageStore, route: LLMRoute | None, cfg: TriageConfig, now: datetime, *,
               dry_run: bool = False, recent: int | None = None) -> TriageReport:
    """recent 가 없으면 열린·최근(lookback) 인시던트, 있으면 최근 N건(lookback 무시)."""
    candidates = store.triage_candidates(None, recent) if recent else store.triage_candidates(now - cfg.lookback, None)
    return _Runner(store, route, cfg, now, dry_run).run(candidates)


def triage_summary(r: TriageReport) -> str:
    gates = ", ".join(f"{g} {n}" for g, n in sorted(r.gates.items())) or "없음"
    return (f"[판정] 대상 {r.candidates} · 건너뜀 {sum(r.skipped.values())} · 관문 {gates} · LLM 요청 {r.llm_requests} · "
            f"토큰 입력 {r.tokens_in}/출력 {r.tokens_out}/캐시 {r.tokens_cache}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="mini-xdr 트리아지(호출 깔때기)")
    parser.add_argument("--dry-run", action="store_true", help="LLM 호출·저장 없이 관문 분포만")
    parser.add_argument("--recent", type=int, default=None, help="최근 N건(lookback 무시)")
    args = parser.parse_args(argv)
    from app.config import Settings
    from app.worker import build_store, llm_route, triage_config

    settings = Settings()
    store = build_store(settings)
    try:
        route = llm_route(settings, store)
        rep = run_triage(store, route, triage_config(settings), datetime.now(timezone.utc), dry_run=args.dry_run,
                         recent=args.recent)
    finally:
        store.close()
    print(("[dry-run] " if args.dry_run else "") + triage_summary(rep))
    if args.dry_run and rep.candidates:
        llm = rep.gates.get("LLM", 0)
        print(f"LLM 에 갈 인시던트 {llm}/{rep.candidates} ({llm / rep.candidates:.1%}), 묶음 후 요청 {rep.llm_requests}회")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
