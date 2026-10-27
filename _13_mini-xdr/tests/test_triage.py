"""트리아지 실행기 — 깔때기 G1~G7·묶음·라우팅·가드레일·재시도·거절·예산·지문 중복·dry-run (가짜 저장소·가짜 LLM)."""
from datetime import datetime, timedelta, timezone
from ipaddress import ip_network

from app.correlator import EventRow
from app.llm_triage import LLMResult
from app.triage import LLMRoute, TriageConfig, run_triage, triage_summary
from app.triage_schema import Verdict

NOW = datetime(2026, 10, 27, 2, 0, 0, tzinfo=timezone.utc)
CFG = TriageConfig(whitelist=(ip_network("127.0.0.1/32"),))


def inc(iid, ip="203.0.113.9", layers=("app", "network"), floor="P4", level=None, fp=None, **kw):
    row = {"id": iid, "entity_key": f"ip:{ip}", "layers": list(layers), "event_count": 20, "max_level": level,
           "rule_floor": floor, "current_priority": floor, "fingerprint": fp or f"fp{iid}",
           "last_triaged_at": None, "material_state": None, "opened_at": NOW - timedelta(minutes=5),
           "last_event_at": NOW - timedelta(minutes=1)}
    row.update(kw)
    return row


def events(ip, signals=("web-scan", "ids-alert")):
    t = NOW - timedelta(minutes=5)
    return [EventRow(id=i, ts=t + timedelta(seconds=i), layer="app", source="board", event_type=s, src_ip=ip)
            for i, s in enumerate(signals)]


class FakeStore:
    def __init__(self, incidents, signals=None, cache=None, usage=None):
        self.incidents = incidents
        self.signals = signals or {}
        self.cache = cache or {}
        self.usage = usage or {"day": 0, "hour": 0, "recent_errors": 0}
        self.saved, self.calls, self.hits, self.put = [], [], [], []

    def triage_candidates(self, since, limit):
        return self.incidents[:limit] if limit else list(self.incidents)

    def card_inputs(self, iid):
        row = next(i for i in self.incidents if i["id"] == iid)
        ip = row["entity_key"][3:]
        sig = self.signals.get(iid, ("web-scan", "ids-alert"))
        return {"summary": [{"layer": "app", "source": "board", "sig": s, "n": 1, "max_level": None, "mitre": None}
                            for s in sig], "events": events(ip, sig), "anomalies": [], "users": [],
                "signals": list(sig)}

    def get_cached_verdict(self, fp, now):
        return self.cache.get(fp)

    def hit_cached_verdict(self, fp):
        self.hits.append(fp)

    def put_cached_verdict(self, fp, verdict, model, expires_at):
        self.put.append((fp, verdict, model))

    def llm_usage(self, now):
        return dict(self.usage)

    def record_llm_call(self, result, incidents_in_batch, gate_reason):
        self.calls.append((result.model, result.status, incidents_in_batch, gate_reason))

    def save_decision(self, inc, decision, material, now):
        self.saved.append((inc["id"], decision))


class FakeTriager:
    provider = "gemini"

    def __init__(self, answers):
        self.answers = list(answers)      # 호출마다 하나씩: (status, {ref: dict}) 또는 함수
        self.requests = []

    def triage(self, system, user, model):
        self.requests.append((model, user))
        status, verdicts = self.answers.pop(0)
        res = LLMResult("gemini", model, status, input_tokens=300, output_tokens=60, cache_read=1800)
        res.verdicts = {ref: Verdict(ref=ref, **v) for ref, v in verdicts.items()}
        return res


def v(priority="P3", conf=0.8, reason="ip_1 에서 스캔 뒤 IDS 경보", playbook="monitor"):
    return {"priority": priority, "verdict": "true_positive", "false_positive_likelihood": 0.2,
            "reasoning_ko": reason, "recommended_playbook": playbook, "confidence": conf}


def route(answers, escalate=None):
    return LLMRoute(FakeTriager(answers), "gemini-3.5-flash-lite", escalate)


def decisions(store):
    return {iid: d for iid, d in store.saved}


def test_debounce_skips_unchanged_incident():
    from app.gate import material_state
    row = inc(1, last_triaged_at=NOW - timedelta(minutes=1))
    row["material_state"] = material_state(row, None)
    store = FakeStore([row])
    rep = run_triage(store, None, CFG, NOW)
    assert store.saved == [] and rep.skipped == {"unchanged": 1}


def test_whitelist_rule_and_cache_gates_never_call_llm():
    store = FakeStore([inc(1, ip="127.0.0.1", floor="P2", level=10),
                       inc(2, signals=None, layers=("app",)),
                       inc(3, fp="known")],
                      signals={2: ("login-bruteforce", "login-success")},
                      cache={"known": {"priority": "P3", "verdict": "true_positive", "false_positive_likelihood": 0.1,
                                       "reasoning_ko": "ip_1 지문 캐시", "recommended_playbook": "monitor",
                                       "confidence": 0.9, "model": "gemini-3.5-flash-lite"}})
    r = route([])
    rep = run_triage(store, r, CFG, NOW)
    d = decisions(store)
    assert (d[1].gate, d[1].verdict, d[1].priority) == ("G1", "benign", "P2")     # 화이트리스트라도 하한은 지킨다
    assert (d[2].gate, d[2].priority, d[2].recommended_playbook) == ("G2", "P1", "lock_account")
    assert (d[3].source, d[3].gate, d[3].priority) == ("cache", "G3", "P3") and store.hits == ["known"]
    assert r.triager.requests == [] and rep.gates == {"G1": 1, "G2": 1, "G3": 1}


def test_no_key_falls_back_to_rule():
    store = FakeStore([inc(1, floor="P2", level=10)])
    run_triage(store, None, CFG, NOW)
    d = decisions(store)[1]
    assert (d.source, d.gate, d.priority, d.recommended_playbook) == ("rule", "NOKEY", "P2", "block_ip")


def test_gray_zone_batched_masked_cached_and_unmasked_on_save():
    store = FakeStore([inc(i, ip=f"203.0.113.{i}") for i in (1, 2, 3)])
    r = route([("ok", {f"INC-{i}": v(reason=f"ip_{i} 스캔 정황") for i in (1, 2, 3)})])
    rep = run_triage(store, r, CFG, NOW)
    assert len(r.triager.requests) == 1                                   # G6: 3건을 한 요청
    sent = r.triager.requests[0][1]
    assert "203.0.113." not in sent and '"ref":"INC-2"' in sent           # 마스킹된 카드만 나감
    d = decisions(store)
    assert all(x.source == "llm" and x.gate == "LLM" for x in d.values())
    assert "203.0.113." in d[1].reasoning_ko                              # 저장 전 복원
    assert len(store.put) == 3 and "203.0.113." not in str(store.put)     # 캐시에는 가린 근거만
    assert store.calls == [("gemini-3.5-flash-lite", "ok", 3, "gray_zone")]
    assert rep.llm_requests == 1 and rep.tokens == (300, 60, 1800)


def test_floor_wins_over_lower_llm_priority():
    store = FakeStore([inc(1, floor="P2", level=10)])
    run_triage(store, route([("ok", {"INC-1": v(priority="P4")})]), CFG, NOW)
    d = decisions(store)[1]
    assert (d.priority, d.gate) == ("P2", "LLM-FLOOR")


def test_urgent_singles_and_escalation_routing():
    store = FakeStore([inc(1, floor="P2", level=10), inc(2, floor="P2", level=10),
                       inc(3, layers=("app", "network", "behavior"))])
    r = route([("ok", {"INC-1": v()}), ("ok", {"INC-2": v()}), ("ok", {"INC-3": v()})], escalate="big-model")
    run_triage(store, r, CFG, NOW)
    models = [m for m, _ in r.triager.requests]
    assert len(models) == 3                                    # 하한 P1·P2 와 3계층은 단건
    assert models.count("big-model") == 1                      # 3계층만 승급(하한 P2 는 기본 모델)


def test_low_confidence_reasks_escalate_model_once():
    store = FakeStore([inc(1)])
    r = route([("ok", {"INC-1": v(conf=0.4)}), ("ok", {"INC-1": v(priority="P2", conf=0.9)})], escalate="big-model")
    run_triage(store, r, CFG, NOW)
    assert [m for m, _ in r.triager.requests] == ["gemini-3.5-flash-lite", "big-model"]
    d = decisions(store)[1]
    assert (d.priority, d.model) == ("P2", "big-model")
    assert [c[3] for c in store.calls] == ["gray_zone", "escalate_low_conf"]


def test_invalid_retried_once_then_rule():
    store = FakeStore([inc(1)])
    r = route([("invalid", {}), ("invalid", {})])
    run_triage(store, r, CFG, NOW)
    assert len(r.triager.requests) == 2
    d = decisions(store)[1]
    assert (d.source, d.gate) == ("rule", "LLM-ERR")
    assert [c[1] for c in store.calls] == ["invalid", "invalid"]


def test_refusal_is_a_normal_branch():
    store = FakeStore([inc(1)])
    run_triage(store, route([("refusal", {})]), CFG, NOW)
    d = decisions(store)[1]
    assert (d.source, d.gate) == ("refusal", "LLM-REFUSAL")


def test_budget_and_breaker_block_calls():
    for usage in ({"day": 200, "hour": 0, "recent_errors": 0}, {"day": 0, "hour": 0, "recent_errors": 3}):
        store = FakeStore([inc(1)], usage=usage)
        r = route([])
        run_triage(store, r, CFG, NOW)
        assert r.triager.requests == [] and decisions(store)[1].gate == "G5"


def test_same_fingerprint_in_one_run_asks_once():
    store = FakeStore([inc(1, ip="203.0.113.1", fp="same"), inc(2, ip="203.0.113.2", fp="same")])
    r = route([("ok", {"INC-1": v()})])
    rep = run_triage(store, r, CFG, NOW)
    d = decisions(store)
    assert len(r.triager.requests) == 1 and (d[1].source, d[2].source) == ("llm", "cache")
    assert rep.gates["G3"] == 1


def test_dry_run_counts_without_writing_or_calling():
    store = FakeStore([inc(1), inc(2, layers=("app",)), inc(3, ip="127.0.0.1")])
    r = route([])
    rep = run_triage(store, r, CFG, NOW, dry_run=True)
    assert store.saved == [] and store.calls == [] and r.triager.requests == []
    assert rep.gates == {"LLM": 1, "G2": 1, "G1": 1} and rep.llm_requests == 1
    assert triage_summary(rep).startswith("[판정] 대상 3")
