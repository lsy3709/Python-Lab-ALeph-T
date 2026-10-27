"""AI 설정 화면(/settings) — 사용할 AI 교체, 공급자별 키·모델 입력·삭제, 연결 테스트, 웹 UI 설정 지우기.

사건 조회 화면(읽기 전용 연결)과 분리된 쓰기 경로다. 모든 POST 는 Origin·CSRF 검사를 통과해야 하고,
키는 화면에 다시 나오지 않는다(앞4…뒤4). 모든 화면 상단에 지금 쓰는 AI 를 표시한다(키 값은 제외).
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from flask import Flask, abort, redirect, render_template, request, session

from app.config import Settings
from app.console.security import csrf_token, csrf_valid, origin_allowed
from app.llm_probe import ProbeResult, estimate_cost, probe_claude, probe_gemini
from app.llm_settings import (KEY_NAMES, PROVIDERS, clear_provider_key, config_for_provider, effective_llm_config,
                              provider_status, reset_llm, save_llm, set_active_provider)
from app.secret_box import SecretBox
from app.settings_store import MySQLSettingsRepo, record_llm_call

log = logging.getLogger(__name__)
MESSAGES = {"saved": "저장했습니다.", "reset": "웹 UI 설정을 지웠습니다 — .env(환경변수) 값으로 돌아갔습니다.",
            "switched": "사용할 AI 를 바꿨습니다. 워커는 다음 주기(약 30초 안)부터 새 설정으로 판정합니다.",
            "cleared": "저장된 키를 지웠습니다(.env 에 키가 있으면 그것을 씁니다)."}
KEY_SOURCE_LABEL = {"ui": "웹 UI 저장(암호화)", "env": ".env·환경변수", None: "없음"}
PROVIDER_LABEL = {"claude": "Claude (Anthropic)", "gemini": "Gemini (Google)", "none": "AI 끄기 — 규칙 판정만"}
KEY_HINT = {"claude": "Anthropic 콘솔에서 발급한 키", "gemini": "Google AI Studio(aistudio.google.com/apikey)에서 발급한 키"}


@dataclass
class SettingsDeps:
    env: Settings
    open_conn: Callable[[], Any]                       # 쓰기 연결을 주는 컨텍스트 매니저
    box: SecretBox | None
    box_problem: str | None = None
    probes: dict[str, Callable[..., ProbeResult]] = field(
        default_factory=lambda: {"gemini": probe_gemini, "claude": probe_claude})
    repo_factory: Callable[[Any], Any] = MySQLSettingsRepo
    recorder: Callable[[Any, ProbeResult], None] = record_llm_call


def register(app: Flask, deps: SettingsDeps) -> None:
    @app.context_processor
    def ai_status():
        """모든 화면 상단의 AI 상태 — 설정 DB 를 못 읽어도 화면은 떠야 하므로 실패하면 표시만 생략."""
        try:
            with deps.open_conn() as conn:
                cfg = effective_llm_config(deps.env, deps.repo_factory(conn), deps.box)
        except Exception:
            log.warning("AI 상태를 읽지 못함", exc_info=True)
            return {"ai_status": None}
        return {"ai_status": {"provider": cfg.provider, "model": cfg.model, "reason": cfg.disabled_reason}}

    def page(repo, *, status=200, error=None, result=None, test_model=None):
        cfg = effective_llm_config(deps.env, repo, deps.box)
        cost = (estimate_cost(result.provider, result.model, result.input_tokens or 0, result.output_tokens or 0)
                if result and result.step == "샘플 호출" else None)
        return render_template("settings.html", cfg=cfg, cards=provider_status(deps.env, repo, deps.box),
                               csrf=csrf_token(session), providers=PROVIDERS, labels=PROVIDER_LABEL, hints=KEY_HINT,
                               key_labels=KEY_SOURCE_LABEL, box_ready=deps.box is not None,
                               box_problem=deps.box_problem, key_source=KEY_SOURCE_LABEL.get(cfg.key_source, "없음"),
                               msg=MESSAGES.get(request.args.get("msg", "")), error=error, result=result, cost=cost,
                               model_hints=result.models if result else [], test_model=test_model), status

    def guard() -> None:
        if not origin_allowed(request.headers.get("Origin")):
            abort(403, "허용되지 않은 출처(Origin)")
        if not csrf_valid(session, request.form.get("csrf")):
            abort(400, "보안 토큰이 맞지 않습니다 — 화면을 새로 고친 뒤 다시 시도하세요")

    @app.get("/settings")
    def settings_page():
        with deps.open_conn() as conn:
            return page(deps.repo_factory(conn))

    @app.post("/settings/llm")
    def settings_save():
        guard()
        with deps.open_conn() as conn:
            repo = deps.repo_factory(conn)
            current = effective_llm_config(deps.env, repo, deps.box)
            provider, model = request.form.get("provider", ""), request.form.get("model", "").strip()
            activate = request.form.get("activate", "1") != "0"   # "저장만" 버튼은 0
            if activate and provider != current.provider and model == (current.model or ""):
                model = ""  # 공급자를 바꾸며 이전 공급자의 모델 ID 가 그대로 넘어오면 저장하지 않는다
            try:
                save_llm(repo, deps.box, provider=provider, model=model, api_key=request.form.get("api_key", ""),
                         activate=activate)
            except ValueError as exc:  # 입력값(특히 키)은 되돌려 보여 주지 않는다
                return page(repo, status=400, error=str(exc))
        return redirect("/settings?msg=saved", code=303)

    @app.post("/settings/provider")
    def settings_switch():
        guard()
        with deps.open_conn() as conn:
            try:
                set_active_provider(deps.repo_factory(conn), request.form.get("provider", ""))
            except ValueError as exc:
                return page(deps.repo_factory(conn), status=400, error=str(exc))
        return redirect("/settings?msg=switched", code=303)

    @app.post("/settings/key/clear")
    def settings_clear_key():
        guard()
        with deps.open_conn() as conn:
            try:
                clear_provider_key(deps.repo_factory(conn), request.form.get("provider", ""))
            except ValueError as exc:
                return page(deps.repo_factory(conn), status=400, error=str(exc))
        return redirect("/settings?msg=cleared", code=303)

    @app.post("/settings/llm/reset")
    def settings_reset():
        guard()
        with deps.open_conn() as conn:
            reset_llm(deps.repo_factory(conn))
        return redirect("/settings?msg=reset", code=303)

    @app.post("/settings/llm/test")
    def settings_test():
        guard()
        with deps.open_conn() as conn:
            repo = deps.repo_factory(conn)
            provider = request.form.get("provider") or effective_llm_config(deps.env, repo, deps.box).provider
            if provider not in KEY_NAMES:
                return page(repo, status=400, error="연결 테스트를 할 수 없습니다 — 사용할 AI 가 꺼져 있습니다(none)")
            cfg = config_for_provider(deps.env, repo, deps.box, provider)
            if not cfg.api_key:
                return page(repo, status=400, error=f"연결 테스트를 할 수 없습니다 — {cfg.disabled_reason}")
            sample = request.form.get("sample") == "1"
            model = (request.form.get("model") or cfg.model or "").strip() or None
            if sample and not model:
                return page(repo, status=400, error="샘플 호출에는 모델이 필요합니다 — 먼저 모델 목록을 받아 고르세요")
            result = deps.probes[provider](cfg.api_key, model if sample else None)
            if result.step == "샘플 호출":
                try:
                    deps.recorder(conn, result)
                except Exception:  # 기록 실패가 화면을 막지 않게(내용은 서버 로그에만)
                    log.exception("연결 테스트 사용 기록 실패")
            return page(repo, result=result, test_model=model)
