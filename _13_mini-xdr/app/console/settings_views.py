"""AI 설정 화면(/settings) — 공급자·모델·키 교체, 연결 테스트, 웹 UI 설정 지우기.

사건 조회 화면(읽기 전용 연결)과 분리된 쓰기 경로다. 모든 POST 는 Origin·CSRF 검사를 통과해야 하고,
키는 화면에 다시 나오지 않는다(앞4…뒤4).
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
from app.llm_settings import PROVIDERS, effective_llm_config, reset_llm, save_llm
from app.secret_box import SecretBox
from app.settings_store import MySQLSettingsRepo, record_llm_call

log = logging.getLogger(__name__)
MESSAGES = {"saved": "저장했습니다.", "reset": "웹 UI 설정을 지웠습니다 — .env(환경변수) 값으로 돌아갔습니다."}
KEY_SOURCE_LABEL = {"ui": "웹 UI 저장(암호화)", "env": ".env·환경변수", None: "없음"}


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
    def page(cfg, *, status=200, error=None, result=None, test_model=None):
        hints = result.models if result else []
        cost = (estimate_cost(result.provider, result.model, result.input_tokens or 0, result.output_tokens or 0)
                if result and result.step == "샘플 호출" else None)
        return render_template("settings.html", cfg=cfg, csrf=csrf_token(session), providers=PROVIDERS,
                               box_ready=deps.box is not None, box_problem=deps.box_problem,
                               key_source=KEY_SOURCE_LABEL.get(cfg.key_source, "없음"),
                               msg=MESSAGES.get(request.args.get("msg", "")), error=error, result=result,
                               cost=cost, model_hints=hints, test_model=test_model or cfg.model or ""), status

    def guard() -> None:
        if not origin_allowed(request.headers.get("Origin")):
            abort(403, "허용되지 않은 출처(Origin)")
        if not csrf_valid(session, request.form.get("csrf")):
            abort(400, "보안 토큰이 맞지 않습니다 — 화면을 새로 고친 뒤 다시 시도하세요")

    @app.get("/settings")
    def settings_page():
        with deps.open_conn() as conn:
            cfg = effective_llm_config(deps.env, deps.repo_factory(conn), deps.box)
        return page(cfg)

    @app.post("/settings/llm")
    def settings_save():
        guard()
        with deps.open_conn() as conn:
            repo = deps.repo_factory(conn)
            try:
                save_llm(repo, deps.box, provider=request.form.get("provider", ""),
                         model=request.form.get("model", ""), api_key=request.form.get("api_key", ""))
            except ValueError as exc:  # 입력값(특히 키)은 되돌려 보여 주지 않는다
                return page(effective_llm_config(deps.env, repo, deps.box), status=400, error=str(exc))
        return redirect("/settings?msg=saved", code=303)

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
            cfg = effective_llm_config(deps.env, deps.repo_factory(conn), deps.box)
            if cfg.provider == "none" or not cfg.api_key:
                return page(cfg, status=400, error=f"연결 테스트를 할 수 없습니다 — {cfg.disabled_reason}")
            sample = request.form.get("sample") == "1"
            model = (request.form.get("model") or cfg.model or "").strip() or None
            if sample and not model:
                return page(cfg, status=400, error="샘플 호출에는 모델이 필요합니다 — 먼저 모델 목록을 받아 고르세요")
            result = deps.probes[cfg.provider](cfg.api_key, model if sample else None)
            if result.step == "샘플 호출":
                try:
                    deps.recorder(conn, result)
                except Exception:  # 기록 실패가 화면을 막지 않게(내용은 서버 로그에만)
                    log.exception("연결 테스트 사용 기록 실패")
        return page(cfg, result=result, test_model=model)
