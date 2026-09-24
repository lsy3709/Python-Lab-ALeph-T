"""엔트리포인트 — 앱 팩토리(create_app) 패턴.

구조
  config.py       설정(.env 로딩)
  extensions.py   db · jwt 인스턴스
  models/         User · Post · SecurityEvent
  controllers/    page · auth · post · security · public (블루프린트)
  templates/      화면 (partials/_nav.html = 공통 반응형 헤더)

실행:  python app.py   →  http://localhost:5000
"""
from flask import Flask, jsonify, request
from sqlalchemy import inspect, text

from config import Config
from controllers import all_blueprints
from extensions import db, jwt
from models import BlockedIP
from controllers.gelf import send_gelf


def _client_ip():
  """요청의 실제 클라이언트 IP. 프록시(n8n·nginx) 뒤면 X-Forwarded-For 첫 홉을 신뢰.
  (랩 한정 규칙 — 실서비스는 신뢰 프록시 목록으로 검증해야 스푸핑을 막는다.)"""
  xff = request.headers.get('X-Forwarded-For', '')
  if xff:
    return xff.split(',')[0].strip()
  return request.remote_addr or ''


def _ensure_schema():
  """기존 users 표에 role 관련 컬럼이 없으면 추가(가벼운 자동 마이그레이션).

  db.create_all() 은 '없는 표'만 만들고 '기존 표'는 손대지 않는다. 이미 운영 중인
  users 표에 role/감사 컬럼을 더하려면 ALTER 가 필요하므로, 여기서 컬럼 유무를
  검사해 없을 때만 한 번 추가한다(있으면 조용히 통과 — 여러 번 켜도 안전)."""
  cols = {c['name'] for c in inspect(db.engine).get_columns('users')}
  adds = {
      'role': "ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'",
      'role_granted_by': "ALTER TABLE users ADD COLUMN role_granted_by VARCHAR(80) NULL",
      'role_granted_at': "ALTER TABLE users ADD COLUMN role_granted_at DATETIME NULL",
      'role_reason': "ALTER TABLE users ADD COLUMN role_reason VARCHAR(200) NULL",
      # ── 계정 잠금(브루트포스 대응) ──
      'is_locked': "ALTER TABLE users ADD COLUMN is_locked TINYINT(1) NOT NULL DEFAULT 0",
      'locked_at': "ALTER TABLE users ADD COLUMN locked_at DATETIME NULL",
      'lock_reason': "ALTER TABLE users ADD COLUMN lock_reason VARCHAR(200) NULL",
      'failed_logins': "ALTER TABLE users ADD COLUMN failed_logins INT NOT NULL DEFAULT 0",
  }
  with db.engine.begin() as conn:
    for name, ddl in adds.items():
      if name not in cols:
        conn.execute(text(ddl))


def create_app(config_class=Config):
  app = Flask(__name__)
  app.config.from_object(config_class)

  # 확장 초기화
  db.init_app(app)
  jwt.init_app(app)

  # 컨트롤러(블루프린트) 등록
  for bp in all_blueprints:
    app.register_blueprint(bp)

  # 테이블 생성 (models 를 import 한 뒤여야 한다 — controllers 가 이미 import 함)
  with app.app_context():
    db.create_all()
    _ensure_schema()   # 기존 users 표에 role 컬럼 보강

  def _is_trusted_automation():
    """유효한 API 키(보안/관리자)를 제시한 요청인가 — SOAR 봇 판별용.

    키가 설정돼 있지 않으면(빈 값) 어떤 요청도 신뢰하지 않는다(fail-closed).
    """
    key = request.headers.get('X-API-Key', '')
    if not key:
      return False
    valid = {app.config.get('SECURITY_API_KEY') or '',
             app.config.get('ADMIN_API_KEY') or ''} - {''}
    return key in valid

  @app.before_request
  def _block_ip_guard():
    """실차단(active response): 차단된 IP 의 요청은 앱에 닿기 전에 403 으로 되돌린다.

    - 관리자 API(/api/admin/*) 는 예외 — 그래야 운영자·n8n 이 차단/해제를 계속 할 수 있다
      (자기 자신을 잠가 복구 불능이 되는 것을 막는 안전장치).
    - ★ **유효한 API 키를 제시한 자동화(SOAR) 요청도 예외**다. 2026-09-24 실측:
      브루트포스 대응으로 SOAR 가 127.0.0.1 을 차단하자, 같은 호스트에서 오던
      [129] Wazuh 경보봇의 `/api/security/events` 기록까지 403 이 되어 봇이 3회 연속
      실패했다(자기차단). 사람이 아닌 인증된 봇은 차단 대상이 아니다.
    - 매 요청 blocked_ips 표를 조회한다. 랩 규모에선 충분하고, 실서비스는
      캐시(예: Redis)나 방화벽(nftables) 계층으로 올려야 한다."""
    if request.path.startswith('/api/admin'):
      return None
    if _is_trusted_automation():
      return None
    ip = _client_ip()
    if ip and db.session.get(BlockedIP, ip):
      return jsonify({'msg': '차단된 IP 입니다(관리자에게 문의).', 'ip': ip, 'blocked': True}), 403
    return None

  @app.after_request
  def _web_scan_probe(response):
    """스캐너(nikto·dirbuster 등)는 없는 경로에 404 를 대량 유발한다.
    404 를 GELF(rule='web-scan')로 신고 → Graylog src_ip 집계가 '한 IP 404 폭주'를 탐지."""
    try:
      if response.status_code == 404 and not request.path.startswith('/api/admin'):
        send_gelf(f"404 probe {request.path[:80]}", rule='web-scan',
                  src_ip=_client_ip(), path=request.path[:120], code=404)
    except Exception:
      pass
    return response

  return app


app = create_app()


if __name__ == '__main__':
  # host='0.0.0.0' 이면 같은 공유기의 다른 기기에서도 접속 가능.
  # 도커 안 n8n 에서는 http://host.docker.internal:5000 으로 부른다.
  app.run(debug=True, host='0.0.0.0', port=5000)
