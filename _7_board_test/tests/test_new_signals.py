"""S5·S6 탐지용 신호 2종 — 차단 재시도 · 관리자 인증 실패.

배경(문서 144 S5·S6): 지금은 두 상황이 **로그로 남지 않아** 탐지 룰을 만들 수 없다.
  · 차단된 IP 가 계속 두드리는 것(지속성) — 403 을 주고 끝
  · 관리자 API 키를 틀리는 것(인증 공격) — 401 을 주고 끝
둘 다 GELF 로 신고해 Graylog 가 집계할 수 있게 한다.

개인정보: 남기는 값은 출발지 IP·요청 경로뿐. 시도된 키 값은 절대 남기지 않는다.
"""
from datetime import timedelta

import pytest

from app import create_app
from extensions import db

ADMIN = {'X-API-Key': 'test-admin-key'}
SEC = {'X-API-Key': 'test-security-key'}
BAD = {'X-API-Key': 'totally-wrong-key'}


@pytest.fixture
def sent(monkeypatch):
  """send_gelf 호출을 가로채 기록한다(실제 UDP 전송 없이 검증)."""
  calls = []

  def fake(short_message, rule, **fields):
    calls.append({'msg': short_message, 'rule': rule, **fields})

  import controllers.gelf as gelf_mod
  monkeypatch.setattr(gelf_mod, 'send_gelf', fake)
  # 이미 import 해 간 모듈들도 교체
  import app as app_mod
  monkeypatch.setattr(app_mod, 'send_gelf', fake, raising=False)
  import controllers.security_controller as sec_mod
  monkeypatch.setattr(sec_mod, 'send_gelf', fake, raising=False)
  return calls


@pytest.fixture
def client(tmp_path):
  class TestConfig:
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{tmp_path / 'test.db'}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = 'test-secret-key'
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    SECURITY_API_KEY = 'test-security-key'
    ADMIN_API_KEY = 'test-admin-key'
    ADMIN_ALLOWLIST = []
    AUTO_POST_ON_DENY = False
    PUBLIC_API_KEY = None
    PUBLIC_API_URL = 'http://example.invalid/'

  application = create_app(TestConfig)
  yield application.test_client()
  with application.app_context():
    db.session.remove()
    db.engine.dispose()


def rules(calls):
  return [c['rule'] for c in calls]


def test_blocked_retry_is_reported(client, sent):
  """S5 — 차단된 IP 가 다시 두드리면 rule='blocked-retry' 로 신고한다."""
  assert client.post('/api/admin/block', headers=ADMIN,
                     json={'ip': '127.0.0.1', 'reason': 'S5 재현'}).status_code == 200
  sent.clear()
  assert client.get('/').status_code == 403          # 차단된 상태로 접근
  assert 'blocked-retry' in rules(sent), sent
  ev = [c for c in sent if c['rule'] == 'blocked-retry'][0]
  assert ev.get('src_ip') == '127.0.0.1'


def test_admin_auth_fail_is_reported(client, sent):
  """S6 — 관리자 API 키가 틀리면 rule='admin-auth-fail' 로 신고한다."""
  sent.clear()
  assert client.get('/api/security/events', headers=BAD) is not None   # 조회는 키 불필요
  assert client.post('/api/security/events', headers=BAD,
                     json={'student': 'x', 'src_ip': '1.2.3.4', 'decision': 'deny'}).status_code == 401
  assert 'admin-auth-fail' in rules(sent), sent


def test_no_key_value_in_signal(client, sent):
  """시도된 키 값 자체는 로그에 남기지 않는다."""
  sent.clear()
  client.post('/api/security/events', headers=BAD,
              json={'student': 'x', 'src_ip': '1.2.3.4', 'decision': 'deny'})
  blob = repr(sent)
  assert 'totally-wrong-key' not in blob, blob


def test_normal_traffic_emits_no_new_signal(client, sent):
  """정상 요청에는 두 신호가 붙지 않는다(오탐 방지)."""
  sent.clear()
  client.get('/')
  assert 'blocked-retry' not in rules(sent)
  assert 'admin-auth-fail' not in rules(sent)
