"""자기차단(self-block) 회귀 테스트 — [129] 봇이 자기 IP 차단으로 죽는 문제.

실측 배경(2026-09-24): 브루트포스 탐지로 SOAR 가 127.0.0.1 을 차단하자,
같은 호스트에서 오는 **129 Wazuh 경보봇의 `/api/security/events` 기록 요청까지 403** 이 되어
워크플로우가 3회 연속 실패했다. 차단 예외가 `/api/admin/*` 뿐이었기 때문이다.

규칙: **유효한 API 키를 제시한 자동화(SOAR) 요청은 IP 차단의 영향을 받지 않는다.**
      키 없는 일반 요청은 그대로 차단된다(실차단 기능 자체는 유지).
"""
from datetime import timedelta

import pytest

from app import create_app
from extensions import db

ADMIN = {'X-API-Key': 'test-admin-key'}
SEC = {'X-API-Key': 'test-security-key'}
BAD = {'X-API-Key': 'wrong-key'}
IP = '203.0.113.77'


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


def block_self(client):
  """호출자 IP(테스트 클라이언트는 127.0.0.1)를 차단한다."""
  res = client.post('/api/admin/block', headers=ADMIN,
                    json={'ip': '127.0.0.1', 'reason': 'self-block 재현', 'severity': 'High'})
  assert res.status_code == 200, res.get_json()


def test_soar_can_record_events_even_when_own_ip_blocked(client):
  """★ 핵심: 자기 IP 가 차단돼도 SOAR 봇의 이벤트 기록은 성공해야 한다."""
  block_self(client)
  res = client.post('/api/security/events', headers=SEC, json={
      'student': 'lab', 'src_ip': IP, 'decision': 'deny',
      'severity': 'High', 'reason': 'wazuh alert', 'source': 'wazuh'})
  assert res.status_code == 201, res.get_json()


def test_admin_api_still_exempt(client):
  """기존 안전장치 — 관리자 API 는 계속 통과(복구 불능 방지)."""
  block_self(client)
  assert client.get('/api/admin/blocked', headers=ADMIN).status_code == 200
  assert client.post('/api/admin/unblock', headers=ADMIN,
                     json={'ip': '127.0.0.1'}).status_code == 200


def test_plain_request_from_blocked_ip_still_403(client):
  """실차단 기능 자체는 유지 — 키 없는 요청은 여전히 막힌다."""
  block_self(client)
  res = client.get('/')
  assert res.status_code == 403
  assert res.get_json()['blocked'] is True


def test_wrong_api_key_does_not_bypass_block(client):
  """틀린 키로는 차단을 우회할 수 없다."""
  block_self(client)
  assert client.post('/api/security/events', headers=BAD, json={
      'student': 'lab', 'src_ip': IP, 'decision': 'deny'}).status_code == 403
