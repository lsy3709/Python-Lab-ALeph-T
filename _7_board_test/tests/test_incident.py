"""인시던트 티켓 규칙 테스트 — [114] 인시던트 API.

[129] Wazuh 연동 E2E 에서 실제로 드러난 결함 두 가지를 테스트로 고정한다.
  ① 심각도는 내려가지 않는다 — Critical 티켓에 나중에 Medium 경보가 합쳐져도 Critical 유지
  ② 종료(closed)된 티켓의 사건을 새 티켓이 다시 흡수하지 않는다

실습용 MySQL 을 건드리지 않도록 임시 SQLite 파일에 별도 앱을 띄워 검사한다.
"""
from datetime import timedelta

import pytest

from app import create_app
from extensions import db

ADMIN = {'X-API-Key': 'test-admin-key'}
SEC = {'X-API-Key': 'test-security-key'}


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


def record(client, key, severity):
  """n8n 이 하는 것처럼 보안 이벤트 1건 기록."""
  res = client.post('/api/security/events', headers=SEC, json={
      'student': 'lab', 'src_ip': key, 'decision': 'deny',
      'severity': severity, 'reason': f'{severity} test', 'source': 'wazuh'})
  assert res.status_code == 201


def upsert_incident(client, key, severity):
  res = client.post('/api/admin/incident', headers=ADMIN,
                    json={'src_ip': key, 'severity': severity, 'student': 'lab'})
  assert res.status_code in (200, 201)
  return res.get_json()


def test_severity_never_downgrades(client):
  record(client, 'wazuh:agent-a', 'Critical')
  first = upsert_incident(client, 'wazuh:agent-a', 'Critical')
  assert first['incident']['severity'] == 'Critical'

  record(client, 'wazuh:agent-a', 'Medium')          # 덜 심각한 경보가 나중에 합쳐짐
  second = upsert_incident(client, 'wazuh:agent-a', 'Medium')

  assert second['created'] is False                   # 같은 열린 티켓 갱신
  assert second['incident']['event_count'] == 2
  assert second['incident']['severity'] == 'Critical' # 내려가면 안 된다


def test_new_incident_after_close_ignores_old_events(client):
  record(client, '203.0.113.99', 'High')
  first = upsert_incident(client, '203.0.113.99', 'High')
  closed = client.post('/api/admin/incident/close', headers=ADMIN,
                       json={'id': first['incident']['id']})
  assert closed.status_code == 200

  record(client, '203.0.113.99', 'High')              # 종료 뒤 새 사건
  second = upsert_incident(client, '203.0.113.99', 'High')

  assert second['created'] is True
  assert second['incident']['id'] != first['incident']['id']
  assert second['incident']['event_count'] == 1       # 옛 사건(종료된 티켓 몫)은 제외
