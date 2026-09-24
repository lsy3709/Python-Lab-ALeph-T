"""대시보드용 인시던트 티켓 조회 API 테스트 — [114] 대시보드 연동.

대시보드(/dashboard)는 로그인·API 키 없이 열리는 수업 확인용 화면이라
`/api/security/events` 처럼 **조회만 키 없이** 허용한다(쓰기는 그대로 관리자 키).
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


def seed(client, src_ip, severity='High'):
  """보안 이벤트 1건 + 그 출발지의 인시던트 티켓 1건."""
  res = client.post('/api/security/events', headers=SEC, json={
      'student': 'lab', 'src_ip': src_ip, 'decision': 'deny',
      'severity': severity, 'reason': f'{severity} seed', 'source': 'ip-guard'})
  assert res.status_code == 201
  res = client.post('/api/admin/incident', headers=ADMIN,
                    json={'src_ip': src_ip, 'severity': severity, 'student': 'lab'})
  assert res.status_code in (200, 201)
  return res.get_json()['incident']


def test_list_incidents_without_api_key(client):
  """대시보드는 키가 없다 — 그래도 목록이 보여야 한다."""
  inc = seed(client, '203.0.113.1', 'High')

  res = client.get('/api/security/incidents')          # 헤더 없음
  assert res.status_code == 200
  body = res.get_json()
  assert body['count'] == 1
  assert body['incidents'][0]['id'] == inc['id']
  assert body['incidents'][0]['src_ip'] == '203.0.113.1'
  assert body['incidents'][0]['status'] == 'open'


def test_list_is_newest_first_and_limited(client):
  for i in range(1, 4):
    seed(client, f'203.0.113.{10 + i}')

  res = client.get('/api/security/incidents?limit=2')
  body = res.get_json()
  assert body['count'] == 2
  ids = [x['id'] for x in body['incidents']]
  assert ids == sorted(ids, reverse=True)              # 최신순


def test_status_filter(client):
  a = seed(client, '203.0.113.21')
  seed(client, '203.0.113.22')
  assert client.post('/api/admin/incident/close', headers=ADMIN,
                     json={'id': a['id']}).status_code == 200

  op = client.get('/api/security/incidents?status=open').get_json()
  cl = client.get('/api/security/incidents?status=closed').get_json()
  assert [x['src_ip'] for x in op['incidents']] == ['203.0.113.22']
  assert [x['src_ip'] for x in cl['incidents']] == ['203.0.113.21']


def test_summary_counts_and_severity(client):
  a = seed(client, '203.0.113.31', 'Critical')
  seed(client, '203.0.113.32', 'High')
  client.post('/api/admin/incident/close', headers=ADMIN, json={'id': a['id']})

  body = client.get('/api/security/incidents/summary').get_json()
  assert body['by_status'] == {'open': 1, 'closed': 1}
  assert body['open_by_severity'].get('High') == 1     # 열린 것만 심각도 분포
  assert body['open_by_severity'].get('Critical') is None


def test_read_endpoint_does_not_open_writes(client):
  """조회용 경로가 생겨도 생성·종료는 여전히 관리자 키가 필요하다."""
  seed(client, '203.0.113.41')
  assert client.post('/api/security/incidents').status_code in (404, 405)
  assert client.post('/api/admin/incident', json={'src_ip': '203.0.113.41'}).status_code == 401
