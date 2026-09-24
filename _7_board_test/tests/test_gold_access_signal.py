"""S9 탐지용 신호 — 골드 전용 자료 열람(`rule='gold-access'`).

배경(문서 144 S9): 권한을 올린 직후 민감 자료를 열람하는 흐름을 잡으려면
`priv-unauthorized-admin`(권한 이상) 뿐 아니라 **"실제로 봤다"** 는 신호가 필요하다.
지금은 골드 API 가 열람돼도 아무 기록이 남지 않아 두 신호를 이을 수 없다.

개인정보: 남기는 값은 계정명·등급·출발지 IP 뿐이다. 게시글 내용은 남기지 않는다.
"""
from datetime import timedelta

import pytest

from app import create_app
from extensions import db

PW = 'pw12345'
ADMIN_KEY = {'X-API-Key': 'test-admin-key'}


@pytest.fixture
def sent(monkeypatch):
  """send_gelf 호출을 가로채 기록한다(실제 UDP 전송 없이 검증)."""
  calls = []

  def fake(short_message, rule, **fields):
    calls.append({'msg': short_message, 'rule': rule, **fields})

  import controllers.gelf as gelf_mod
  monkeypatch.setattr(gelf_mod, 'send_gelf', fake)
  import controllers.gold_controller as gold_mod
  monkeypatch.setattr(gold_mod, 'send_gelf', fake, raising=False)
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


def make_user(client, username, role=None):
  client.post('/api/auth/register', json={'username': username, 'password': PW})
  if role:
    client.post('/api/admin/grant', headers=ADMIN_KEY,
                json={'username': username, 'role': role, 'reason': 'test'})
  res = client.post('/api/auth/login', json={'username': username, 'password': PW})
  return {'Authorization': f"Bearer {res.get_json()['access_token']}"}


def test_gold_access_is_reported(client, sent):
  """골드 등급이 골드 API 를 열람하면 rule='gold-access' 로 신고한다."""
  hdr = make_user(client, 'zz_gold', 'gold')
  sent.clear()

  assert client.get('/api/gold/posts', headers=hdr).status_code == 200
  assert 'gold-access' in rules(sent), sent

  ev = [c for c in sent if c['rule'] == 'gold-access'][0]
  assert ev.get('username') == 'zz_gold'
  assert ev.get('role') == 'gold'


def test_admin_access_to_gold_is_reported(client, sent):
  """admin 도 골드 자료를 볼 수 있으므로 같은 신호가 남아야 한다(S9 의 핵심 경로)."""
  hdr = make_user(client, 'zz_admin9', 'admin')
  sent.clear()

  assert client.get('/api/gold/posts', headers=hdr).status_code == 200
  ev = [c for c in sent if c['rule'] == 'gold-access']
  assert ev and ev[0].get('role') == 'admin', sent


def test_denied_access_emits_no_gold_access(client, sent):
  """등급이 모자라 403 이면 '열람' 신호는 남지 않는다(오탐 방지)."""
  hdr = make_user(client, 'zz_plain')
  sent.clear()

  assert client.get('/api/gold/posts', headers=hdr).status_code == 403
  assert 'gold-access' not in rules(sent), sent


def test_no_post_content_in_signal(client, sent):
  """신호에 게시글 본문이 섞여 나가지 않는다."""
  hdr = make_user(client, 'zz_gold2', 'gold')
  sent.clear()

  client.get('/api/gold/posts', headers=hdr)
  blob = repr(sent)
  assert 'posts' not in blob and 'content' not in blob, blob
