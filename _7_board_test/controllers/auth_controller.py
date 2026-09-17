"""회원가입 / 로그인 / 내 정보."""
from flask import Blueprint, jsonify, request
from flask_jwt_extended import create_access_token
from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db
from models import User
from models.user import ROLE_LABEL

from .gelf import send_gelf
from .rbac import current_user
from .seclog import write_seclog

auth_bp = Blueprint('auth', __name__, url_prefix='/api/auth')


@auth_bp.route('/register', methods=['POST'])
def register():
  data = request.get_json(silent=True) or {}
  if not data.get('username') or not data.get('password'):
    return jsonify({'msg': 'username, password 는 필수입니다.'}), 400
  if User.query.filter_by(username=data['username']).first():
    return jsonify({'msg': '이미 존재하는 사용자입니다.'}), 400

  user = User(username=data['username'],
              password=generate_password_hash(data['password']))
  db.session.add(user)
  db.session.commit()
  return jsonify({'msg': '회원가입 성공'}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
  data = request.get_json(silent=True) or {}
  username = (data.get('username') or '').strip()
  user = User.query.filter_by(username=username).first()
  # 공격자가 X-Forwarded-For 를 위조할 수 있으니 실습에선 remote_addr 를 쓴다.
  src_ip = request.headers.get('X-Forwarded-For', request.remote_addr) or '0.0.0.0'

  # ① 이미 잠긴 계정은 비번이 맞아도 거부(423 Locked)
  if user and user.is_locked:
    send_gelf(f"login attempt on LOCKED account '{username}'",
              rule='login-bruteforce', username=username, src_ip=src_ip, locked='1')
    write_seclog('login_failed', username, src_ip)   # 잠긴 계정 시도도 실패로 기록(Wazuh)
    return jsonify({'msg': '계정이 잠겨 있습니다. 관리자에게 문의하세요.',
                    'locked': True}), 423

  # ② 인증 실패 → Graylog 로 신고 + 실패 카운트(표시용) 증가
  if not user or not check_password_hash(user.password, data.get('password', '')):
    if user:
      user.failed_logins = (user.failed_logins or 0) + 1
      db.session.commit()
    send_gelf(f"failed login for '{username}' from {src_ip}",
              rule='login-bruteforce', username=username or '(unknown)',
              src_ip=src_ip, count=1)
    write_seclog('login_failed', username or '(unknown)', src_ip)   # 호스트 로그 → Wazuh
    return jsonify({'msg': '아이디 또는 비밀번호가 잘못되었습니다.'}), 401

  # ③ 성공 → 실패 카운트 초기화 + 토큰 발급
  if user.failed_logins:
    user.failed_logins = 0
    db.session.commit()
  token = create_access_token(identity=str(user.id))
  # role 을 함께 내려주면 화면이 곧바로 등급에 맞는 메뉴를 그릴 수 있다.
  return jsonify(access_token=token, username=user.username,
                 role=user.role, role_label=ROLE_LABEL.get(user.role, user.role))


@auth_bp.route('/me', methods=['GET'])
def me():
  """지금 로그인한 사람이 누구이고 어떤 등급인지 — 화면의 등급 확인용.

  토큰은 localStorage 에 있어서 페이지를 열 때 서버로 자동 전송되지 않는다.
  그래서 화면 JS 가 이 API 를 불러 등급을 확인하고 예외 화면 여부를 정한다."""
  user = current_user()
  if user is None:
    return jsonify({'msg': '로그인이 필요합니다.'}), 401
  return jsonify({
      'id': user.id,
      'username': user.username,
      'role': user.role,
      'role_label': ROLE_LABEL.get(user.role, user.role),
      'is_gold': user.is_gold,
      'is_admin': user.is_admin,
  })
