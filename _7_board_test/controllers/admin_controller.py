"""관리자(인가/RBAC) REST — 회원 권한 부여·회수.

접근 방식 두 가지
  ① 기계 호출(n8n·회수봇)  : 헤더  X-API-Key: <ADMIN_API_KEY>
  ② 사람(관리자 페이지)     : JWT(로그인 토큰) + 그 계정의 role == 'admin'

시나리오
  - 관리자 페이지에서 특정 회원에게 admin 을 '부여'(인가) → 불필요한 과잉권한 발생
  - 파이썬 회수봇이 허용목록(ADMIN_ALLOWLIST) 밖 admin 을 탐지 → Graylog 신고
  - Graylog 이벤트 → n8n → 이 API 의 /revoke 를 호출해 실제 '회수'(최소권한 복원)
  - 회수 시 security_events 에 감사기록(source='privilege-guard') → 대시보드 노출
"""
from datetime import datetime, timedelta
from functools import wraps

from flask import Blueprint, current_app, jsonify, request

from extensions import db
from models import BlockedIP, Incident, SecurityEvent, User

from .rbac import VALID_ROLES, current_user   # 등급 정의는 rbac 한 곳에서

admin_bp = Blueprint('admin', __name__, url_prefix='/api/admin')

# ('user', 'gold', 'admin') — models/user.py 의 ROLE_LEVEL 에서 온다.
ROLE_CHOICES = '|'.join(VALID_ROLES)


def _has_valid_key():
  """X-API-Key 가 ADMIN_API_KEY 와 일치하면 True(비어 있으면 항상 False = fail-closed)."""
  expected = current_app.config.get('ADMIN_API_KEY', '')
  return bool(expected) and request.headers.get('X-API-Key', '') == expected


def _current_admin_user():
  """JWT 가 있고 그 계정이 admin 이면 User, 아니면 None."""
  user = current_user()
  return user if (user and user.is_admin) else None


def admin_required(fn):
  """유효한 관리자 키(기계) 또는 admin JWT(사람)면 통과. 아니면 401/403."""
  @wraps(fn)
  def wrapper(*args, **kwargs):
    if _has_valid_key():
      request.actor = 'apikey'
      return fn(*args, **kwargs)
    admin = _current_admin_user()
    if admin:
      request.actor = admin.username
      return fn(*args, **kwargs)
    return jsonify({'msg': '관리자 인가가 필요합니다(X-API-Key 또는 admin 로그인).'}), 401
  return wrapper


def _allowlist(param=None):
  """정책 허용목록. 쿼리/바디로 넘기면 우선, 없으면 config(.env)."""
  if param:
    return [u.strip() for u in param.split(',') if u.strip()]
  return current_app.config.get('ADMIN_ALLOWLIST', [])


@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users():
  """회원 목록 + 역할. ?role=admin 으로 필터."""
  role = request.args.get('role')
  q = User.query
  if role in VALID_ROLES:
    q = q.filter_by(role=role)
  rows = q.order_by(User.id.asc()).all()
  return jsonify({'count': len(rows), 'users': [u.to_dict() for u in rows]})


@admin_bp.route('/violations', methods=['GET'])
@admin_required
def list_violations():
  """정책 위반(허용목록 밖 admin) 목록. 회수봇이 참고용으로 쓸 수 있다.
  ?allowlist=lsy,instructor 로 기준을 넘기면 그걸 우선 적용."""
  allow = _allowlist(request.args.get('allowlist'))
  admins = User.query.filter_by(role='admin').all()
  bad = [u for u in admins if u.username not in allow]
  return jsonify({
      'allowlist': allow,
      'count': len(bad),
      'violations': [u.to_dict() for u in bad],
  })


@admin_bp.route('/grant', methods=['POST'])
@admin_required
def grant_role():
  """회원에게 역할 부여(인가). body: {username, role, reason}
  시나리오상 여기서 admin 을 잘못/과하게 부여해 '불필요한 권한'을 만든다."""
  data = request.get_json(silent=True) or {}
  username = (data.get('username') or '').strip()
  role = (data.get('role') or '').strip()
  if not username or role not in VALID_ROLES:
    return jsonify({'msg': f'username, role({ROLE_CHOICES}) 은 필수입니다.'}), 400

  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'msg': f'없는 사용자: {username}'}), 404

  old = user.role
  user.role = role
  user.role_granted_by = getattr(request, 'actor', 'unknown')
  user.role_granted_at = datetime.now()
  user.role_reason = (data.get('reason') or '')[:200]
  db.session.commit()
  return jsonify({'msg': '역할 부여 완료', 'username': username,
                  'old_role': old, 'new_role': role,
                  'granted_by': user.role_granted_by}), 200


@admin_bp.route('/revoke', methods=['POST'])
@admin_required
def revoke_role():
  """과잉권한 회수(최소권한 복원) → role 을 'user' 로. n8n 이 호출.
  body: {username, reason, student, severity, src_ip}
  회수가 실제로 일어나면 security_events 에 감사기록(source='privilege-guard')을 남긴다."""
  data = request.get_json(silent=True) or {}
  username = (data.get('username') or '').strip()
  if not username:
    return jsonify({'msg': 'username 은 필수입니다.'}), 400

  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'msg': f'없는 사용자: {username}'}), 404

  old = user.role
  actor = getattr(request, 'actor', 'unknown')
  if old == 'user':
    # 이미 최소권한 — 변경 없음(감사기록도 남기지 않아 소음 방지)
    return jsonify({'msg': '이미 user 권한(회수 불필요)', 'username': username,
                    'old_role': old, 'new_role': 'user', 'revoked': False}), 200

  user.role = 'user'
  user.role_granted_by = actor
  user.role_granted_at = datetime.now()
  user.role_reason = (data.get('reason') or f'{old}→user 회수 by {actor}')[:200]

  # 감사기록: 대시보드에서 보이도록 security_events 재사용
  ev = SecurityEvent(
      student=(data.get('student') or actor)[:50],
      src_ip=data.get('src_ip') or '0.0.0.0',
      fail_count=0, decision='deny',
      severity=data.get('severity', 'High'),
      reason=(data.get('reason') or f'과잉권한 회수: {username} {old}→user')[:200],
      users=username, source=data.get('source', 'privilege-guard'),
      generated_at=data.get('generated_at'),
  )
  db.session.add(ev)
  db.session.commit()
  return jsonify({'msg': '권한 회수 완료', 'username': username,
                  'old_role': old, 'new_role': 'user', 'revoked': True,
                  'event_id': ev.id, 'revoked_by': actor}), 200


@admin_bp.route('/lock', methods=['POST'])
@admin_required
def lock_account():
  """계정 잠금(브루트포스 대응) → is_locked=True. n8n 이 호출.
  body: {username, reason, student, src_ip, fail_count, severity}
  잠금이 실제로 일어나면 security_events 에 감사기록(source='login-guard')을 남긴다."""
  data = request.get_json(silent=True) or {}
  username = (data.get('username') or '').strip()
  if not username:
    return jsonify({'msg': 'username 은 필수입니다.'}), 400
  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'msg': f'없는 사용자: {username}'}), 404

  actor = getattr(request, 'actor', 'unknown')
  if user.is_locked:
    return jsonify({'msg': '이미 잠긴 계정', 'username': username,
                    'locked': True, 'changed': False}), 200

  user.is_locked = True
  user.locked_at = datetime.now()
  user.lock_reason = (data.get('reason') or f'브루트포스 자동 잠금 by {actor}')[:200]
  ev = SecurityEvent(
      student=(data.get('student') or actor)[:50],
      src_ip=data.get('src_ip') or '0.0.0.0',
      fail_count=int(data.get('fail_count') or 0), decision='deny',
      severity=data.get('severity', 'High'),
      reason=(data.get('reason') or f'계정 잠금: {username} (브루트포스)')[:200],
      users=username, source=data.get('source', 'login-guard'),
      generated_at=data.get('generated_at'),
  )
  db.session.add(ev)
  db.session.commit()
  return jsonify({'msg': '계정 잠금 완료', 'username': username, 'locked': True,
                  'changed': True, 'event_id': ev.id, 'locked_by': actor}), 200


@admin_bp.route('/unlock', methods=['POST'])
@admin_required
def unlock_account():
  """계정 잠금 해제 → is_locked=False + 실패 카운트 초기화. body: {username}"""
  data = request.get_json(silent=True) or {}
  username = (data.get('username') or '').strip()
  if not username:
    return jsonify({'msg': 'username 은 필수입니다.'}), 400
  user = User.query.filter_by(username=username).first()
  if not user:
    return jsonify({'msg': f'없는 사용자: {username}'}), 404

  user.is_locked = False
  user.failed_logins = 0
  user.lock_reason = None
  db.session.commit()
  return jsonify({'msg': '잠금 해제 완료', 'username': username, 'locked': False,
                  'unlocked_by': getattr(request, 'actor', 'unknown')}), 200


@admin_bp.route('/block', methods=['POST'])
@admin_required
def block_ip():
  """공격 IP 실차단(active response) → blocked_ips 에 추가. n8n 이 호출.
  body: {ip, reason, student, severity}. 이후 그 IP 요청은 미들웨어가 403(관리자 API 제외)."""
  data = request.get_json(silent=True) or {}
  ip = (data.get('ip') or data.get('src_ip') or '').strip()
  if not ip:
    return jsonify({'msg': 'ip(또는 src_ip) 는 필수입니다.'}), 400
  actor = getattr(request, 'actor', 'unknown')

  if not db.session.get(BlockedIP, ip):
    db.session.add(BlockedIP(ip=ip, reason=(data.get('reason') or f'자동 차단 by {actor}')[:200],
                             blocked_by=actor))
    ev = SecurityEvent(
        student=(data.get('student') or actor)[:50], src_ip=ip,
        fail_count=int(data.get('fail_count') or 0), decision='deny',
        severity=data.get('severity', 'High'),
        reason=(data.get('reason') or f'IP 실차단: {ip}')[:200],
        users='', source=data.get('source', 'ip-guard'),
        generated_at=data.get('generated_at'))
    db.session.add(ev)
    db.session.commit()
    return jsonify({'msg': 'IP 차단 완료', 'ip': ip, 'blocked': True,
                    'changed': True, 'event_id': ev.id, 'blocked_by': actor}), 200
  return jsonify({'msg': '이미 차단된 IP', 'ip': ip, 'blocked': True, 'changed': False}), 200


@admin_bp.route('/unblock', methods=['POST'])
@admin_required
def unblock_ip():
  """IP 차단 해제. body: {ip}"""
  data = request.get_json(silent=True) or {}
  ip = (data.get('ip') or data.get('src_ip') or '').strip()
  if not ip:
    return jsonify({'msg': 'ip 는 필수입니다.'}), 400
  row = db.session.get(BlockedIP, ip)
  if row:
    db.session.delete(row)
    db.session.commit()
  return jsonify({'msg': '차단 해제 완료', 'ip': ip, 'blocked': False,
                  'unblocked_by': getattr(request, 'actor', 'unknown')}), 200


@admin_bp.route('/blocked', methods=['GET'])
@admin_required
def list_blocked():
  """차단된 IP 목록."""
  rows = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).all()
  return jsonify({'count': len(rows), 'blocked': [r.to_dict() for r in rows]})


_SEV_RANK = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}


def _build_summary(src_ip, events):
  """security_events 를 사람이 읽는 인시던트 요약(타임라인·집계·조치)으로 취합."""
  by_source, actions = {}, set()
  worst = 'Low'
  lines = []
  for e in events:
    by_source[e.source] = by_source.get(e.source, 0) + 1
    if e.decision:
      actions.add(e.decision)
    if _SEV_RANK.get(e.severity, 1) > _SEV_RANK.get(worst, 1):
      worst = e.severity
    when = e.created_at.strftime('%Y-%m-%d %H:%M:%S') if e.created_at else (e.generated_at or '?')
    lines.append(f"- {when} [{e.severity}/{e.source}] {e.reason or ''} (users={e.users or '-'})")
  first = events[-1].created_at if events and events[-1].created_at else None
  last = events[0].created_at if events and events[0].created_at else None
  src_summary = ', '.join(f'{k}×{v}' for k, v in sorted(by_source.items()))
  summary = (
      f"[인시던트 요약] 출발지 {src_ip}\n"
      f"- 관련 이벤트: {len(events)}건 ({src_summary})\n"
      f"- 최초/최종: {first} ~ {last}\n"
      f"- 취해진 조치: {', '.join(sorted(actions)) or '없음'}\n"
      f"- 최고 심각도: {worst}\n"
      f"[타임라인]\n" + "\n".join(lines[:20])
  )
  return summary, worst, ', '.join(sorted(actions)) or '없음', len(events)


@admin_bp.route('/incident', methods=['POST'])
@admin_required
def create_incident():
  """인시던트 티켓 생성/갱신. body: {src_ip, title?, severity?, student?, hours?}

  같은 src_ip 의 '열린' 티켓이 있으면 갱신(중복 방지), 없으면 새로 만든다.
  요약은 최근 hours(기본 24) 시간의 security_events 를 자동 취합한다(사람이 읽는 리포트)."""
  data = request.get_json(silent=True) or {}
  src_ip = (data.get('src_ip') or data.get('ip') or '').strip()
  if not src_ip:
    return jsonify({'msg': 'src_ip 는 필수입니다.'}), 400
  actor = getattr(request, 'actor', 'unknown')
  hours = int(data.get('hours') or 24)
  since = datetime.now() - timedelta(hours=hours)
  # 같은 키의 '마지막으로 종료된 티켓' 이후 사건만 취합한다 — 이미 처리·종료한 사건을
  # 새 티켓이 다시 흡수하지 않게([129] E2E 에서 발견). 같은 초 경계는 포함(>=) 쪽으로:
  # 새 증거를 놓치는 것보다 한 건 겹치는 편이 안전하다.
  last_closed = (Incident.query
                 .filter(Incident.src_ip == src_ip, Incident.status == 'closed',
                         Incident.closed_at.isnot(None))
                 .order_by(Incident.closed_at.desc()).first())
  if last_closed and last_closed.closed_at > since:
    since = last_closed.closed_at
  events = (SecurityEvent.query
            .filter(SecurityEvent.src_ip == src_ip, SecurityEvent.created_at >= since)
            .order_by(SecurityEvent.created_at.desc()).all())
  summary, worst, actions, cnt = _build_summary(src_ip, events)
  severity = data.get('severity') or worst
  title = (data.get('title') or f'보안 인시던트: {src_ip} ({cnt}건)')[:200]

  inc = Incident.query.filter_by(src_ip=src_ip, status='open').first()
  created = False
  if not inc:
    inc = Incident(src_ip=src_ip, status='open'); db.session.add(inc); created = True
  inc.title = title
  # 심각도는 '내려가지 않는다': 요청값·취합 최고값·기존 티켓 값 중 가장 높은 것
  # (Critical 티켓에 나중에 Medium 경보가 합쳐져도 Critical 유지 — [129] E2E 에서 발견해 수정)
  inc.severity = max((severity, worst, inc.severity or 'Low'),
                     key=lambda s: _SEV_RANK.get(s, 0))
  inc.summary = summary
  inc.event_count = cnt
  inc.actions = actions[:255]
  inc.student = (data.get('student') or actor)[:50]
  db.session.commit()
  return jsonify({'msg': '인시던트 생성' if created else '인시던트 갱신',
                  'created': created, 'incident': inc.to_dict()}), (201 if created else 200)


@admin_bp.route('/incidents', methods=['GET'])
@admin_required
def list_incidents():
  """인시던트 목록. ?status=open|closed 로 필터."""
  status = request.args.get('status')
  q = Incident.query
  if status in ('open', 'closed'):
    q = q.filter_by(status=status)
  rows = q.order_by(Incident.updated_at.desc()).all()
  return jsonify({'count': len(rows), 'incidents': [r.to_dict() for r in rows]})


@admin_bp.route('/incident/close', methods=['POST'])
@admin_required
def close_incident():
  """인시던트 종료(status=closed). body: {id}"""
  data = request.get_json(silent=True) or {}
  inc = db.session.get(Incident, int(data.get('id') or 0))
  if not inc:
    return jsonify({'msg': '없는 인시던트'}), 404
  inc.status = 'closed'
  inc.closed_at = datetime.now()
  db.session.commit()
  return jsonify({'msg': '인시던트 종료', 'incident': inc.to_dict()}), 200
