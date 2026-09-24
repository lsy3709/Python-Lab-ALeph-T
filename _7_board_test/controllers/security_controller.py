"""보안 이벤트 REST — n8n 이 판정 결과를 보내 저장하는 곳.

인증: 헤더 X-API-Key (사람이 아니라 봇이 부르므로 로그인 대신 공유 비밀 1개)
"""
import os
from functools import wraps

from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import generate_password_hash

from extensions import db
from models import Incident, Post, SecurityEvent, User

security_bp = Blueprint('security', __name__, url_prefix='/api/security')


def require_api_key(fn):
  """X-API-Key 가 설정값과 같을 때만 통과. 키가 비었거나 다르면 401(fail-closed)."""
  @wraps(fn)
  def wrapper(*args, **kwargs):
    expected = current_app.config.get('SECURITY_API_KEY', '')
    if not expected or request.headers.get('X-API-Key', '') != expected:
      return jsonify({'msg': 'API 키가 없거나 잘못되었습니다.'}), 401
    return fn(*args, **kwargs)
  return wrapper


def _create_security_post(ev):
  """심화: 거부 이벤트를 게시판 '보안' 공지글로 자동 등록(작성자 = 시스템 계정)."""
  bot = User.query.filter_by(username='soarbot').first()
  if not bot:
    bot = User(username='soarbot',
               password=generate_password_hash(os.urandom(16).hex()))
    db.session.add(bot)
    db.session.flush()

  post = Post(
      title=f'[보안][{ev.student}] {ev.src_ip} 접근 거부 ({ev.severity})',
      content=(f'{ev.reason}\n시도 계정: {ev.users}\n'
               f'마지막 시도: {ev.last_seen}\n수집: {ev.generated_at}'),
      category='보안', author_id=bot.id)
  db.session.add(post)
  db.session.flush()
  return post.id


@security_bp.route('/events', methods=['POST'])
@require_api_key
def create_security_event():
  data = request.get_json(silent=True) or {}      # JSON 아니어도 500 대신 400
  student = (data.get('student') or '').strip()
  src_ip = data.get('src_ip')
  decision = data.get('decision')
  if not student or not src_ip or decision not in ('allow', 'deny'):
    return jsonify({'msg': 'student, src_ip, decision(allow|deny) 은 필수입니다.'}), 400

  ev = SecurityEvent(
      student=student[:50], src_ip=src_ip,
      fail_count=int(data.get('fail_count') or 0), decision=decision,
      severity=data.get('severity', 'Low'), reason=data.get('reason'),
      users=data.get('users'), last_seen=data.get('last_seen'),
      window_min=data.get('window_min'),
      source=data.get('source', 'login_guard'),
      generated_at=data.get('generated_at'),
  )
  db.session.add(ev)
  db.session.flush()                              # ev.id 확보

  post_id = None
  if decision == 'deny' and current_app.config.get('AUTO_POST_ON_DENY'):
    post_id = _create_security_post(ev)

  db.session.commit()                             # 이벤트+공지글을 한 트랜잭션으로
  return jsonify({'id': ev.id, 'student': ev.student,
                  'decision': ev.decision, 'post_id': post_id}), 201


@security_bp.route('/events', methods=['GET'])
def list_security_events():
  """조회는 키 없이(수업 확인용). ?student= 로 본인 것만 고른다."""
  student = request.args.get('student')
  decision = request.args.get('decision')
  limit = request.args.get('limit', default=20, type=int)

  query = SecurityEvent.query
  if student:
    query = query.filter_by(student=student)
  if decision in ('allow', 'deny'):
    query = query.filter_by(decision=decision)

  rows = query.order_by(SecurityEvent.id.desc()).limit(min(limit, 100)).all()
  return jsonify({'count': len(rows), 'events': [r.to_dict() for r in rows]})


@security_bp.route('/events/summary', methods=['GET'])
def security_events_summary():
  """허용/거부 건수 + 거부 상위 IP 5개."""
  from sqlalchemy import func

  student = request.args.get('student')
  q1 = db.session.query(SecurityEvent.decision, func.count(SecurityEvent.id))
  q2 = (db.session.query(SecurityEvent.src_ip, func.sum(SecurityEvent.fail_count))
        .filter(SecurityEvent.decision == 'deny'))
  if student:
    q1 = q1.filter(SecurityEvent.student == student)
    q2 = q2.filter(SecurityEvent.student == student)

  by_decision = dict(q1.group_by(SecurityEvent.decision).all())
  top = (q2.group_by(SecurityEvent.src_ip)
         .order_by(func.sum(SecurityEvent.fail_count).desc()).limit(5).all())

  return jsonify({
      'student': student,
      'by_decision': by_decision,
      'top_deny_ips': [{'src_ip': ip, 'fails': int(n)} for ip, n in top],
  })


@security_bp.route('/incidents', methods=['GET'])
def list_security_incidents():
  """인시던트 티켓 목록 — 조회는 키 없이(대시보드가 쓴다).

  생성/종료는 그대로 관리자 키가 필요한 /api/admin/incident 쪽이다(읽기 전용).
  ?status=open|closed · ?student= · ?limit= (최대 100)
  """
  status = request.args.get('status')
  student = request.args.get('student')
  limit = request.args.get('limit', default=20, type=int)

  query = Incident.query
  if status in ('open', 'closed'):
    query = query.filter_by(status=status)
  if student:
    query = query.filter_by(student=student)

  rows = query.order_by(Incident.id.desc()).limit(min(limit, 100)).all()
  return jsonify({'count': len(rows), 'incidents': [r.to_dict() for r in rows]})


@security_bp.route('/incidents/summary', methods=['GET'])
def security_incidents_summary():
  """상태별 티켓 수 + 열린 티켓의 심각도 분포(대시보드 카드용)."""
  from sqlalchemy import func

  student = request.args.get('student')
  q1 = db.session.query(Incident.status, func.count(Incident.id))
  q2 = (db.session.query(Incident.severity, func.count(Incident.id))
        .filter(Incident.status == 'open'))
  if student:
    q1 = q1.filter(Incident.student == student)
    q2 = q2.filter(Incident.student == student)

  return jsonify({
      'by_status': dict(q1.group_by(Incident.status).all()),
      'open_by_severity': dict(q2.group_by(Incident.severity).all()),
  })


@security_bp.route('/students', methods=['GET'])
def list_students():
  """대시보드 드롭다운용 — 기록이 있는 학생 목록."""
  rows = (db.session.query(SecurityEvent.student)
          .distinct().order_by(SecurityEvent.student).all())
  return jsonify({'students': [r[0] for r in rows]})
