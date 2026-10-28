"""보안 이벤트 REST — n8n 이 판정 결과를 보내 저장하는 곳.

인증: 헤더 X-API-Key (사람이 아니라 봇이 부르므로 로그인 대신 공유 비밀 1개)
"""
import os
from collections import Counter
from datetime import datetime, time, timedelta
from functools import wraps

from flask import Blueprint, current_app, jsonify, request
from werkzeug.security import generate_password_hash

from .gelf import send_gelf
from .seclog import write_auth_fail
from .pagination import SortError, paginate, severity_rank
from extensions import db
from models import Incident, Post, SecurityEvent, User

security_bp = Blueprint('security', __name__, url_prefix='/api/security')

# 정렬 허용 컬럼(화이트리스트) — 화면의 표 머리글을 누르면 이 이름이 날아온다.
# severity 는 글자가 아니라 서열로 정렬한다(pagination.severity_rank 설명 참고).
_EVENT_SORTS = {
    'created_at': SecurityEvent.created_at,
    'decision': SecurityEvent.decision,
    'severity': severity_rank(SecurityEvent.severity),
    'fail_count': SecurityEvent.fail_count,
    'student': SecurityEvent.student,
    'src_ip': SecurityEvent.src_ip,
    'id': SecurityEvent.id,
}

_INCIDENT_SORTS = {
    'created_at': Incident.created_at,
    'updated_at': Incident.updated_at,
    'closed_at': Incident.closed_at,
    'severity': severity_rank(Incident.severity),
    'status': Incident.status,
    'event_count': Incident.event_count,
    'src_ip': Incident.src_ip,
    'id': Incident.id,
}


def require_api_key(fn):
  """X-API-Key 가 설정값과 같을 때만 통과. 키가 비었거나 다르면 401(fail-closed)."""
  @wraps(fn)
  def wrapper(*args, **kwargs):
    expected = current_app.config.get('SECURITY_API_KEY', '')
    if not expected or request.headers.get('X-API-Key', '') != expected:
      # S6 인증 공격 탐지 — 키를 추측해 두드리는 것을 신고한다.
      # 시도된 키 값 자체는 절대 남기지 않는다(그 자체가 비밀 후보다).
      try:
        send_gelf(f"admin api auth failed {request.path[:80]}", rule='admin-auth-fail',
                  src_ip=(request.headers.get('X-Forwarded-For', request.remote_addr)
                          or '0.0.0.0').split(',')[0].strip(),
                  path=request.path[:120], code=401)
      except Exception:
        pass
      # 이중출력: Wazuh 에이전트가 읽는 security.log 에도 한 줄(S6 wazuh-dashboard 노출)
      try:
        write_auth_fail(request.headers.get('X-Forwarded-For', request.remote_addr),
                        request.path[:120])
      except Exception:
        pass
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
  """조회는 키 없이(수업 확인용). ?student= 로 본인 것만 고른다.

  필터: ?student= · ?decision=allow|deny · ?severity=Low|Medium|High|Critical
  페이징: ?page=1 &per_page=20 (최대 100, 예전 ?limit= 도 받는다)
  정렬:  ?sort=created_at|decision|severity|fail_count|student|src_ip|id
         &order=asc|desc (기본 created_at desc = 최신 먼저)
  """
  student = request.args.get('student')
  decision = request.args.get('decision')
  severity = request.args.get('severity')

  query = SecurityEvent.query
  if student:
    query = query.filter_by(student=student)
  if decision in ('allow', 'deny'):
    query = query.filter_by(decision=decision)
  if severity:
    query = query.filter_by(severity=severity)

  try:
    rows, meta = paginate(query, request.args, _EVENT_SORTS, SecurityEvent.id)
  except SortError as e:
    return jsonify({'msg': str(e)}), 400

  return jsonify({'count': len(rows),
                  'events': [r.to_dict() for r in rows], **meta})


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


_SEVERITIES = ('Low', 'Medium', 'High', 'Critical')   # 그래프 쌓는 순서(아래 → 위)
_STATS_DAYS = (7, 14, 30, 90)


def _norm_severity(value):
  """대소문자만 다른 등급은 합치고, 목록에 없는 등급은 'Other' 로 따로 센다(아무 칸에나 섞지 않는다)."""
  for s in _SEVERITIES:
    if (value or '').strip().lower() == s.lower():
      return s
  return 'Other'


@security_bp.route('/stats', methods=['GET'])
def security_stats():
  """대시보드 그래프용 집계 — 최근 N일 날짜별·심각도별 이벤트 수, 심각도·출처 분포.

  조회 전용·키 없음(요약 API 와 같은 수준). 날짜는 created_at(이 PC 시각 = KST) 으로 묶는다.
  필터: ?student= · ?days=7|14|30|90 (기본 30, 허용 밖이면 30)
  """
  student = request.args.get('student')
  days = request.args.get('days', 30, type=int)
  days = days if days in _STATS_DAYS else 30
  today = datetime.now().date()
  start = today - timedelta(days=days - 1)

  query = (db.session.query(SecurityEvent.created_at, SecurityEvent.severity, SecurityEvent.source)
           .filter(SecurityEvent.created_at >= datetime.combine(start, time.min)))
  if student:
    query = query.filter(SecurityEvent.student == student)

  slot = {start + timedelta(days=i): i for i in range(days)}
  daily = {s: [0] * days for s in _SEVERITIES}
  by_source = Counter()
  for created_at, severity, source in query.all():
    i = slot.get(created_at.date())
    if i is None:          # 미래 시각(시계 차이) 등 — 칸이 없으면 뺀다
      continue
    daily.setdefault(_norm_severity(severity), [0] * days)[i] += 1
    by_source[source or '(없음)'] += 1

  by_severity = {s: sum(v) for s, v in daily.items()}
  return jsonify({
      'student': student, 'days': days, 'start': start.isoformat(), 'end': today.isoformat(),
      'labels': [d.strftime('%m-%d') for d in slot],
      'daily': daily, 'by_severity': by_severity,
      'by_source': [{'source': s, 'n': n}
                    for s, n in sorted(by_source.items(), key=lambda kv: (-kv[1], kv[0]))],
      'total': sum(by_severity.values()),
  })


@security_bp.route('/incidents', methods=['GET'])
def list_security_incidents():
  """인시던트 티켓 목록 — 조회는 키 없이(대시보드가 쓴다).

  생성/종료는 그대로 관리자 키가 필요한 /api/admin/incident 쪽이다(읽기 전용).

  필터: ?status=open|closed · ?student= · ?severity=Low|Medium|High|Critical
  페이징: ?page=1 &per_page=20 (최대 100, 예전 ?limit= 도 받는다)
  정렬:  ?sort=created_at|updated_at|closed_at|severity|status|event_count|src_ip|id
         &order=asc|desc (기본 created_at desc = 최신 먼저)
  """
  status = request.args.get('status')
  student = request.args.get('student')
  severity = request.args.get('severity')

  query = Incident.query
  if status in ('open', 'closed'):
    query = query.filter_by(status=status)
  if student:
    query = query.filter_by(student=student)
  if severity:
    query = query.filter_by(severity=severity)

  try:
    rows, meta = paginate(query, request.args, _INCIDENT_SORTS, Incident.id)
  except SortError as e:
    return jsonify({'msg': str(e)}), 400

  return jsonify({'count': len(rows),
                  'incidents': [r.to_dict() for r in rows], **meta})


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
