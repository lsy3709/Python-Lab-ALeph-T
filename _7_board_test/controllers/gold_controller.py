"""골드 등급 전용 API.

화면에서 메뉴를 숨기는 것만으로는 막은 게 아니다 —
주소창에 API 를 직접 쳐 보면 그대로 열린다.
그래서 서버에서 한 번 더 등급을 검사한다(@role_required('gold')).
"""
from flask import Blueprint, jsonify, request

from models import Post
from .gelf import send_gelf
from .rbac import role_required

gold_bp = Blueprint('gold', __name__, url_prefix='/api/gold')

GOLD_CATEGORY = '골드'


@gold_bp.route('/posts', methods=['GET'])
@role_required('gold')
def gold_posts():
  """골드 전용 게시글 목록. 일반 게시판(/api/posts)과 달리 등급이 없으면 403."""
  # S9 상관 탐지용 — "권한을 올린 뒤 실제로 열람했는가"를 이으려면 열람 사실이 남아야 한다.
  # 남기는 값은 계정명·등급·출발지뿐. 본문은 남기지 않는다(로그는 더 넓게 공유된다).
  user = request.current_user
  try:
    send_gelf(f"gold area accessed by '{user.username}'", rule='gold-access',
              username=user.username, role=user.role or '',
              src_ip=(request.headers.get('X-Forwarded-For', request.remote_addr)
                      or '0.0.0.0').split(',')[0].strip())
  except Exception:
    pass

  rows = (Post.query.filter_by(category=GOLD_CATEGORY)
          .order_by(Post.id.desc()).limit(20).all())
  return jsonify({'count': len(rows), 'posts': [p.to_dict() for p in rows]})
