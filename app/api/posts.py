from . import api
from app.models import Post, Permission
from flask import jsonify, request, url_for, g, current_app
from .decorators import permission_required
from app import db
from .errors import forbidden


@api.route('/posts/')
def get_posts():
    page = request.args.get('page', 1, type=int)
    pagination = Post.query.paginate(page, per_page=current_app.config['POSTS_PER_PAGE'], error_out=False)
    posts = pagination.items
    prev, next = None, None
    if pagination.has_prev:
        prev = url_for('api.get_posts', page=pagination.prev_num)
    if pagination.has_next:
        next = url_for('api.get_posts', page=pagination.next_num)
    return jsonify({'posts': [post.to_json() for post in posts],
                    'prev': prev,
                    'next': next,
                    'count': pagination.total})


@api.route('/posts/<int:id>')
def get_post(id):
    post = Post.query.get_or_404(id)
    return jsonify(post.to_json())


@api.route('/posts/', methods=['POST'])
@permission_required(Permission.WRITE)
def create_post():
    post = Post.from_json(request.json)
    post.author = g.current_user
    db.session.add(post)
    db.session.commit()
    return jsonify(post.to_json()), 201, {'Location': url_for('api.get_post', id=post.id)}


@api.route('/posts/<int:id>', methods=['PUT'])
@permission_required(Permission.WRITE)
def edit_post(id):
    post = Post.query.get_or_404(id)
    if g.current_user != post.author and not g.current_user.is_administrator():
        return forbidden('Insufficient permissions')
    post.body = Post.from_json(request.json).body
    db.session.add(post)
    db.session.commit()
    return jsonify(post.to_json())
