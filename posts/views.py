from flask import Blueprint, render_template, flash, url_for, redirect
from flask_login import login_required

from config import db, Post
from posts.forms import PostForm
from sqlalchemy import desc
from flask_login import current_user

posts_bp = Blueprint('posts', __name__, template_folder='templates')

@posts_bp.route('/posts')
def posts():
    if current_user.role == 'end_user':
        if current_user.is_authenticated:
            all_posts = Post.query.order_by(desc('id')).all()
            return render_template('posts/posts.html', posts=all_posts)
        else:
            flash('You are not logged in.', category='danger')
            return redirect(url_for('accounts.login'))
    else:
        flash('You are authorised to access this page', category="danger")
        return redirect(url_for('accounts.login'))



@posts_bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():
    if current_user.role == 'end_user':
        if current_user.is_authenticated:
            form = PostForm()

            if form.validate_on_submit():
                new_post = Post(user=current_user, title=form.title.data, body=form.body.data)

                db.session.add(new_post)
                db.session.commit()

                flash('Post created', category='success')
                return redirect(url_for('posts.posts'))

            return render_template('posts/create.html', form=form)
        else:
            flash('you are not logged in', category='danger')
            return redirect(url_for('accounts.login'))
    else:
        flash('You are authorised to access this page', category="danger")
        return redirect(url_for('accounts.login'))



@posts_bp.route('/<int:id>/update', methods=('GET', 'POST'))
def update(id):
    if current_user.is_authenticated:
        post_to_update = Post.query.filter_by(id=id).first()

        if not post_to_update or post_to_update.userid != current_user.id:
            flash('You do not have permission to update this post.', category='danger')
            return redirect(url_for('posts.posts'))

        form = PostForm()

        if form.validate_on_submit():
            post_to_update.update(title=form.title.data, body=form.body.data)
            flash('Post updated successfully', category='success')
            return redirect(url_for('posts.posts'))

        form.title.data = post_to_update.title
        form.body.data = post_to_update.body

        return render_template('posts/update.html', form=form)
    else:
        flash('You do not have permission to update this post.', category='danger')
        return render_template('home/index.html')


@posts_bp.route('/<int:id>/delete')
def delete(id):
    if current_user.is_authenticated:
        post_to_delete = Post.query.filter_by(id=id).first()

        if not post_to_delete or post_to_delete.userid != current_user.id:
            flash('You do not have permission to delete this post.', category='danger')
            return redirect(url_for('posts.posts'))

        db.session.delete(post_to_delete)
        db.session.commit()
        flash('Post deleted successfully', category='success')
        return redirect(url_for('posts.posts'))
    else:
        flash('You do not have permission to delete this post.', category='danger')
        return render_template('home/index.html')

