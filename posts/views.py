from flask import Blueprint, render_template, flash, url_for, redirect
from config import db, Post
from posts.forms import PostForm

posts_bp = Blueprint('posts', __name__, template_folder='templates')

@posts_bp.route('/posts')
def posts():
    return render_template('posts/posts.html')

@posts_bp.route('/create', methods=('GET', 'POST'))
def create():

    form = PostForm()

    if form.validate_on_submit():
        new_post = Post(title=form.title.data, body=form.body.data)

        db.session.add(new_post)
        db.session.commit()

        flash('Post created', category='success')
        return redirect(url_for('posts.posts'))

    return render_template('posts/create.html', form=form)

@posts_bp.route('/update')
def update():
    return render_template('posts/update.html')
