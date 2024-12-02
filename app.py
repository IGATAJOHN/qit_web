from flask import Flask, render_template,redirect,url_for,request,jsonify,flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime
from flask_login import UserMixin
from dotenv import load_dotenv
from functools import wraps
import os
from flask import abort
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SubmitField
from wtforms.validators import DataRequired

from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, current_user, login_required, LoginManager
load_dotenv()
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI')
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
db = SQLAlchemy(app)
migrate=Migrate(app,db)
login_manager = LoginManager(app)
login_manager.init_app(app)
@app.route('/')
def index():
    return render_template('index.html')

class ArticleForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Submit')

class ContactSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    subject = db.Column(db.String(100))
    message = db.Column(db.Text)
class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(50), nullable=False)
    date = db.Column(db.Date, nullable=False)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    favorites = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='article', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'content': self.content,
            'author': self.author,
            'date': self.date.strftime('%Y-%m-%d'),
            'likes': self.likes,
            'dislikes': self.dislikes,
            'favorites': self.favorites,
            'comments': [comment.content for comment in self.comments]
        }

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    article_id = db.Column(db.Integer, db.ForeignKey('article.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=True)
    replies = db.relationship('Comment', backref=db.backref('parent', remote_side=[id]), lazy=True)
    user = db.relationship('User', backref='comments')

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<User {}>'.format(self.username)
    @property
    def is_authenticated(self):
        return True
    @property
    def is_active(self):
        return True
    @property
    def is_anonymous(self):
        return False
    def get_id(self):
        return str(self.id)
with app.app_context():
    db.create_all()
@app.route('/like_article/<int:article_id>', methods=['POST'])
@login_required
def like_article(article_id):
    article = Article.query.get_or_404(article_id)
    article.likes += 1
    db.session.commit()
    return jsonify({'success': True, 'likes': article.likes})

@app.route('/dislike_article/<int:article_id>', methods=['POST'])
@login_required
def dislike_article(article_id):
    article = Article.query.get_or_404(article_id)
    article.dislikes += 1
    db.session.commit()
    return jsonify({'success': True, 'dislikes': article.dislikes})

@app.route('/add_comment/<int:article_id>', methods=['POST'])
@login_required
def add_comment(article_id):
    if not request.json or 'content' not in request.json:
        return jsonify({'error': 'Invalid data'}), 400

    content = request.json.get('content')
    parent_id = request.json.get('parent_id')

    new_comment = Comment(
        content=content,
        user_id=current_user.id,
        article_id=article_id,
        parent_id=parent_id  # parent_id is None for root-level comments
    )

    try:
        db.session.add(new_comment)
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to add comment', 'details': str(e)}), 500.

    return jsonify({
        'id': new_comment.id,  # Include the comment ID in the response
        'username': current_user.username,
        'content': new_comment.content,
        'parent_id': new_comment.parent_id
    }), 201
    

@app.route('/reply_comment/<int:comment_id>', methods=['POST'])
@login_required
def reply_comment(comment_id):  # Update parameter name
    # Validate JSON payload
    if not request.json or not request.json.get('content'):
        return jsonify({'error': 'Reply content cannot be empty'}), 400

    # Extract content
    content = request.json.get('content')

    # Fetch parent comment
    parent_comment = Comment.query.get_or_404(comment_id)

    # Create a new reply
    new_comment = Comment(
        content=content,
        user_id=current_user.id,
        article_id=parent_comment.article_id,
        parent_id=parent_comment.id
    )

    try:
        db.session.add(new_comment)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Failed to add reply', 'details': str(e)}), 500

    return jsonify({
        'id': new_comment.id,
        'username': current_user.username,
        'content': new_comment.content,
        'parent_id': new_comment.parent_id
    }), 201  # Remove the redundant return statement

@app.route('/get_comments/<int:article_id>')
def get_comments(article_id):
    article = Article.query.get_or_404(article_id)
    comments = [
        {
            'id': comment.id,
            'content': comment.content,
            'username': comment.user.username if comment.user else None,  # Add username
            'replies': get_replies(comment)  # Fetch replies recursively
        }
        for comment in article.comments if comment.parent_id is None  # Get top-level comments
    ]
    return jsonify(comments)

def get_replies(comment):
    """Recursively fetch replies for a comment."""
    replies = [
        {
            'id': reply.id,
            'content': reply.content,
            'username': reply.user.username if reply.user else None,
            'replies': get_replies(reply)  # Recursive call for nested replies
        }
        for reply in comment.replies
    ]
    return replies

@app.route('/favorite_article/<int:article_id>', methods=['POST'])
@login_required
def favorite_article(article_id):
    article = Article.query.get_or_404(article_id)
    article.favorites += 1
    db.session.commit()
    return jsonify({'success': True, 'favorites': article.favorites})



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different username.', 'error')
            return redirect(url_for('register'))
        
        # For simplicity, assume all users except 'quantum' are regular users
        role = 'admin' if username == 'quantum' and password == 'quantum' else 'user'

        user = User(username=username, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Registration successful. You can now login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('research'))
        else:
            flash('Invalid username or password.', 'error')

    return render_template('login.html')
@login_manager.user_loader
def load_user(user_id):
    session = db.session  # Get the current session
    return session.get(User, int(user_id))
@app.route('/edit_article/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_article(id):
    article = Article.query.get_or_404(id)
    form = ArticleForm()

    if form.validate_on_submit():
        article.title = form.title.data
        article.content = form.content.data
        article.date = datetime.now()  # Update the date to the current date
        db.session.commit()
        flash('Article updated successfully.', 'success')
        return redirect(url_for('research'))

    form.title.data = article.title
    form.content.data = article.content
    return render_template('edit_article.html', form=form)


@app.route('/delete_article/<int:id>', methods=['GET', 'POST'])
@login_required
def delete_article(id):
    article = Article.query.get_or_404(id)
    db.session.delete(article)
    db.session.commit()
    flash('Article deleted successfully.', 'success')
    return redirect(url_for('research'))

@app.route('/delete_comment/<int:comment_id>', methods=['DELETE'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)

    # Allow only comment authors or admins to delete
    if comment.user_id != current_user.id and current_user.role != 'admin':
        abort(403)

    try:
        db.session.delete(comment)
        db.session.commit()
        return jsonify({'success': True, 'message': 'Comment deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'Failed to delete comment', 'details': str(e)}), 500
    
@app.route('/submit-contact-form', methods=['POST'])
def submit_contact_form():
    # Retrieve form data
    name = request.form.get('name')
    email = request.form.get('email')
    subject = request.form.get('subject')
    message = request.form.get('message')

    # Create a new ContactSubmission object
    new_submission = ContactSubmission(name=name, email=email, subject=subject, message=message)

    # Add the new submission to the database session
    db.session.add(new_submission)
    
    try:
        # Commit the session to save the new submission to the database
        db.session.commit()
        # Return a JSON response indicating success
        return jsonify({'success': True, 'message': 'Your message has been received. We will get back to you soon!'}), 200
    except Exception as e:
        # Rollback the session in case of an error
        db.session.rollback()
        # Return a JSON response indicating failure
        return jsonify({'success': False, 'message': 'Failed to submit form. Please try again later.'}), 500
    finally:
        # Close the session
        db.session.close()
@app.route('/meetup')
def meetup():
    return render_template('meetup.html')
@app.route('/meetups-gallery')
def meetups_gallery():
    return render_template('meets-gallery.html')
@app.route('/research')
def research():
    articles = Article.query.all()
    articles_data = [
        {
            'id': article.id,
            'title': article.title,
            'description': article.description,
            'content': article.content,
            'author': article.author,
            'date': article.date.strftime('%Y-%m-%d'),
            'likes': getattr(article, 'likes', 0),
            'dislikes': getattr(article, 'dislikes', 0),
            'favorites': getattr(article, 'favorites', 0),
            'comments': [
                {'id': comment.id, 'content': comment.content}
                for comment in article.comments
            ]
        }
        for article in articles
    ]
    return render_template('research.html', articles=articles_data)


def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden
        return func(*args, **kwargs)
    return decorated_function
@app.route('/upload', methods=['GET', 'POST'])
@login_required
@admin_required
def upload():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        content = request.form['content']
        author = request.form['author']
        date = datetime.strptime(request.form['date'], '%Y-%m-%d')
        
        new_article = Article(title=title, description=description, content=content, author=author, date=date)
        db.session.add(new_article)
        db.session.commit()

        return redirect(url_for('research'))

    return render_template('upload.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))
@app.errorhandler(401)
def unauthorized(error):
    return render_template('unauthorize.html'), 401

if __name__=='__main__':
    app.run()
