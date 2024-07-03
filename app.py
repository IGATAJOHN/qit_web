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
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'content': self.content,
            'author': self.author,
            'date': self.date.strftime('%Y-%m-%d')
        }
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
    return User.query.get(int(user_id))
@app.route('/edit_article/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_article(id):
    article = Article.query.get_or_404(id)
    form = ArticleForm()

    if form.validate_on_submit():
        article.title = form.title.data
        article.content = form.content.data
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
    articles_data = [article.to_dict() for article in articles]
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
    return redirect(url_for('index'))
@app.errorhandler(401)
def unauthorized(error):
    return render_template('unauthorize.html'), 401

if __name__=='__main__':
    app.run(debug=True,host='0.0.0.0',port='5000')
