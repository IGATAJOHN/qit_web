from flask import Flask, render_template,redirect,url_for,request,jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
app=Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mydb.db'
db = SQLAlchemy(app)
migrate=Migrate(app,db)
@app.route('/')
def index():
    return render_template('index.html')
class ContactSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    subject = db.Column(db.String(100))
    message = db.Column(db.Text)
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
@app.route('/meets-gallery')
def meets_gallery():
    return render_template('meets-gallery.html')
    
if __name__=='__main__':
    app.run(debug=True)
