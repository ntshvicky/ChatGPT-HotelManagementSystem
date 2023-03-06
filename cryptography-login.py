from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db, login_manager

# We can use the cryptography library to generate and verify password hashes. Here's an updated version of the User model that includes password hashing:

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(32), default='user')

    def __repr__(self):
        return f'<User {self.name}>'

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def from_dict(data):
        return User(name=data['name'], email=data['email'], password=data['password'], role=data.get('role', 'user'))


'''
In this updated version of the User model, we've added a password_hash field to store the hash of the user's password instead of the plaintext password. We've also added a password setter method that hashes the provided password and stores the result in the password_hash field.

We've also added a verify_password method that checks whether a given password matches the hash stored in the password_hash field. This method uses the check_password_hash function from the werkzeug.security module to perform the password verification.

To use this updated User model for user authentication, we can modify the login route to verify the user's password using the verify_password method:
'''

from flask import Flask, jsonify, request, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from app import create_app, db
from app.models import User

app = create_app()
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    if not email or not password:
        abort(400)
    user = User.query.filter_by(email=email).first()
    if not user or not user.verify_password(password):
        abort(401)
    login_user(user)
    return jsonify({'msg': 'Logged in successfully'})

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return jsonify({'msg': 'Logged out successfully'})

'''
In this updated version of the login route, we retrieve the user from the database using the provided email address, and then call the verify_password method to check whether the provided password matches the stored password hash. If the verification succeeds, we call the login_user function to log the user in and create a session.

To log the user out, we simply call the logout_user function and return a success message.

With these changes, we can use the User model with hashed passwords and the verify_password method to securely manage user authentication and login in our Flask application.
'''