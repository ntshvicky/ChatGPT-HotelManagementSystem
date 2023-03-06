from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hotel.db'
app.config['JWT_SECRET_KEY'] = 'super-secret'
db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(50))
    role = db.Column(db.String(20), default='user')

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'email': self.email,
            'role': self.role
        }

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    capacity = db.Column(db.Integer)
    price = db.Column(db.Float)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'capacity': self.capacity,
            'price': self.price
        }

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow())

    def to_dict(self):
        return {
            'id': self.id,
            'room': Room.query.get(self.room_id).to_dict(),
            'checkin_date': self.room_assignment.checkin_date,
            
            'checkout_date': self.room_assignment.checkout_date,
            'created_at': self.created_at
        }


class RoomAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'))
    checkin_date = db.Column(db.DateTime)
    checkout_date = db.Column(db.DateTime)
    def to_dict(self):
        return {
            'id': self.id,
            'room': Room.query.get(self.room_id).to_dict(),
            'checkin_date': self.checkin_date,
            'checkout_date': self.checkout_date
        }


def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            current_user = User.query.filter_by(email=get_jwt_identity()).first()
            if not current_user:
                return jsonify({'msg': 'User not found'}), 404
            if current_user.role != role:
                return jsonify({'msg': 'Unauthorized access'}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator

@app.route('/login', methods=['POST'])
def login():
    email = request.json.get('email')
    password = request.json.get('password')
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    if not check_password_hash(user.password, password):
        return jsonify({'msg': 'Invalid credentials'}), 401
    access_token = create_access_token(identity=user.email)
    return jsonify({'access_token': access_token})

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify({'msg': 'Logged out successfully'})

@app.route('/rooms', methods=['GET'])
def get_rooms():
    rooms = Room.query.all()
    return jsonify([room.to_dict() for room in rooms])

@app.route('/bookings', methods=['POST'])
@jwt_required()
def create_booking():
    user = User.query.filter_by(email=get_jwt_identity()).first()
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    room_id = request.json.get('room_id')
    checkin_date = request.json.get('checkin_date')
    checkout_date = request.json.get('checkout_date')
    if not room_id or not checkin_date or not checkout_date:
        return jsonify({'msg': 'Missing required fields'}), 400
    room = Room.query.get(room_id)
    if not room:
        return jsonify({'msg': 'Room not found'}), 404
    existing_booking = RoomAssignment.query.filter_by(room_id=room_id).filter(RoomAssignment.checkout_date>=checkin_date).filter(RoomAssignment.checkin_date<=checkout_date).first()
    if existing_booking:
        return jsonify({'msg': 'Room not available for the selected dates'}), 400
    new_booking = Booking(user_id=user.id, room_id=room_id)
    new_room_assignment = RoomAssignment(room_id=room_id, checkin_date=checkin_date, checkout_date=checkout_date)
    db.session.add(new_booking)
    db.session.add(new_room_assignment)
    db.session.commit()
    return jsonify({'msg': 'Booking created successfully'})

@app.route('/users', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_users():
    users = User.query.all()
    return jsonify([user.to_dict() for user in users])

@app.route('/users', methods=['POST'])
@jwt_required()
@role_required('admin')
def create_user():
    name = request.json.get('name')
    email = request.json.get('email')
    password = request.json

    if not name or not email or not password:
        return jsonify({'msg': 'Missing required fields'}), 400
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'msg': 'User already exists'}), 400
    new_user = User(name=name, email=email, password=generate_password_hash(password))
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'msg': 'User created successfully'})

@app.route('/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@role_required('admin')
def update_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    name = request.json.get('name')
    email = request.json.get('email')
    password = request.json.get('password')
    if not name or not email:
        return jsonify({'msg': 'Missing required fields'}), 400
    existing_user = User.query.filter_by(email=email).first()
    if existing_user and existing_user.id != user.id:
        return jsonify({'msg': 'Email already in use by another user'}), 400
    user.name = name
    user.email = email
    if password:
        user.password = generate_password_hash(password)
    db.session.commit()
    return jsonify({'msg': 'User updated successfully'})

@app.route('/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
@role_required('admin')
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({'msg': 'User not found'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'msg': 'User deleted successfully'})


if __name__ == 'main':
    app.run()