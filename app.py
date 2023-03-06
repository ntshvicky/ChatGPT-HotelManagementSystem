from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from datetime import datetime, timedelta
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///hotel_management.db'
app.config['JWT_SECRET_KEY'] = 'hotel_secret_key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
db = SQLAlchemy(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Room(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    checkin_date = db.Column(db.Date, nullable=False)
    checkout_date = db.Column(db.Date, nullable=False)

class RoomAssignment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    booking_id = db.Column(db.Integer, db.ForeignKey('booking.id'), nullable=False)
    room_id = db.Column(db.Integer, db.ForeignKey('room.id'), nullable=False)
    checkin_date = db.Column(db.Date, nullable=False)
    checkout_date = db.Column(db.Date, nullable=False)

# API endpoints for authentication and authorization

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    user = User.query.filter_by(username=username).first()

    if not user or user.password != password:
        return jsonify({'message': 'Invalid username or password'}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify({'access_token': access_token})

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    # JWT token revocation logic here
    return jsonify({'message': 'Logout successful'})

# API endpoints for user and role management

@app.route('/user', methods=['POST'])
@jwt_required()
def add_user():
    if get_jwt_identity()['role'] != 'admin':
        return jsonify({'message': 'Only admin can create new users'}), 403

    username = request.json.get('username', None)
    password = request.json.get('password', None)
    role_id = request.json.get('role_id', None)

    if not username or not password or not role_id:
        return jsonify({'message': 'Missing required fields'}), 400

    role = Role.query.get(role_id)

    if not role:
        return jsonify({'message': 'Invalid role id'}), 400

    user = User(username=username, password=password, role_id=role_id)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/role', methods=['POST'])
@jwt_required()
def add_role():
    if get_jwt_identity()['role'] != 'admin':
        return jsonify({'message': 'Only admin can create new roles'}), 403 
    name = request.json.get('name', None)

    if not name:
        return jsonify({'message': 'Missing required fields'}), 400

    role = Role(name=name)
    db.session.add(role)
    db.session.commit()

    return jsonify({'message': 'Role created successfully'}), 201

# API endpoints for room management
@app.route('/room', methods=['POST'])
@jwt_required()
def add_room():
    if get_jwt_identity()['role'] != 'admin':
        return jsonify({'message': 'Only admin can create new rooms'}), 403 
    name = request.json.get('name', None)

    if not name:
        return jsonify({'message': 'Missing required fields'}), 400

    room = Room(name=name)
    db.session.add(room)
    db.session.commit()

    return jsonify({'message': 'Room created successfully'}), 201

@app.route('/room', methods=['GET'])
@jwt_required()
def get_rooms():
    rooms = Room.query.all()
    return jsonify({'rooms': [{'id': room.id, 'name': room.name} for room in rooms]})


# API endpoints for booking and room assignment
@app.route('/booking', methods=['POST'])
@jwt_required()
def book_room():
    user_id = get_jwt_identity()['id']
    room_id = request.json.get('room_id', None)
    checkin_date = request.json.get('checkin_date', None)
    checkout_date = request.json.get('checkout_date', None) 
    if not room_id or not checkin_date or not checkout_date:
        return jsonify({'message': 'Missing required fields'}), 400

    booking = Booking(user_id=user_id, room_id=room_id, checkin_date=checkin_date, checkout_date=checkout_date)
    db.session.add(booking)
    db.session.commit()

    room_assignment = RoomAssignment(booking_id=booking.id, room_id=room_id, checkin_date=checkin_date, checkout_date=checkout_date)
    db.session.add(room_assignment)
    db.session.commit()

    return jsonify({'message': 'Room booked successfully'}), 201


@app.route('/booking/available', methods=['GET'])
@jwt_required()
def get_available_rooms():
    checkin_date = request.args.get('checkin_date', None)
    checkout_date = request.args.get('checkout_date', None)
    if not checkin_date or not checkout_date:
        return jsonify({'message': 'Missing required fields'}), 400

    available_rooms = Room.query.filter(~Room.id.in_(
        RoomAssignment.query.with_entities(RoomAssignment.room_id).filter(
            ((RoomAssignment.checkin_date <= checkin_date) & (RoomAssignment.checkout_date >= checkout_date)) |
            ((RoomAssignment.checkin_date >= checkin_date) & (RoomAssignment.checkin_date <= checkout_date)) |
            ((RoomAssignment.checkout_date >= checkin_date) & (RoomAssignment.checkout_date <= checkout_date))
        )
    )).all()

    return jsonify({'rooms': [{'id': room.id, 'name': room.name} for room in available_rooms]})

@app.route('/booking/booked', methods=['GET'])
@jwt_required()
def get_booked_rooms():
    checkin_date = request.args.get('checkin_date', None)
    checkout_date = request.args.get
    if not checkin_date or not checkout_date:
        return jsonify({'message': 'Missing required fields'}), 400

    booked_rooms = Room.query.filter(Room.id.in_(
        RoomAssignment.query.with_entities(RoomAssignment.room_id).filter(
            ((RoomAssignment.checkin_date <= checkin_date) & (RoomAssignment.checkout_date >= checkout_date)) |
            ((RoomAssignment.checkin_date >= checkin_date) & (RoomAssignment.checkin_date <= checkout_date)) |
            ((RoomAssignment.checkout_date >= checkin_date) & (RoomAssignment.checkout_date <= checkout_date))
        )
    )).all()

    return jsonify({'rooms': [{'id': room.id, 'name': room.name} for room in booked_rooms]})


@app.route('/checkin', methods=['POST'])
@jwt_required()
def checkin():
    user_id = get_jwt_identity()['id']
    booking_id = request.json.get('booking_id', None)
    if not booking_id:
        return jsonify({'message': 'Missing required fields'}), 400

    booking = Booking.query.get(booking_id)

    if not booking:
        return jsonify({'message': 'Booking not found'}), 404

    if booking.user_id != user_id:
        return jsonify({'message': 'You are not authorized to checkin this booking'}), 403

    room_assignment = RoomAssignment.query.filter_by(booking_id=booking.id).first()

    if not room_assignment:
        return jsonify({'message': 'Room not assigned to booking yet'}), 400

    if room_assignment.checkin_date < datetime.now().date():
        return jsonify({'message': 'Checkin date has already passed'}), 400

    room_assignment.checkin_date = datetime.now().date()
    db.session.commit()

    return jsonify({'message': 'Checked in successfully'}), 200


@app.route('/checkout', methods=['POST'])
@jwt_required()
def checkout():
    user_id = get_jwt_identity()['id']
    booking_id = request.json.get('booking_id', None)
    if not booking_id:
        return jsonify({'message': 'Missing required fields'}), 400

    booking = Booking.query.get(booking_id)

    if not booking:
        return jsonify({'message': 'Booking not found'}), 404

    if booking.user_id != user_id:
        return jsonify({'message': 'You are not authorized to checkout this booking'}), 403

    room_assignment = RoomAssignment.query.filter_by(booking_id=booking.id).first()

    if not room_assignment:
        return jsonify({'message': 'Room not assigned to booking yet'}), 400

    if room_assignment.checkout_date < datetime.now().date():
        return jsonify({'message': 'Checkout date has already passed'}), 400

    room_assignment.checkout_date = datetime.now().date()
    db.session.commit()

    return jsonify({'message': 'Checked out successfully'}), 200



@app.route('/bookings', methods=['GET'])
@jwt_required()
def get_bookings():
    user_id = get_jwt_identity()['id']
    bookings = Booking.query.filter_by(user_id=user_id).all()
    return jsonify({'bookings': [booking.to_dict() for booking in bookings]})

@app.route('/bookings', methods=['POST'])
@jwt_required()
def create_booking():
    user_id = get_jwt_identity()['id']
    room_id = request.json.get('room_id', None)
    checkin_date = request.json.get('checkin_date', None)
    checkout_date = request.json.get('checkout_date', None)

    if not room_id or not checkin_date or not checkout_date:
        return jsonify({'message': 'Missing required fields'}), 400

    room = Room.query.get(room_id)

    if not room:
        return jsonify({'message': 'Room not found'}), 404

    room_assignment = RoomAssignment.query.filter(RoomAssignment.room_id == room_id).filter(
        ((RoomAssignment.checkin_date <= checkin_date) & (RoomAssignment.checkout_date >= checkout_date)) |
        ((RoomAssignment.checkin_date >= checkin_date) & (RoomAssignment.checkin_date <= checkout_date)) |
        ((RoomAssignment.checkout_date >= checkin_date) & (RoomAssignment.checkout_date <= checkout_date))
    ).first()

    if room_assignment:
        return jsonify({'message': 'Room is already booked for the given dates'}), 400

    booking = Booking(user_id=user_id, room_id=room_id)
    db.session.add(booking)
    db.session.commit()

    room_assignment = RoomAssignment(booking_id=booking.id, room_id=room_id, checkin_date=checkin_date, checkout_date=checkout_date)
    db.session.add(room_assignment)
    db.session.commit()

    return jsonify({'message': 'Booking created successfully', 'booking': booking.to_dict()}), 201

@app.route('/rooms', methods=['GET'])
def get_rooms():
    rooms = Room.query.all()
    return jsonify({'rooms': [room.to_dict() for room in rooms]})

@app.route('/users', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_users():
    users = User.query.all()
    return jsonify({'users': [user.to_dict() for user in users]})

@app.route('/users', methods=['POST'])
@jwt_required()
@role_required('admin')
def create_user():
    name = request.json.get('name', None)
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    role = request.json.get('role', 'user')

    if not name or not email or not password:
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'message': 'User already exists'}), 400

    user = User(name=name, email=email, password=bcrypt.generate_password_hash(password), role=role)
    db.session.add(user)
    db.session.commit()

    return jsonify({'message': 'User created successfully', 'user': user.to_dict()}), 201

@app.route('/roles', methods=['GET'])
@jwt_required()
@role_required('admin')
def get_roles():
    roles = Role.query.all()
    return jsonify({'roles': [role.to_dict() for role in roles]})

if __name__ == '__main__':
    app.run()

