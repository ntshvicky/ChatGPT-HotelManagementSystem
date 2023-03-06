@app.route('/checkin', methods=['POST'])
@login_required
def checkin():
    room_number = request.json.get('room_number')
    guest_name = request.json.get('guest_name')
    checkin_date = request.json.get('checkin_date')
    user_id = current_user.id
    room = Room.query.filter_by(number=room_number).first()
    if not room:
        return jsonify({'msg': 'Room not found'}), 404
    if room.is_occupied():
        return jsonify({'msg': 'Room is already occupied'}), 409
    guest = Guest(name=guest_name, checkin_date=checkin_date, room_id=room.id, user_id=user_id)
    db.session.add(guest)
    db.session.commit()
    return jsonify({'msg': 'Guest checked in successfully'})




@app.route('/book-room', methods=['POST'])
@login_required
def book_room():
    room_number = request.json.get('room_number')
    start_date = request.json.get('start_date')
    end_date = request.json.get('end_date')
    user_id = current_user.id
    room = Room.query.filter_by(number=room_number).first()
    if not room:
        return jsonify({'msg': 'Room not found'}), 404
    if room.is_booked(start_date, end_date):
        return jsonify({'msg': 'Room already booked'}), 409
    booking = Booking(user_id=user_id, room_id=room.id, start_date=start_date, end_date=end_date)
    db.session.add(booking)
    db.session.commit()
    return jsonify({'msg': 'Room booked successfully'})

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    room_number = request.json.get('room_number')
    checkout_date = request.json.get('checkout_date')
    user_id = current_user.id
    room = Room.query.filter_by(number=room_number).first()
    if not room:
        return jsonify({'msg': 'Room not found'}), 404
    if not room.is_occupied():
        return jsonify({'msg': 'Room is already vacant'}), 409
    guest = Guest.query.filter_by(room_id=room.id).order_by(Guest.checkin_date.desc()).first()
    if not guest:
        return jsonify({'msg': 'Guest not found'}), 404
    guest.checkout_date = checkout_date
    db.session.commit()
    return jsonify({'msg': 'Guest checked out successfully'})


@app.route('/book', methods=['POST'])
@login_required
def book():
    checkin_date = request.json.get('checkin_date')
    checkout_date = request.json.get('checkout_date')
    user_id = current_user.id
    available_rooms = Room.query.filter_by(is_available=True).all()
    for room in available_rooms:
        if room.is_available(checkin_date, checkout_date):
            guest = Guest(user_id=user_id, room_id=room.id, checkin_date=checkin_date, checkout_date=checkout_date)
            room.is_available = False
            db.session.add(guest)
            db.session.commit()
            return jsonify({'msg': 'Room booked successfully'})
    return jsonify({'msg': 'No available rooms found'}), 404


@app.route('/availability', methods=['POST'])
def availability():
    checkin_date = request.json.get('checkin_date')
    checkout_date = request.json.get('checkout_date')
    available_rooms = Room.query.filter_by(is_available=True).all()
    available_rooms_data = []
    for room in available_rooms:
        if room.is_available(checkin_date, checkout_date):
            room_data = {
                'room_number': room.number,
                'room_type': room.room_type,
                'price': room.price,
                'is_available': True
            }
        else:
            room_data = {
                'room_number': room.number,
                'room_type': room.room_type,
                'price': room.price,
                'is_available': False
            }
        available_rooms_data.append(room_data)
    return jsonify({'rooms': available_rooms_data})
