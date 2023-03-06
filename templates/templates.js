// Constants for API endpoints
const LOGIN_ENDPOINT = '/login';
const LOGOUT_ENDPOINT = '/logout';
const ADD_USER_ENDPOINT = '/add_user';
const GET_USERS_ENDPOINT = '/get_users';
const ADD_BOOKING_ENDPOINT = '/add_booking';
const GET_AVAILABLE_ROOMS_ENDPOINT = '/get_available_rooms';
const GET_BOOKED_ROOMS_ENDPOINT = '/get_booked_rooms';
const GET_BOOKING_ANALYTICS_ENDPOINT = '/get_booking_analytics';

// Constants for chart colors
const CHART_COLORS = [
'rgba(54, 162, 235, 0.2)',
'rgba(255, 99, 132, 0.2)',
'rgba(255, 206, 86, 0.2)',
'rgba(75, 192, 192, 0.2)',
'rgba(153, 102, 255, 0.2)',
'rgba(255, 159, 64, 0.2)'
];

// Global variables
let currentUser = null;

// Function to handle user login
const handleLogin = async (event) => {
event.preventDefault();
const username = document.getElementById('login-username').value;
const password = document.getElementById('login-password').value;
const response = await fetch(LOGIN_ENDPOINT, {
method: 'POST',
headers: {
'Content-Type': 'application/json'
},
body: JSON.stringify({
username: username,
password: password
})
});
if (response.ok) {
const data = await response.json();
currentUser = data.username;
document.getElementById('login-form').reset();
showContent('booking-form');
} else {
alert('Invalid username or password');
}
};

// Function to handle user logout
const handleLogout = async (event) => {
event.preventDefault();
const response = await fetch(LOGOUT_ENDPOINT, {
method: 'POST'
});
if (response.ok) {
currentUser = null;
showContent('login-form');
} else {
alert('Error logging out');
}
};

// Function to handle user registration
const handleAddUser = async (event) => {
event.preventDefault();
const username = document.getElementById('username').value;
const password = document.getElementById('password').value;
const role = document.getElementById('role').value;
const response = await fetch(ADD_USER_ENDPOINT, {
method: 'POST',
headers: {
'Content-Type': 'application/json'
},
body: JSON.stringify({
username: username,
password: password,
role: role
})
});
if (response.ok) {
document.getElementById('add-user-form').reset();
await loadUsers();
} else {
alert('Error adding user');
}
};

// Function to load all users from the server
const loadUsers = async () => {
const response = await fetch(GET_USERS_ENDPOINT);
if (response.ok) {
const data = await response.json();
const tableBody = document.getElementById('user-table').querySelector('tbody');
tableBody.innerHTML = '';
data.forEach((user) => {
const row = tableBody.insertRow();
row.innerHTML = <td>${user.id}</td> <td>${user.username}</td> <td>${user.role}</td> <td><button onclick="handleDeleteUser(${user.id})">Delete</button></td> ;
});
} else {
alert('Error loading users');
}
};

// Function to handle user deletion
const handleDeleteUser = async (userId) => {
if (confirm('Are you sure you want to delete this user


###############
import sha256 from 'crypto-js/sha256';

// Retrieve values from form fields
const password = document.getElementById("password").value;
const salt = document.getElementById("salt").value;

// Hash the password
const hashValue = sha256(password + salt);
const hashedPassword = hashValue.toString();

// Compare the hashed password to the one stored in the database
if (hashedPassword === storedHashedPassword) {
  // User is authenticated
} else {
  // Invalid password
}
