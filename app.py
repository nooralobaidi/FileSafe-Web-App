from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)
app.secret_key = 'your_secret_key'
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Connect to the SQLite database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Create a 'users' table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL,
        email TEXT NOT NULL,
        password TEXT NOT NULL
    )
''')

# Create an 'uploads' table if it doesn't exist
cursor.execute('''
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY,
        user_id INTEGER,
        filename TEXT NOT NULL,
        upload_date DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )
''')

conn.commit()
conn.close()

# Create an 'uploads' directory if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@login_manager.user_loader
def load_user(user_id):
    # Load a user by their ID from the database
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user_data = cursor.fetchone()
    conn.close()
    if user_data:
        return User(user_data[0], user_data[1], user_data[2], user_data[3])
    return None

class User(UserMixin):
    def __init__(self, id, username, email, password):
        self.id = id
        self.username = username
        self.email = email
        self.password = password

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash the password before storing it
        hashed_password = generate_password_hash(password, method='sha256')

        # Insert the user into the database
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                       (username, email, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if the email exists in the database
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            user_obj = User(user[0], user[1], user[2], user[3])
            login_user(user_obj)
            flash('Login successful!', 'success')
            return redirect(url_for('user_home'))
        else:
            flash('Login failed. Please check your email and password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logout successful', 'success')
    return redirect(url_for('home'))

@app.route('/user_home')
@login_required
def user_home():
    # Fetch the user's uploads from the database
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM uploads WHERE user_id = ?", (current_user.id,))
    uploads = cursor.fetchall()
    conn.close()

    return render_template('user_home.html', uploads=uploads)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)

    file = request.files['file']

    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)

    if file:
        # Save the uploaded file
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # Record the file details in the database
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO uploads (user_id, filename, upload_date) VALUES (?, ?, ?)",
                       (current_user.id, filename, datetime.now()))
        conn.commit()
        conn.close()

        flash('File uploaded successfully', 'success')

    return redirect(url_for('user_home'))

@app.route('/download/<filename>', methods=['GET'])
@login_required
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

@app.route('/delete_file/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    # Check if the user is the owner of the file
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM uploads WHERE filename = ?", (filename,))
    file_owner_id = cursor.fetchone()

    if file_owner_id and file_owner_id[0] == current_user.id:
        try:
            # Define the path to the file you want to delete
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Check if the file exists before attempting to delete it
            if os.path.exists(file_path):
                os.remove(file_path)

                # Remove the record from the database
                cursor.execute("DELETE FROM uploads WHERE filename = ?", (filename,))
                conn.commit()
                conn.close()

                flash(f'File {filename} deleted successfully', 'success')
            else:
                flash(f'File {filename} not found', 'danger')
        except Exception as e:
            flash(f'Error deleting file {filename}: {str(e)}', 'danger')
    else:
        flash('You are not authorized to delete this file', 'danger')

    # Redirect the user back to their dashboard
    return redirect(url_for('user_home'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
