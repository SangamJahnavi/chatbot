# from flask import Flask
# from flask_sqlalchemy import SQLAlchemy


# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///university.db'
# db = SQLAlchemy(app)

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Use your existing 'university.db' file
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///university.db'
app.config['SECRET_KEY'] = 'your_secret_key'  # Required for flash messages

db = SQLAlchemy(app)

# Add the User model to your existing database schema
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Your existing routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        # Hash the password
        # hashed_password = generate_password_hash(password, method='sha256')
        # Hash the password using pbkdf2:sha256
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(name=name, email=email, password=hashed_password)

        # Add the user to the database
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()  # Find user by email
        if user and check_password_hash(user.password, password):  # Check password
            flash('Login successful!', 'success')
            return redirect(url_for('admin'))  # Redirect to admin page
        else:
            flash('Invalid login credentials!', 'danger')
            return redirect(url_for('login'))  # Reload login page

    return render_template('login.html')

@app.route('/admin')
def admin():
    # Your admin page code
    return render_template('admin.html')

if __name__ == '__main__':
    db.create_all()  # Create tables (if they don't already exist in the database)
    app.run(debug=True)
