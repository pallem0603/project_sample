from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import re

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///coffee_shop.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Create database tables
db.create_all()

# Menu and Inventory data
menu = {
    'espresso': ['Espresso', 'Double Espresso', 'Americano'],
    'cappuccino': ['Cappuccino', 'Iced Cappuccino', 'Caramel Cappuccino'],
    'pastries': ['Croissant', 'Danish', 'Muffin'],
    'sandwiches': ['Chicken Sandwich', 'Vegetarian Sandwich', 'BLT Sandwich'],
    # Add more categories and items here
}

inventory = {
    'espresso': 20,
    'cappuccino': 15,
    'pastries': 30,
    'sandwiches': 10,
    # Add more categories and inventory quantities here
}

@app.route('/')
def main_page():
    # Check if user is already logged in as manager
    if 'manager_email' in session:
        return redirect(url_for('manager_dashboard'))

    # Check if user is already logged in as user
    if 'user_email' in session:
        return redirect(url_for('user_dashboard'))

    # Redirect to user login page if not logged in
    return redirect(url_for('user_login'))

@app.route('/category/<category>')
def category_menu(category):
    if category not in menu:
        return "Category not found."

    return render_template('category_menu.html', category=category, menu=menu, inventory=inventory)

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Please provide both email and password.", "error")
            return redirect(url_for('user_login'))

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            # Successful login, store user information in session
            session['user_email'] = email
            flash(f"Welcome, {user.first_name}! You are now logged in as a user.", "success")
            return redirect(url_for('user_dashboard'))
        else:
            flash("Invalid email address or password. Please try again.", "error")

    return render_template('user_login.html')

@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if User.query.filter_by(email=email).first():
            flash("Email address already used. Please choose a different email address.", "error")
        elif password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
        else:
            missing_requirements = get_missing_password_requirements(password)
            if missing_requirements:
                return render_template('user_signup.html', signup_url=url_for('user_signup'), login_url=url_for('user_login'), missing_requirements=missing_requirements)

            # Create and add the user to the database
            user = User(first_name=first_name, last_name=last_name, email=email, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()

            flash("User successfully signed up. Please log in with your new credentials.", "success")
            return redirect(url_for('user_login'))

    return render_template('user_signup.html', signup_url=url_for('user_signup'), login_url=url_for('user_login'))

@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not email or not password:
            flash("Please provide both email and password.", "error")
            return redirect(url_for('manager_login'))

        manager = Manager.query.filter_by(email=email).first()
        if manager and check_password_hash(manager.password, password):
            # Successful login, store manager information in session
            session['manager_email'] = email
            flash(f"Welcome, {manager.first_name}! You are now logged in as a manager.", "success")
            return redirect(url_for('manager_dashboard'))
        else:
            flash("Invalid email address or password. Please try again.", "error")

    return render_template('manager_login.html')

@app.route('/manager/signup', methods=['GET', 'POST'])
def manager_signup():
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if Manager.query.filter_by(email=email).first():
            flash("Email address already used. Please choose a different email address.", "error")
        elif password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
        else:
            missing_requirements = get_missing_password_requirements(password)
            if missing_requirements:
                return render_template('manager_signup.html', signup_url=url_for('manager_signup'), login_url=url_for('manager_login'), missing_requirements=missing_requirements)

            # Create and add the manager to the database
            manager = Manager(first_name=first_name, last_name=last_name, email=email, password=generate_password_hash(password))
            db.session.add(manager)
            db.session.commit()

            flash("Manager successfully signed up. Please log in with your new credentials.", "success")
            return redirect(url_for('manager_login'))

    return render_template('manager_signup.html', signup_url=url_for('manager_signup'), login_url=url_for('manager_login'))

@app.route('/user/dashboard')
def user_dashboard():
    # This is the user dashboard page
    if 'user_email' not in session:
        flash("You need to log in as a user to access the dashboard.", "error")
        return redirect(url_for('user_login'))

    return render_template('user_dashboard.html')

@app.route('/manager/dashboard')
def manager_dashboard():
    # This is the manager dashboard page
    if 'manager_email' not in session:
        flash("You need to log in as a manager to access the dashboard.", "error")
        return redirect(url_for('manager_login'))

    return render_template('manager_dashboard.html')

@app.route('/logout')
def logout():
    # Clear the user and manager session data to log them out
    session.pop('user_email', None)
    session.pop('manager_email', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('main_page'))

def get_missing_password_requirements(password):
    # Check if the password meets the specified requirements using regular expressions
    # (?=.*[a-z]): At least one lowercase letter
    # (?=.*[A-Z]): At least one uppercase letter
    # (?=.*\d$): Ends with a number
    # .{8,}: At least 8 characters long
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d$).{8,}$'
    missing_requirements = []
    if not re.search(r'[a-z]', password):
        missing_requirements.append("at least one lowercase letter")
    if not re.search(r'[A-Z]', password):
        missing_requirements.append("at least one uppercase letter")
    if not re.search(r'\d$', password):
        missing_requirements.append("end with a number")
    if len(password) < 8:
        missing_requirements.append("at least 8 characters long")
    return missing_requirements

if __name__ == '__main__':
    app.run(debug=True)
