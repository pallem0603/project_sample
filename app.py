# app.py
from flask import Flask, render_template, request, redirect, url_for, make_response, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///coffee_shop.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
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
    if 'manager' in request.cookies:
        return redirect(url_for('manager_dashboard'))

    # Check if user is already logged in as user
    if 'user' in request.cookies:
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
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            # Successful login, redirect to user dashboard
            resp = make_response(redirect(url_for('user_dashboard')))
            resp.set_cookie('user', username)
            flash(f"Welcome, {username}! You are now logged in as a user.", "success")
            return resp
        else:
            flash("Invalid username or password. Please try again.", "error")

    return render_template('user_login.html')

@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different username.", "error")
        elif password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
        else:
            # Create and add the user to the database
            user = User(username=username, password=generate_password_hash(password))
            db.session.add(user)
            db.session.commit()

            resp = make_response(redirect(url_for('user_dashboard')))
            resp.set_cookie('user', username)
            flash(f"Welcome, {username}! You are now signed up and logged in as a user.", "success")
            return resp

    return render_template('user_signup.html')

@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        manager = Manager.query.filter_by(username=username).first()
        if manager and check_password_hash(manager.password, password):
            # Successful login, redirect to manager dashboard
            resp = make_response(redirect(url_for('manager_dashboard')))
            resp.set_cookie('manager', username)
            flash(f"Welcome, {username}! You are now logged in as a manager.", "success")
            return resp
        else:
            flash("Invalid username or password. Please try again.", "error")

    return render_template('manager_login.html')

@app.route('/manager/signup', methods=['GET', 'POST'])
def manager_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if Manager.query.filter_by(username=username).first():
            flash("Username already exists. Please choose a different username.", "error")
        elif password != confirm_password:
            flash("Passwords do not match. Please try again.", "error")
        else:
            # Create and add the manager to the database
            manager = Manager(username=username, password=generate_password_hash(password))
            db.session.add(manager)
            db.session.commit()

            resp = make_response(redirect(url_for('manager_dashboard')))
            resp.set_cookie('manager', username)
            flash(f"Welcome, {username}! You are now signed up and logged in as a manager.", "success")
            return resp

    return render_template('manager_signup.html')

@app.route('/user/dashboard')
def user_dashboard():
    # This is the user dashboard page
    if 'user' not in request.cookies:
        flash("You need to log in as a user to access the dashboard.", "error")
        return redirect(url_for('user_login'))

    return render_template('user_dashboard.html')

@app.route('/manager/dashboard')
def manager_dashboard():
    # This is the manager dashboard page
    if 'manager' not in request.cookies:
        flash("You need to log in as a manager to access the dashboard.", "error")
        return redirect(url_for('manager_login'))

    return render_template('manager_dashboard.html')

@app.route('/logout')
def logout():
    # Clear the user and manager cookies to log them out
    resp = make_response(redirect(url_for('main_page')))
    resp.delete_cookie('user')
    resp.delete_cookie('manager')
    flash("You have been logged out.", "success")
    return resp

if __name__ == '__main__':
    app.run(debug=True)
