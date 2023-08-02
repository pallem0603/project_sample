# app.py
from flask import Flask, render_template, request, redirect, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
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
    # Redirect to login page
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
            return resp

    return render_template('user_login.html')

@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if User.query.filter_by(username=username).first():
            return "Username already exists. Please choose a different username."

        if password != confirm_password:
            return "Passwords do not match. Please try again."

        # Create and add the user to the database
        user = User(username=username, password=generate_password_hash(password))
        db.session.add(user)
        db.session.commit()

        resp = make_response(redirect(url_for('main_page')))
        resp.set_cookie('user', username)
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
            return resp

    return render_template('manager_login.html')

@app.route('/manager/signup', methods=['GET', 'POST'])
def manager_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if Manager.query.filter_by(username=username).first():
            return "Username already exists. Please choose a different username."

        if password != confirm_password:
            return "Passwords do not match. Please try again."

        # Create and add the manager to the database
        manager = Manager(username=username, password=generate_password_hash(password))
        db.session.add(manager)
        db.session.commit()

        resp = make_response(redirect(url_for('main_page')))
        resp.set_cookie('manager', username)
        return resp

    return render_template('manager_signup.html')

@app.route('/user/dashboard')
def user_dashboard():
    # This is the user dashboard page
    if 'user' not in request.cookies:
        return redirect(url_for('user_login'))

    return redirect(url_for('main_page'))

@app.route('/manager/dashboard')
def manager_dashboard():
    # This is the manager dashboard page
    if 'manager' not in request.cookies:
        return redirect(url_for('manager_login'))

    return "Welcome to your manager dashboard!"

if __name__ == '__main__':
    app.run(debug=True)
