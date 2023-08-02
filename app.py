# app.py
from flask import Flask, render_template, request, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# In a real application, store users and managers in a database. For simplicity, we'll use dictionaries.
users = {}
managers = {}

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
    return render_template('main_page.html')

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

        user = users.get(username)
        if user and check_password_hash(user['password'], password):
            # Successful login, redirect to user dashboard
            return redirect(url_for('user_dashboard'))

    return render_template('user_login.html')

@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in users:
            return "Username already exists. Please choose a different username."

        # Store the user details in the dictionary
        users[username] = {'username': username, 'password': generate_password_hash(password)}
        return redirect(url_for('user_dashboard'))

    return render_template('user_signup.html')

@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        manager = managers.get(username)
        if manager and check_password_hash(manager['password'], password):
            # Successful login, redirect to manager dashboard
            return redirect(url_for('manager_dashboard'))

    return render_template('manager_login.html')

@app.route('/manager/signup', methods=['GET', 'POST'])
def manager_signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username in managers:
            return "Username already exists. Please choose a different username."

        # Store the manager details in the dictionary
        managers[username] = {'username': username, 'password': generate_password_hash(password)}
        return redirect(url_for('manager_dashboard'))

    return render_template('manager_signup.html')

@app.route('/user/dashboard')
def user_dashboard():
    # This is the user dashboard page
    return "Welcome to your user dashboard!"

@app.route('/manager/dashboard')
def manager_dashboard():
    # This is the manager dashboard page
    return "Welcome to your manager dashboard!"

if __name__ == '__main__':
    app.run(debug=True)
