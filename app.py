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
    # Check if user is already logged in
    # Redirect to respective dashboard if logged in, otherwise redirect to login page
    if 'user' in request.cookies:
        return redirect(url_for('user_dashboard'))
    elif 'manager' in request.cookies:
        return redirect(url_for('manager_dashboard'))
    else:
        return redirect(url_for('user_login'))

@app.route('/category/<category>')
def category_menu(category):
    if category not in menu:
        return "Category not found."

    return render_template('category_menu.html', category=category, menu=menu, inventory=inventory)

# ... routes for user login, signup, manager login, signup, user dashboard, and manager dashboard ...

if __name__ == '__main__':
    app.run(debug=True)
