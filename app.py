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

class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    category = db.Column(db.String(50), nullable=False)

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    total_price = db.Column(db.Float, nullable=False)
    items = db.relationship('OrderItem', back_populates='order', cascade='all, delete-orphan')
    user = db.relationship('User', backref='orders')

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

    order = db.relationship('Order', back_populates='items')
    item = db.relationship('MenuItem')
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
# Create database tables
menu = {
    # ... (your menu items here)
}
menu_items = [
    MenuItem(name='Espresso', price=3.0, quantity=20, category='espresso'),
    MenuItem(name='Double Espresso', price=4.5, quantity=15, category='espresso'),
    MenuItem(name='Americano', price=3.5, quantity=30, category='espresso'),
    MenuItem(name='Cappuccino', price=4.0, quantity=20, category='cappuccino'),
    MenuItem(name='Iced Cappuccino', price=4.5, quantity=15, category='cappuccino'),
    MenuItem(name='Caramel Cappuccino', price=5.0, quantity=30, category='cappuccino'),
    MenuItem(name='Croissant', price=2.0, quantity=10, category='pastries'),
    MenuItem(name='Danish', price=2.5, quantity=12, category='pastries'),
    MenuItem(name='Muffin', price=2.0, quantity=15, category='pastries'),
    MenuItem(name='Chicken Sandwich', price=5.0, quantity=10, category='sandwiches'),
    MenuItem(name='Vegetarian Sandwich', price=4.5, quantity=12, category='sandwiches'),
    MenuItem(name='BLT Sandwich', price=4.0, quantity=15, category='sandwiches'),
    # Add more menu items here
]

# Insert menu items into the database
for item in menu_items:
    db.session.add(item)

# Commit changes to the database
db.session.commit()
# Insert menu items into the database
for category, items in menu.items():
    for item_id, item_data in items.items():
        item = MenuItem(name=item_data['name'], price=item_data['price'], quantity=item_data['quantity'], category=category)
        db.session.add(item)

# Commit changes to the database
db.session.commit()
db.create_all()
MenuItem.query.all()
# Menu and Inventory data
menu = {
    'espresso': {
        '1': {'name': 'Espresso', 'price': 3.0, 'quantity': 20},
        '2': {'name': 'Double Espresso', 'price': 4.5, 'quantity': 15},
        '3': {'name': 'Americano', 'price': 3.5, 'quantity': 30},
    },
    'cappuccino': {
        '4': {'name': 'Cappuccino', 'price': 4.0, 'quantity': 20},
        '5': {'name': 'Iced Cappuccino', 'price': 4.5, 'quantity': 15},
        '6': {'name': 'Caramel Cappuccino', 'price': 5.0, 'quantity': 30},
    },
    'pastries': {
        '7': {'name': 'Croissant', 'price': 2.0, 'quantity': 10},
        '8': {'name': 'Danish', 'price': 2.5, 'quantity': 12},
        '9': {'name': 'Muffin', 'price': 2.0, 'quantity': 15},
    },
    'sandwiches': {
        '10': {'name': 'Chicken Sandwich', 'price': 5.0, 'quantity': 10},
        '11': {'name': 'Vegetarian Sandwich', 'price': 4.5, 'quantity': 12},
        '12': {'name': 'BLT Sandwich', 'price': 4.0, 'quantity': 15},
    },
    # Add more categories and items here
}
# Assuming you have the MenuItem model defined with 'price' attribute
menu_prices = {
    'espresso': {
        'Espresso': 3.0,
        'Double Espresso': 4.5,
        'Americano': 3.5,
    },
    'cappuccino': {
        'Cappuccino': 4.0,
        'Iced Cappuccino': 4.5,
        'Caramel Cappuccino': 5.0,
    },
    'pastries': {
        'Croissant': 2.0,
        'Danish': 2.5,
        'Muffin': 2.0,
    },
    'sandwiches': {
        'Chicken Sandwich': 5.0,
        'Vegetarian Sandwich': 4.5,
        'BLT Sandwich': 4.0,
    },
    # Add more categories and items here
}
# Cart data for users
# The structure is: {item_name: {'price': price, 'quantity': quantity}}
user_cart = {}
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

    # Redirect to role selection page if not logged in
    return redirect(url_for('select_role'))

@app.route('/select_role', methods=['GET', 'POST'])
def select_role():
    if request.method == 'POST':
        role = request.form.get('role')
        if role == 'user':
            return redirect(url_for('user_login'))
        elif role == 'manager':
            return redirect(url_for('manager_login'))

    return render_template('select_role.html')

@app.route('/category/<category>')
def category_menu(category):
    # Fetch the latest menu information from the database
    category_items = MenuItem.query.filter_by(category=category).all()
    category_menu_items = {item.name: {'price': item.price, 'quantity': item.quantity} for item in category_items}

    return render_template('category_menu.html', category=category, menu=category_menu_items)

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form.get('user_email')
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

    return render_template('user_login.html', signup_url=url_for('user_signup'), login_url=url_for('user_login'))

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
            return redirect(url_for('user_login'))  # Redirect to user login page after successful signup

    return render_template('user_signup.html', signup_url=url_for('user_signup'), login_url=url_for('user_login'))


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
                return render_template('manager_signup.html', manager_signup_url=url_for('manager_signup'), manager_login_url=url_for('manager_login'), missing_requirements=missing_requirements)

            # Create and add the manager to the database
            manager = Manager(first_name=first_name, last_name=last_name, email=email, password=generate_password_hash(password))
            db.session.add(manager)
            db.session.commit()

            flash("Manager successfully signed up. Please log in with your new credentials.", "success")
            return redirect(url_for('manager_login'))  # Redirect to manager login page after successful signup

    return render_template('manager_signup.html', manager_signup_url=url_for('manager_signup'), manager_login_url=url_for('manager_login'))

@app.route('/manager/login', methods=['GET', 'POST'])
def manager_login():
    if request.method == 'POST':
        email = request.form.get('manager_email')
        password = request.form.get('password')

        if not email or not password:
            flash("Please provide both email and password.", "error")
            return redirect(url_for('manager_login'))

        manager = Manager.query.filter_by(email=email).first()
        if manager and check_password_hash(manager.password, password):
            # Successful login, store manager information in session
            session['manager_email'] = email
            flash(f"Welcome, {manager.first_name}! You are now logged in as a manager.", "success")
            return redirect(url_for('manager_dashboard'))  # Redirect to manager dashboard after successful login
        else:
            flash("Invalid email address or password. Please try again.", "error")
            return redirect(url_for('manager_login'))

    # For GET request (initial page load), render the manager_login.html template
    return render_template('manager_login.html', manager_signup_url=url_for('manager_signup'), manager_login_url=url_for('manager_login'))

# ... (previous code)

# ... (previous code)

def get_cart_items():
    if 'user_cart' not in session:
        session['user_cart'] = {}
    return session['user_cart']

# ... (previous code)
def calculate_total_price(cart_items):
    total_price = 0.0
    for item_name, quantity in cart_items.items():
        menu_item = MenuItem.query.filter_by(name=item_name).first()
        if menu_item:
            total_price += menu_item.price * quantity
    return total_price
# ... (previous code)
@app.route('/user/dashboard', methods=['GET', 'POST'])
def user_dashboard():
    if 'user_email' not in session:
        flash("You need to log in as a user to access the dashboard.", "error")
        return redirect(url_for('user_login'))

    user = User.query.filter_by(email=session['user_email']).first()
    cart = session.get('cart', [])  # Initialize cart as an empty list if not found in session

    if request.method == 'POST':
        item_name = request.form.get('item_name')
        item_price = float(request.form.get('item_price'))
        quantity = int(request.form.get('quantity'))

        if item_name and quantity > 0:
            item_in_cart = next((item for item in cart if item['name'] == item_name), None)
            if item_in_cart:
                item_in_cart['quantity'] += quantity
                item_in_cart['subtotal'] = item_in_cart['quantity'] * item_price
            else:
                new_item = {
                    'name': item_name,
                    'price': item_price,
                    'quantity': quantity,
                    'subtotal': item_price * quantity
                }
                cart.append(new_item)

            session['cart'] = cart
            flash(f"{quantity} {item_name}{'s' if quantity > 1 else ''} added to the cart.", "success")
        else:
            flash("Invalid input. Please try again.", "error")

    # Fetch menu items from the database and organize them by category
    menu = {}
    categories = set(item.category for item in MenuItem.query.distinct(MenuItem.category))
    for category in categories:
        items = MenuItem.query.filter_by(category=category).all()
        menu[category] = {item.name: {'price': item.price, 'quantity': item.quantity} for item in items}

    total_price = sum(item['subtotal'] for item in cart)

    return render_template('user_dashboard.html', user_name=user.first_name, menu=menu, cart_items=cart, total_price=total_price)





@app.route('/manager/dashboard')
def manager_dashboard():
    if 'manager_email' not in session:
        flash("You need to log in as a manager to access the dashboard.", "error")
        return redirect(url_for('manager_login'))

    manager = Manager.query.filter_by(email=session['manager_email']).first()
    orders = Order.query.all()

    return render_template('manager_dashboard.html', manager_name=manager.first_name, orders=orders)


# ... (previous code)

@app.route('/manager/add_item', methods=['GET', 'POST'])
def add_item():
    if 'manager_email' not in session:
        flash("You need to log in as a manager to access this page.", "error")
        return redirect(url_for('manager_login'))

    if request.method == 'POST':
        category = request.form.get('category')
        item_name = request.form.get('item_name')
        item_price = request.form.get('item_price')
        quantity = request.form.get('quantity')

        if not category or not item_name or not item_price or not quantity:
            flash("Please fill out all the fields.", "error")
        else:
            try:
                item_price = float(item_price)
                quantity = int(quantity)
            except ValueError:
                flash("Invalid price or quantity. Please enter valid numbers.", "error")
                return redirect(url_for('add_item'))

            if category not in menu:
                flash("Invalid category. Please try again.", "error")
            else:
                existing_item = MenuItem.query.filter_by(name=item_name).first()
                if existing_item:
                    flash(f"The item '{item_name}' already exists in the menu.", "error")
                else:
                    new_item = MenuItem(name=item_name, price=item_price, quantity=quantity, category=category)
                    db.session.add(new_item)
                    db.session.commit()

                    # Update the menu dictionary for the category
                    menu[category][item_name] = {'price': item_price, 'quantity': quantity}

                    flash(f"The item '{item_name}' has been added to the menu.", "success")
                    return redirect(url_for('add_item'))

    return render_template('add_item.html', menu=menu)
@app.route('/manager/update_quantity', methods=['GET', 'POST'])
def update_quantity():
    if 'manager_email' not in session:
        flash("You need to log in as a manager to access this page.", "error")
        return redirect(url_for('manager_login'))

    # Fetch the latest menu items from the database
    menu_items = MenuItem.query.all()

    if request.method == 'POST':
        item_name = request.form.get('item_name')
        new_quantity = int(request.form.get('new_quantity'))

        if new_quantity < 0:
            flash("Invalid input. Quantity cannot be negative.", "error")
        else:
            item = MenuItem.query.filter_by(name=item_name).first()
            if item:
                item.quantity = new_quantity
                db.session.commit()
                flash(f"Item '{item_name}' quantity has been updated.", "success")
                # Update the menu dictionary with the new quantity
                for category, items in menu.items():
                    if item_name in items:
                        menu[category][item_name]['quantity'] = new_quantity
            else:
                flash(f"Item '{item_name}' not found in the menu.", "error")

    return render_template('update_quantity.html', menu=menu, menu_items=menu_items)

@app.route('/manager/view_orders')
def view_orders():
    if 'manager_email' not in session:
        flash("You need to log in as a manager to access this page.", "error")
        return redirect(url_for('manager_login'))

    manager = Manager.query.filter_by(email=session['manager_email']).first()
    orders = Order.query.all()

    return render_template('view_orders.html', manager_name=manager.first_name, orders=orders)

# ... (rest of the code)
# ... (other routes and code)

@app.route('/manager/logout')
def manager_logout():
    # Clear the manager session data to log them out
    session.pop('manager_email', None)
    flash("You have been logged out as a manager.", "success")
    return redirect(url_for('main_page'))

# ... (other routes and code)

@app.route('/logout')
def logout():
    # Clear the user and manager session data to log them out
    session.pop('user_email', None)
    session.pop('manager_email', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('main_page'))
@app.route('/add_to_cart_user', methods=['POST'])
def add_to_cart_user():
    if 'user_email' not in session:
        flash("You need to log in as a user to add items to the cart.", "error")
        return redirect(url_for('user_login'))

    item_id = int(request.form.get('item_id'))
    quantity = int(request.form.get('quantity'))

    menu_item = MenuItem.query.get(item_id)
    if not menu_item:
        flash("Invalid item selected.", "error")
        return redirect(url_for('user_dashboard'))

    if quantity > menu_item.quantity:
        flash(f"Insufficient quantity of {menu_item.name} in stock.", "error")
        return redirect(url_for('user_dashboard'))

    cart = session.get('cart', [])
    item_in_cart = next((item for item in cart if item['name'] == menu_item.name), None)
    if item_in_cart:
        item_in_cart['quantity'] += quantity
        item_in_cart['subtotal'] = item_in_cart['quantity'] * menu_item.price
    else:
        new_item = {
            'item_id': menu_item.id,
            'name': menu_item.name,
            'quantity': quantity,
            'price': menu_item.price,
            'subtotal': quantity * menu_item.price
        }
        cart.append(new_item)

    session['cart'] = cart
    flash(f"{quantity} {menu_item.name}{'s' if quantity > 1 else ''} added to the cart.", "success")
    return redirect(url_for('user_dashboard'))






@app.route('/remove_from_cart_user/<item_name>', methods=['POST'])
def remove_from_cart_user(item_name):
    if 'user_email' not in session:
        flash("You need to log in as a user to remove items from the cart.", "error")
        return redirect(url_for('user_login'))

    cart = session.get('cart', [])
    updated_cart = [item for item in cart if item['name'] != item_name]
    session['cart'] = updated_cart
    flash(f"{item_name} removed from the cart.", "success")
    return redirect(url_for('user_dashboard'))



@app.route('/place_order', methods=['POST'])
def place_order():
    if 'user_email' not in session:
        flash("You need to log in as a user to place an order.", "error")
        return redirect(url_for('user_login'))

    user = User.query.filter_by(email=session['user_email']).first()
    if not user:
        flash("User not found. Please log in again.", "error")
        return redirect(url_for('user_login'))

    cart = session.get('cart', [])
    if not cart:
        flash("Your cart is empty. Please add items before placing an order.", "error")
        return redirect(url_for('user_dashboard'))

    total_price = sum(item['subtotal'] for item in cart)

    # Check if items exist in the menu and have sufficient inventory before proceeding with the order
    for item_info in cart:
        menu_item = MenuItem.query.filter_by(name=item_info['name']).first()
        if not menu_item:
            flash(f"Item '{item_info['name']}' not found in the menu. Please remove it from the cart.", "error")
            return redirect(url_for('user_dashboard'))

        if item_info['quantity'] > menu_item.quantity:
            flash(f"Insufficient inventory for '{item_info['name']}'. Available: {menu_item.quantity}", "error")
            return redirect(url_for('user_dashboard'))

    order = Order(user_id=user.id, total_price=total_price)
    db.session.add(order)
    db.session.commit()

    for item_info in cart:
        menu_item = MenuItem.query.filter_by(name=item_info['name']).first()
        order_item = OrderItem(order_id=order.id, item_id=menu_item.id, quantity=item_info['quantity'])
        db.session.add(order_item)
        menu_item.quantity -= item_info['quantity']  # Reduce the item quantity from the inventory
        db.session.commit()
    flash("Your order has been placed successfully. Thank you!", "success")
    session['cart'] = []  # Clear the cart after placing the order
    flash("Your order has been placed successfully. Thank you!", "success")
    return redirect(url_for('user_dashboard'))


def get_missing_password_requirements(password):
    missing_requirements = []
    if len(password) < 8:
        missing_requirements.append("Password must be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        missing_requirements.append("Password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        missing_requirements.append("Password must contain at least one lowercase letter.")
    if not re.search(r'[0-9]', password):
        missing_requirements.append("Password must contain at least one digit.")
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        missing_requirements.append("Password must contain at least one special character (!@#$%^&*(),.?\":{}|<>).")

    return missing_requirements

if __name__ == "__main__":
    app.run(debug=True)
