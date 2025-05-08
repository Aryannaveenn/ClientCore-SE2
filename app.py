import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import bcrypt
import re
import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)

def init_db():
    conn = sqlite3.connect('CRM.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phoneno TEXT NOT NULL,
        address TEXT,
        gender TEXT,
        status TEXT DEFAULT 'New',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS customer_lists (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        user_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS lists_customers (
        list_id INTEGER,
        customer_id INTEGER,
        PRIMARY KEY (list_id, customer_id),
        FOREIGN KEY (list_id) REFERENCES customer_lists(id),
        FOREIGN KEY (customer_id) REFERENCES customers(id)
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS interactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        interaction_type TEXT,
        notes TEXT,
        reminder_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES customers(id)
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS tasks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        due_date TIMESTAMP,
        priority TEXT,
        status TEXT DEFAULT 'Pending',
        user_id INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('CRM.db')
    conn.row_factory = sqlite3.Row
    return conn

def email_valid(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def hash_password(password):
    if not password:
        return None
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def check_password(password, hashed):
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except (ValueError, AttributeError):
        return False

#login page route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password(password, user['password']):
            session['user_id'] = user['id']
            session['email'] = user['email']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

#register page route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        if not is_valid_email(email):
            flash('Please enter a valid email address', 'error')
            return render_template('register.html')
        
        conn = get_db()
        cursor = conn.cursor()
        
        try:
            hashed_password = hash_password(password)
            cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)',
                     (email, hashed_password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

#logout route
@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out successfully", "info")
    return redirect(url_for('login'))


@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get statistics
    cursor.execute('SELECT COUNT(*) as total FROM customers')
    total_customers = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as total FROM customer_lists WHERE user_id = ?', (session['user_id'],))
    total_lists = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as total FROM tasks WHERE user_id = ? AND status != "Completed"', (session['user_id'],))
    active_tasks = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as total FROM interactions WHERE user_id = ?', (session['user_id'],))
    total_interactions = cursor.fetchone()['total']
    
    # Get recent customers
    cursor.execute('SELECT * FROM customers ORDER BY created_at DESC LIMIT 5')
    recent_customers = cursor.fetchall()
    
    # Get recent interactions
    cursor.execute('''SELECT interactions.*, customers.name as customer_name 
                 FROM interactions 
                 JOIN customers ON interactions.customer_id = customers.id 
                 WHERE interactions.user_id = ? 
                 ORDER BY interactions.created_at DESC LIMIT 5''', (session['user_id'],))
    recent_interactions = cursor.fetchall()
    
    conn.close()
    
    stats = {
        'total_customers': total_customers,
        'total_lists': total_lists,
        'active_tasks': active_tasks,
        'total_interactions': total_interactions
    }
    
    return render_template('index.html', 
                         stats=stats,
                         recent_customers=recent_customers,
                         recent_interactions=recent_interactions)



@app.route('/customers')
def customers():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM customers ORDER BY name')
    customers = cursor.fetchall()
    conn.close()
    
    return render_template('customers.html', customers=customers)


@app.route('/customer/add', methods=['GET', 'POST'])
def add_customer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        gender = request.form['gender']
        
        if email and not is_valid_email(email):
            flash('Please enter a valid email address', 'error')
            return render_template('add_customer.html')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO customers (name, email, phone, address, gender) VALUES (?, ?, ?, ?, ?)',
                 (name, email, phone, address, gender))
        conn.commit()
        conn.close()
        
        flash('Customer added successfully!', 'success')
        return redirect(url_for('customers'))
    
    return render_template('add_customer.html')

@app.route('/customer/<int:customer_id>')
def view_customer(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get customer details
    cursor.execute('SELECT * FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    
    # Get customer interactions
    cursor.execute('''SELECT * FROM interactions 
                 WHERE customer_id = ? 
                 ORDER BY created_at DESC''', (customer_id,))
    interactions = cursor.fetchall()
    
    conn.close()
    
    if not customer:
        flash('Customer not found', 'error')
        return redirect(url_for('customers'))
    
    return render_template('view_customer.html', 
                         customer=customer,
                         interactions=interactions)
