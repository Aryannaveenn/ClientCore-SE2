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

                         
@app.route('/customer/<int:customer_id>/add_interaction', methods=['POST'])
def add_interaction(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    interaction_type = request.form['interaction_type']
    notes = request.form['notes']
    reminder_date = request.form.get('reminder_date')
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO interactions 
                 (customer_id, user_id, interaction_type, notes, reminder_date) 
                 VALUES (?, ?, ?, ?, ?)''',
             (customer_id, session['user_id'], interaction_type, notes, reminder_date))
    conn.commit()
    conn.close()
    
    flash('Interaction added successfully!', 'success')
    return redirect(url_for('view_customer', customer_id=customer_id))

@app.route('/customer/<int:customer_id>/update_status', methods=['POST'])
def update_customer_status(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    status = request.form['status']
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE customers SET status = ? WHERE id = ?',
             (status, customer_id))
    conn.commit()
    conn.close()
    
    flash('Customer status updated successfully!', 'success')
    return redirect(url_for('view_customer', customer_id=customer_id))


@app.route('/lists')
def lists():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get user's lists
    cursor.execute('SELECT * FROM customer_lists WHERE user_id = ?', (session['user_id'],))
    lists = cursor.fetchall()
    conn.close()
    
    return render_template('lists.html', lists=lists)

@app.route('/list/add', methods=['GET', 'POST'])
def add_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = request.form['name']
        customer_ids = request.form.getlist('customers')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Create new list
        cursor.execute('INSERT INTO customer_lists (name, user_id) VALUES (?, ?)',
                 (name, session['user_id']))
        list_id = cursor.lastrowid
        
        # Add customers to list
        for customer_id in customer_ids:
            cursor.execute('INSERT INTO list_customers (list_id, customer_id) VALUES (?, ?)',
                     (list_id, customer_id))
        
        conn.commit()
        conn.close()
        
        flash('List created successfully!', 'success')
        return redirect(url_for('lists'))
    
    # Get all customers for the form
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM customers ORDER BY name')
    customers = cursor.fetchall()
    conn.close()
    
    return render_template('add_list.html', customers=customers)

@app.route('/list/<int:list_id>')
def view_list(list_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get list details
    cursor.execute('SELECT * FROM customer_lists WHERE id = ? AND user_id = ?', 
                  (list_id, session['user_id']))
    list_data = cursor.fetchone()
    
    if not list_data:
        flash('List not found or unauthorized', 'error')
        return redirect(url_for('lists'))
    
    # Get customers in this list
    cursor.execute('''SELECT c.* FROM customers c
                 JOIN list_customers lc ON c.id = lc.customer_id
                 WHERE lc.list_id = ?
                 ORDER BY c.name''', (list_id,))
    customers = cursor.fetchall()
    
    # Get available customers (not in the list)
    cursor.execute('''SELECT c.* FROM customers c
                 WHERE c.id NOT IN (
                     SELECT customer_id FROM list_customers WHERE list_id = ?
                 )
                 ORDER BY c.name''', (list_id,))
    available_customers = cursor.fetchall()
    
    conn.close()
    
    return render_template('view_list.html', 
                         list_id=list_id,
                         list_name=list_data['name'],
                         customers=customers,
                         available_customers=available_customers)

@app.route('/list/<int:list_id>/add_customers', methods=['POST'])
def add_customers_to_list(list_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    customer_ids = request.form.getlist('customer_ids')
    if not customer_ids:
        flash('Please select at least one customer to add', 'error')
        return redirect(url_for('view_list', list_id=list_id))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify list ownership
    cursor.execute('SELECT id FROM customer_lists WHERE id = ? AND user_id = ?',
                  (list_id, session['user_id']))
    if not cursor.fetchone():
        flash('List not found or unauthorized', 'error')
        return redirect(url_for('lists'))
    
    # Add customers to list
    for customer_id in customer_ids:
        try:
            cursor.execute('INSERT INTO list_customers (list_id, customer_id) VALUES (?, ?)',
                         (list_id, customer_id))
        except sqlite3.IntegrityError:
            # Customer already in list, skip
            continue
    
    conn.commit()
    conn.close()
    
    flash('Customers added to list successfully!', 'success')
    return redirect(url_for('view_list', list_id=list_id))

@app.route('/list/<int:list_id>/remove_customer/<int:customer_id>', methods=['POST'])
def remove_customer_from_list(list_id, customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify list ownership
    cursor.execute('SELECT id FROM customer_lists WHERE id = ? AND user_id = ?',
                  (list_id, session['user_id']))
    if not cursor.fetchone():
        flash('List not found or unauthorized', 'error')
        return redirect(url_for('lists'))
    
    # Remove customer from list
    cursor.execute('DELETE FROM list_customers WHERE list_id = ? AND customer_id = ?',
                  (list_id, customer_id))
    
    if cursor.rowcount > 0:
        conn.commit()
        flash('Customer removed from list successfully!', 'success')
    else:
        flash('Customer not found in list', 'error')
    
    conn.close()
    return redirect(url_for('view_list', list_id=list_id))


@app.route('/customer/<int:customer_id>/interaction/<int:interaction_id>/delete', methods=['POST'])
def delete_interaction(customer_id, interaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify the interaction belongs to the user
    cursor.execute('''
        SELECT i.id FROM interactions i
        WHERE i.id = ? AND i.user_id = ?
    ''', (interaction_id, session['user_id']))
    
    interaction = cursor.fetchone()
    
    if interaction:
        cursor.execute('DELETE FROM interactions WHERE id = ?', (interaction_id,))
        conn.commit()
        flash('Interaction deleted successfully', 'success')
    else:
        flash('Interaction not found or unauthorized', 'error')
    
    conn.close()
    return redirect(url_for('view_customer', customer_id=customer_id))

@app.route('/customer/<int:customer_id>/edit', methods=['GET', 'POST'])
def edit_customer(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        gender = request.form['gender']
        
        if email and not is_valid_email(email):
            flash('Please enter a valid email address', 'error')
            return redirect(url_for('edit_customer', customer_id=customer_id))
        
        cursor.execute('''UPDATE customers 
                     SET name = ?, email = ?, phone = ?, address = ?, gender = ?
                     WHERE id = ?''',
                     (name, email, phone, address, gender, customer_id))
        conn.commit()
        conn.close()
        
        flash('Customer updated successfully!', 'success')
        return redirect(url_for('view_customer', customer_id=customer_id))
    
    # GET request - fetch customer details
    cursor.execute('SELECT * FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    conn.close()
    
    if not customer:
        flash('Customer not found', 'error')
        return redirect(url_for('customers'))
    
    return render_template('edit_customer.html', customer=customer)

@app.route('/customer/<int:customer_id>/interaction/<int:interaction_id>/edit', methods=['GET', 'POST'])
def edit_interaction(customer_id, interaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        interaction_type = request.form['interaction_type']
        notes = request.form['notes']
        reminder_date = request.form.get('reminder_date')
        
        cursor.execute('''UPDATE interactions 
                     SET interaction_type = ?, notes = ?, reminder_date = ?
                     WHERE id = ? AND user_id = ? AND customer_id = ?''',
                     (interaction_type, notes, reminder_date, 
                      interaction_id, session['user_id'], customer_id))
        conn.commit()
        conn.close()
        
        flash('Interaction updated successfully!', 'success')
        return redirect(url_for('view_customer', customer_id=customer_id))
    
    # GET request - fetch interaction details
    cursor.execute('''SELECT * FROM interactions 
                 WHERE id = ? AND user_id = ? AND customer_id = ?''',
                 (interaction_id, session['user_id'], customer_id))
    interaction = cursor.fetchone()
    conn.close()
    
    if not interaction:
        flash('Interaction not found or unauthorized', 'error')
        return redirect(url_for('view_customer', customer_id=customer_id))
    
    return render_template('edit_interaction.html', 
                         customer_id=customer_id,
                         interaction=interaction)


@app.route('/customer/<int:customer_id>/delete', methods=['POST'])
def delete_customer(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # First, delete all interactions for this customer
    cursor.execute('DELETE FROM interactions WHERE customer_id = ?', (customer_id,))
    
    # Then delete the customer
    cursor.execute('DELETE FROM customers WHERE id = ?', (customer_id,))
    
    if cursor.rowcount > 0:
        conn.commit()
        flash('Customer deleted successfully!', 'success')
    else:
        flash('Customer not found', 'error')
    
    conn.close()
    return redirect(url_for('customers'))


@app.route('/tasks')
def tasks():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get tasks grouped by status
    cursor.execute('''SELECT * FROM tasks 
                 WHERE user_id = ? 
                 ORDER BY 
                     CASE status 
                         WHEN 'Pending' THEN 1 
                         WHEN 'In Progress' THEN 2 
                         WHEN 'Completed' THEN 3 
                     END,
                     due_date''', (session['user_id'],))
    tasks = cursor.fetchall()
    
    # Group tasks by status
    tasks_by_status = {
        'Pending': [],
        'In Progress': [],
        'Completed': []
    }
    
    for task in tasks:
        tasks_by_status[task['status']].append(task)
    
    conn.close()
    
    return render_template('tasks.html', tasks_by_status=tasks_by_status)


@app.route('/task/add', methods=['GET', 'POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        priority = request.form['priority']
        status = request.form['status']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''INSERT INTO tasks 
                     (title, description, due_date, priority, status, user_id) 
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 (title, description, due_date, priority, status, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Task added successfully!', 'success')
        return redirect(url_for('tasks'))
    
    return render_template('add_task.html')

@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
def edit_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        priority = request.form['priority']
        status = request.form['status']
        
        cursor.execute('''UPDATE tasks 
                     SET title = ?, description = ?, due_date = ?, 
                         priority = ?, status = ?
                     WHERE id = ? AND user_id = ?''',
                     (title, description, due_date, priority, status, 
                      task_id, session['user_id']))
        conn.commit()
        conn.close()
        
        flash('Task updated successfully!', 'success')
        return redirect(url_for('tasks'))
    
    # GET request - fetch task details
    cursor.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', 
                  (task_id, session['user_id']))
    task = cursor.fetchone()
    conn.close()
    
    if not task:
        flash('Task not found or unauthorized', 'error')
        return redirect(url_for('tasks'))
    
    return render_template('edit_task.html', task=task)

@app.route('/task/<int:task_id>/delete', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', 
                  (task_id, session['user_id']))
    
    if cursor.rowcount > 0:
        conn.commit()
        flash('Task deleted successfully!', 'success')
    else:
        flash('Task not found or unauthorized', 'error')
    
    conn.close()
    return redirect(url_for('tasks'))


@app.route('/list/<int:list_id>/delete', methods=['POST'])
def delete_list(list_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Verify list ownership
    cursor.execute('SELECT id FROM customer_lists WHERE id = ? AND user_id = ?',
                  (list_id, session['user_id']))
    if not cursor.fetchone():
        flash('List not found or unauthorized', 'error')
        return redirect(url_for('lists'))
    
    # First, delete all list_customers entries
    cursor.execute('DELETE FROM list_customers WHERE list_id = ?', (list_id,))
    
    # Then delete the list
    cursor.execute('DELETE FROM customer_lists WHERE id = ?', (list_id,))
    
    if cursor.rowcount > 0:
        conn.commit()
        flash('List deleted successfully!', 'success')
    else:
        flash('List not found', 'error')
    
    conn.close()
    return redirect(url_for('lists'))


if __name__ == '__main__':
    app.run(debug=True)