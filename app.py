#import frameworks and modules
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
import os
import bcrypt
import re
import datetime


app = Flask(__name__) #using flask
app.secret_key = os.urandom(24) #random secret key for application initialisation


#initialise db
def init_db():
    conn = sqlite3.connect('crm.db')
    cursor = conn.cursor() #cursor is the object which interacts with the database
    
    # Create users table
    cursor.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  email TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create customers table
    cursor.execute('''CREATE TABLE IF NOT EXISTS customers
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  email TEXT,
                  phone TEXT,
                  address TEXT,
                  gender TEXT,
                  status TEXT DEFAULT 'New',
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Create customer lists table
    cursor.execute('''CREATE TABLE IF NOT EXISTS customer_lists
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  name TEXT NOT NULL,
                  user_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Create list_customers table (many-to-many relationship)
    cursor.execute('''CREATE TABLE IF NOT EXISTS list_customers
                 (list_id INTEGER,
                  customer_id INTEGER,
                  PRIMARY KEY (list_id, customer_id),
                  FOREIGN KEY (list_id) REFERENCES customer_lists (id),
                  FOREIGN KEY (customer_id) REFERENCES customers (id))''')
    
    # Create interactions table
    cursor.execute('''CREATE TABLE IF NOT EXISTS interactions
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  customer_id INTEGER,
                  user_id INTEGER,
                  interaction_type TEXT NOT NULL,
                  notes TEXT,
                  reminder_date TIMESTAMP,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (customer_id) REFERENCES customers (id),
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Create tasks table
    cursor.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  description TEXT,
                  due_date TIMESTAMP,
                  priority TEXT,
                  status TEXT DEFAULT 'Pending',
                  user_id INTEGER,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (user_id) REFERENCES users (id))''')
    
    # Create task_customers table (many-to-many relationship)
    cursor.execute('''CREATE TABLE IF NOT EXISTS task_customers
                 (task_id INTEGER,
                  customer_id INTEGER,
                  PRIMARY KEY (task_id, customer_id),
                  FOREIGN KEY (task_id) REFERENCES tasks (id),
                  FOREIGN KEY (customer_id) REFERENCES customers (id))''')
    
    conn.commit()
    conn.close()


init_db() 

# Helper function to get database connection
def get_db():
    conn = sqlite3.connect('crm.db')
    conn.row_factory = sqlite3.Row
    return conn

def is_valid_email(email): #function to check if the email the user inputs is valid email
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password): #to see if password the user inputs meets requirements for a strong password
    requirements = {
        'length': len(password) >= 8,
        'uppercase': any(c.isupper() for c in password),
        'lowercase': any(c.islower() for c in password),
        'number': any(c.isdigit() for c in password),
        'special': any(not c.isalnum() for c in password)
    }
    
    if not all(requirements.values()): #if all requirements are not met then return false
        missing = [req for req, met in requirements.items() if not met]
        return False, missing
    return True, []

def hash_password(password): #hashing password bcrypt salt algorithm
    if not password:
        return None
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def check_password(password, hashed): #checking if user input password matches password in db by decrypting the password in db
    if not password or not hashed:
        return False
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except (ValueError, AttributeError):
        return False

#login page route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST': #post method for sending data to db
        email = request.form['email'] #email and password fields entry
        password = request.form['password']
        
        conn = get_db() #initial db
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,)) #searching the user and email fields in DB
        user = cursor.fetchone() 
        conn.close()
        
        if user and check_password(password, user['password']): #checks password in db against user input
            session['user_id'] = user['id'] #creates session with user_id
            session['email'] = user['email'] #creates session with email 
            flash('Login successful!', 'success') 
            return redirect(url_for('index')) #redirect to home page after login
        else:
            flash('Invalid email or password', 'error')
    
    return render_template('login.html') #if login doesn't work

#register page route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']   #confirm password field

        if email and not is_valid_email(email): #checking if email is valid using the function above
            flash('Please enter a valid email address', 'error')
            return render_template('register.html')
            
        if password != confirm_password: #checking if the password matches the confirm password field
            flash('Passwords do not match!', 'error')
            return render_template('register.html')
            
        is_valid, missing_requirements = validate_password(password) #checking if password meets the requirements
        if not is_valid:
            requirements_text = {
                'length': 'at least 8 characters',
                'uppercase': 'one uppercase letter',
                'lowercase': 'one lowercase letter',
                'number': 'one number',
                'special': 'one special character'
            }
            missing_text = [requirements_text[req] for req in missing_requirements]
            flash(f'Password must contain: {", ".join(missing_text)}', 'error')
            return render_template('register.html')
        
        conn = get_db()
        cursor = conn.cursor()
        
        try: #error handling
            hashed_password = hash_password(password) #hashing password and storing to db
            cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)',
                     (email, hashed_password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError: #integrity error to see if the data already exists, so it doesn't create a duplicate
            flash('Email already exists', 'error')
        finally:
            conn.close()
    
    return render_template('register.html')

#logout route
@app.route('/logout')
def logout():
    session.clear() #clears user_id and email session so user is not logged in
    flash("You have been logged out successfully", "info")
    return redirect(url_for('login'))


# Home Page Route
@app.route('/') 
def index():
    if 'user_id' not in session:
        return redirect(url_for('login')) #checks if user is logged in, if not then login page
    
    conn = get_db()
    cursor = conn.cursor()
    
    # Get stats to display in the page counters 
    cursor.execute('SELECT COUNT(*) as total FROM customers')
    total_customers = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as total FROM customer_lists WHERE user_id = ?', (session['user_id'],))
    total_lists = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as total FROM tasks WHERE user_id = ? AND status != "Completed"', (session['user_id'],))
    active_tasks = cursor.fetchone()['total']
    
    cursor.execute('SELECT COUNT(*) as total FROM interactions WHERE user_id = ?', (session['user_id'],))
    total_interactions = cursor.fetchone()['total']
    
    # Get recent customers to display
    cursor.execute('SELECT * FROM customers ORDER BY created_at DESC LIMIT 5')
    recent_customers = cursor.fetchall()
    
    # Get recent interactions to display
    cursor.execute('''SELECT interactions.*, customers.name as customer_name 
                 FROM interactions 
                 JOIN customers ON interactions.customer_id = customers.id 
                 WHERE interactions.user_id = ? 
                 ORDER BY interactions.created_at DESC LIMIT 5''', (session['user_id'],))
    recent_interactions = cursor.fetchall()
    
    conn.close()
    
    #defining stats for the counters
    stats = {
        'total_customers': total_customers,
        'total_lists': total_lists,
        'active_tasks': active_tasks,
        'total_interactions': total_interactions
    }
    
    return render_template('index.html', 
                         stats=stats,
                         recent_customers=recent_customers,
                         recent_interactions=recent_interactions) #rendering stats for the home page


# Customers Page Route
@app.route('/customers')
def customers():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    search_query = request.args.get('search', '').strip() #search bar for customers page
    
    conn = get_db()
    cursor = conn.cursor()
    
    if search_query:
        #users can search in name, email or phone num.
        cursor.execute('''
            SELECT * FROM customers 
            WHERE name LIKE ? OR email LIKE ? OR phone LIKE ?
            ORDER BY name
        ''', (f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'))
    else:
        cursor.execute('SELECT * FROM customers ORDER BY name') #if query is empty then just order by name
    
    customers = cursor.fetchall()
    conn.close()
    
    return render_template('customers.html', customers=customers, search_query=search_query)


# Add Customer Route
@app.route('/customer/add', methods=['GET', 'POST'])
def add_customer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    #fields to add a customer, post method to send data to db
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        gender = request.form['gender']
        
        #using same check function to ensure email is valid
        if email and not is_valid_email(email):
            flash('Please enter a valid email address', 'error')
            return render_template('add_customer.html')
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('INSERT INTO customers (name, email, phone, address, gender) VALUES (?, ?, ?, ?, ?)',
                 (name, email, phone, address, gender)) #put data into db
        conn.commit()
        conn.close()
        
        flash('Customer added successfully!', 'success')
        return redirect(url_for('customers'))
    
    return render_template('add_customer.html')

# Individual Customer View Route
@app.route('/customer/<int:customer_id>')
def view_customer(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    #get customer details
    cursor.execute('SELECT * FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    
    #get customer interactions
    cursor.execute('''SELECT * FROM interactions 
                 WHERE customer_id = ? 
                 ORDER BY created_at DESC''', (customer_id,))
    interactions = cursor.fetchall()
    
    conn.close()
    
    #if customer does not exist, error handling
    if not customer:
        flash('Customer not found', 'error')
        return redirect(url_for('customers'))
    
    return render_template('view_customer.html', 
                         customer=customer,
                         interactions=interactions,
                         current_user_id=session['user_id'])


# Add Interaction Route
@app.route('/customer/<int:customer_id>/add_interaction', methods=['POST'])
def add_interaction(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    #fields for interaction
    interaction_type = request.form['interaction_type']
    notes = request.form['notes']
    reminder_date = request.form.get('reminder_date')
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''INSERT INTO interactions 
                 (customer_id, user_id, interaction_type, notes, reminder_date) 
                 VALUES (?, ?, ?, ?, ?)''',
             (customer_id, session['user_id'], interaction_type, notes, reminder_date))
    conn.commit() #add to db
    conn.close()
    
    flash('Interaction added successfully!', 'success')
    return redirect(url_for('view_customer', customer_id=customer_id))

# Lists Page Route
@app.route('/lists')
def lists():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    #Show the user's lists
    cursor.execute('SELECT * FROM customer_lists WHERE user_id = ?', (session['user_id'],))
    lists = cursor.fetchall()
    conn.close()
    
    return render_template('lists.html', lists=lists)


# Add List Route
@app.route('/list/add', methods=['GET', 'POST'])
def add_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    #fields for adding a list
    if request.method == 'POST':
        name = request.form['name']
        customer_ids = request.form.getlist('customers') #attaching customers
        
        conn = get_db()
        cursor = conn.cursor()
        
        #add data to db
        cursor.execute('INSERT INTO customer_lists (name, user_id) VALUES (?, ?)',
                 (name, session['user_id']))
        list_id = cursor.lastrowid
        
        #adding customer to list
        for customer_id in customer_ids:
            cursor.execute('INSERT INTO list_customers (list_id, customer_id) VALUES (?, ?)',
                     (list_id, customer_id))
        
        conn.commit()
        conn.close()
        
        flash('List created successfully!', 'success')
        return redirect(url_for('lists'))
    
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM customers ORDER BY name') #display customers in the selection field for customers by name
    customers = cursor.fetchall()
    conn.close()
    
    return render_template('add_list.html', customers=customers)

# Individual List View Route
@app.route('/list/<int:list_id>')
def view_list(list_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    #get list details to display
    cursor.execute('SELECT * FROM customer_lists WHERE id = ? AND user_id = ?', 
                  (list_id, session['user_id']))
    list_data = cursor.fetchone()
    
    if not list_data:
        flash('List not found or unauthorised', 'error')
        return redirect(url_for('lists'))
    
    ##show customers in the list
    cursor.execute('''SELECT c.* FROM customers c
                 JOIN list_customers lc ON c.id = lc.customer_id
                 WHERE lc.list_id = ?
                 ORDER BY c.name''', (list_id,))
    customers = cursor.fetchall()
    
    #show customers to add
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


# Add Customers to List Route
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
    #checking if the list belongs to the person trying to access it
    cursor.execute('SELECT id FROM customer_lists WHERE id = ? AND user_id = ?',
                  (list_id, session['user_id']))
    if not cursor.fetchone():
        flash('List not found or unauthorised', 'error') #if someone else trying to access the list
        return redirect(url_for('lists'))
    
    #adding customers to list row
    for customer_id in customer_ids:
        try:
            cursor.execute('INSERT INTO list_customers (list_id, customer_id) VALUES (?, ?)',
                         (list_id, customer_id))
        except sqlite3.IntegrityError: #error handling if customer is already in the list 
            continue
    
    conn.commit()
    conn.close()
    
    flash('Customers added to list successfully!', 'success')
    return redirect(url_for('view_list', list_id=list_id))

# Remove Customer List Route
@app.route('/list/<int:list_id>/remove_customer/<int:customer_id>', methods=['POST'])
def remove_customer_from_list(list_id, customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    #ensuring list is owned by person trying to access it
    cursor.execute('SELECT id FROM customer_lists WHERE id = ? AND user_id = ?',
                  (list_id, session['user_id']))
    if not cursor.fetchone():
        flash('List not found or unauthorised', 'error')
        return redirect(url_for('lists'))
    
    #remove customer from list db
    cursor.execute('DELETE FROM list_customers WHERE list_id = ? AND customer_id = ?',
                  (list_id, customer_id))
    
    if cursor.rowcount > 0:
        conn.commit()
        flash('Customer removed from list successfully!', 'success')
    else:
        flash('Customer not found in list', 'error')
    
    conn.close()
    return redirect(url_for('view_list', list_id=list_id))

# Delete Interaction Route
@app.route('/customer/<int:customer_id>/interaction/<int:interaction_id>/delete', methods=['POST'])
def delete_interaction(customer_id, interaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    conn = get_db()
    cursor = conn.cursor()
    
    #verifies that the person trying to delete the interaction also created it
    cursor.execute('''
        SELECT i.id FROM interactions i
        WHERE i.id = ? AND i.user_id = ?
    ''', (interaction_id, session['user_id']))
    
    interaction = cursor.fetchone()
    
    #deleting interaction and sending flash message to user for confirmation
    if interaction:
        cursor.execute('DELETE FROM interactions WHERE id = ?', (interaction_id,))
        conn.commit()
        flash('Interaction deleted successfully', 'success')
    else:
        flash('Interaction not found or unauthorised', 'error')
    
    conn.close()
    return redirect(url_for('view_customer', customer_id=customer_id))


# Edit Customer Route
@app.route('/customer/<int:customer_id>/edit', methods=['GET', 'POST'])
def edit_customer(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST': #post method to get info from edit_customer fields
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        address = request.form['address']
        gender = request.form['gender']
         
        #ensuring email is valid
        if email and not is_valid_email(email):
            flash('Please enter a valid email address', 'error')
            return redirect(url_for('edit_customer', customer_id=customer_id))
        
        #updating the existing row for the customer details
        cursor.execute('''UPDATE customers 
                     SET name = ?, email = ?, phone = ?, address = ?, gender = ?
                     WHERE id = ?''',
                     (name, email, phone, address, gender, customer_id))
        conn.commit()
        conn.close()
        
        flash('Customer updated successfully!', 'success')
        return redirect(url_for('view_customer', customer_id=customer_id))
    
    cursor.execute('SELECT * FROM customers WHERE id = ?', (customer_id,))
    customer = cursor.fetchone()
    conn.close()
    
    #error handling to ensure the wrong customer cannot be accessed.
    if not customer:
        flash('Customer not found', 'error')
        return redirect(url_for('customers'))
    
    return render_template('edit_customer.html', customer=customer)

# Edit Interaction Route
@app.route('/customer/<int:customer_id>/interaction/<int:interaction_id>/edit', methods=['GET', 'POST'])
def edit_interaction(customer_id, interaction_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST': #post method to get data from the input fields
        interaction_type = request.form['interaction_type']
        notes = request.form['notes']
        reminder_date = request.form.get('reminder_date')
        
        #updating the interaction row in the existing row
        cursor.execute('''UPDATE interactions 
                     SET interaction_type = ?, notes = ?, reminder_date = ?
                     WHERE id = ? AND user_id = ? AND customer_id = ?''',
                     (interaction_type, notes, reminder_date, 
                      interaction_id, session['user_id'], customer_id))
        conn.commit()
        conn.close()
        
        flash('Interaction updated successfully!', 'success')
        return redirect(url_for('view_customer', customer_id=customer_id))
    
    #fetching interaction details for display
    cursor.execute('''SELECT * FROM interactions 
                 WHERE id = ? AND user_id = ? AND customer_id = ?''',
                 (interaction_id, session['user_id'], customer_id))
    interaction = cursor.fetchone()
    conn.close()
    
    if not interaction: #error handling to ensure interaction is real
        flash('Interaction not found or unauthorised', 'error')
        return redirect(url_for('view_customer', customer_id=customer_id))
    
    return render_template('edit_interaction.html', 
                         customer_id=customer_id,
                         interaction=interaction)

# Delete Customer Route
@app.route('/customer/<int:customer_id>/delete', methods=['POST'])
def delete_customer(customer_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    #delete interactions where the customer id matches the customer id for delete
    cursor.execute('DELETE FROM interactions WHERE customer_id = ?', (customer_id,))
    
    #delete the customer data in the customers table
    cursor.execute('DELETE FROM customers WHERE id = ?', (customer_id,))
    
    if cursor.rowcount > 0: #checking to see that everything was successfully deleted
        conn.commit()
        flash('Customer deleted successfully!', 'success')
    else:
        flash('Customer not found', 'error')
    
    conn.close()
    return redirect(url_for('customers'))

# Tasks Route
@app.route('/tasks')
def tasks():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    #grouping by status of task
    cursor.execute('''
        SELECT t.*, GROUP_CONCAT(c.name) as customer_names
        FROM tasks t
        LEFT JOIN task_customers tc ON t.id = tc.task_id
        LEFT JOIN customers c ON tc.customer_id = c.id
        WHERE t.user_id = ?
        GROUP BY t.id
        ORDER BY 
            CASE t.status 
                WHEN 'Pending' THEN 1 
                WHEN 'In Progress' THEN 2 
                WHEN 'Completed' THEN 3 
            END,
            t.due_date
    ''', (session['user_id'],))
    tasks = cursor.fetchall()
    
    #defining the different status for tasks 
    tasks_by_status = {
        'Pending': [],
        'In Progress': [],
        'Completed': []
    }
    
    #converting customer names from string to list to display in each task display
    for task in tasks:
        if task['customer_names']:
            task = dict(task)
            task['customer_names'] = task['customer_names'].split(',')
        tasks_by_status[task['status']].append(task)
    
    conn.close()
    
    return render_template('tasks.html', tasks_by_status=tasks_by_status)

# Add Task Route
@app.route('/task/add', methods=['GET', 'POST'])
def add_task():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST': #post method to get data from field
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        priority = request.form['priority']
        status = request.form['status']
        selected_customers = request.form.getlist('customers')
        #adding a new row for the new task
        cursor.execute('''INSERT INTO tasks 
                     (title, description, due_date, priority, status, user_id) 
                     VALUES (?, ?, ?, ?, ?, ?)''',
                 (title, description, due_date, priority, status, session['user_id']))
        
        task_id = cursor.lastrowid
        
        #add selected customers into the task using customer_id
        for customer_id in selected_customers:
            cursor.execute('INSERT INTO task_customers (task_id, customer_id) VALUES (?, ?)',
                         (task_id, customer_id))
        
        conn.commit()
        conn.close()
        
        flash('Task added successfully!', 'success')
        return redirect(url_for('tasks'))
    
    #display all customers by name order  for adding task 
    cursor.execute('SELECT * FROM customers ORDER BY name')
    customers = cursor.fetchall()
    conn.close()
    
    return render_template('add_task.html', customers=customers)

# Edit Task Route
@app.route('/task/<int:task_id>/edit', methods=['GET', 'POST'])
def edit_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    if request.method == 'POST': #post method to get data from input field
        title = request.form['title']
        description = request.form['description']
        due_date = request.form['due_date']
        priority = request.form['priority']
        status = request.form['status']
        selected_customers = request.form.getlist('customers')
        #updating the existing task row
        cursor.execute('''UPDATE tasks 
                     SET title = ?, description = ?, due_date = ?, 
                         priority = ?, status = ?
                     WHERE id = ? AND user_id = ?''',
                     (title, description, due_date, priority, status, 
                      task_id, session['user_id']))
        cursor.execute('DELETE FROM task_customers WHERE task_id = ?', (task_id,))
        for customer_id in selected_customers:
            cursor.execute('INSERT INTO task_customers (task_id, customer_id) VALUES (?, ?)',
                         (task_id, customer_id))
        
        conn.commit()
        conn.close()
        
        flash('Task updated successfully!', 'success')
        return redirect(url_for('tasks'))
    
    #displaying tasks after redirecting to tasks page
    cursor.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', 
                  (task_id, session['user_id']))
    task = cursor.fetchone()
    
    if not task: #error handling
        conn.close()
        flash('Task not found or unauthorised', 'error')
        return redirect(url_for('tasks'))
    
    #displaying all customers in the new task
    cursor.execute('SELECT * FROM customers ORDER BY name')
    customers = cursor.fetchall()
    
    #displaying customers attached
    cursor.execute('SELECT customer_id FROM task_customers WHERE task_id = ?', (task_id,))
    attached_customer_ids = [row['customer_id'] for row in cursor.fetchall()]
    
    conn.close()
    
    return render_template('edit_task.html', 
                         task=task,
                         customers=customers,
                         attached_customer_ids=attached_customer_ids)

# Delete Task Route
@app.route('/task/<int:task_id>/delete', methods=['POST'])
def delete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    #delete task which matches what the user chose
    cursor.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', 
                  (task_id, session['user_id']))
    
    if cursor.rowcount > 0: #checking if it deleted
        conn.commit()
        flash('Task deleted successfully!', 'success')
    else:
        flash('Task not found or unauthorised', 'error')
    
    conn.close()
    return redirect(url_for('tasks'))

# Complete Task Button Route
@app.route('/task/<int:task_id>/complete', methods=['POST'])
def complete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    #updating the status of the task to completed
    cursor.execute('''UPDATE tasks 
                     SET status = 'Completed'
                     WHERE id = ? AND user_id = ?''',
                  (task_id, session['user_id']))
    
    if cursor.rowcount > 0: #checking to see the task is still there
        conn.commit()
        flash('Task marked as completed!', 'success')
    else:
        flash('Task not found or unauthorised', 'error')
    
    conn.close()
    return redirect(url_for('tasks'))

# Delete List Route
@app.route('/list/<int:list_id>/delete', methods=['POST'])
def delete_list(list_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor()
    
    #checking if the list is owned by the person trying to delete
    cursor.execute('SELECT id FROM customer_lists WHERE id = ? AND user_id = ?',
                  (list_id, session['user_id']))
    if not cursor.fetchone():
        flash('List not found or unauthorised', 'error')
        return redirect(url_for('lists'))
    
    #delete all rows from list_customers where list id the same
    cursor.execute('DELETE FROM list_customers WHERE list_id = ?', (list_id,))
    
    #delete all rows from customer_lists where list id the same
    cursor.execute('DELETE FROM customer_lists WHERE id = ?', (list_id,))
    
    if cursor.rowcount > 0:
        conn.commit()
        flash('List deleted successfully!', 'success')
    else:
        flash('List not found', 'error')
    
    conn.close()
    return redirect(url_for('lists'))

#run app with debug turned on so changes appear
if __name__ == '__main__':
    app.run(debug=True)