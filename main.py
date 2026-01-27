from flask import Flask, render_template, request, redirect, url_for, send_file, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import os
from datetime import datetime
import sqlite3
import json
import stripe
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from flask_mail import Mail, Message


app = Flask(__name__)


app.secret_key = 'your-secret-key-here-random-string-123'

stripe.api_key = 'sk_test_...'  # Use test key, not live
STRIPE_PUBLISHABLE_KEY = 'pk_test_...'  # Use test key

DATABASE_PATH = os.environ.get('DATABASE_PATH', 'users.db')
DATABASE_URL = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

engine = create_engine(DATABASE_URL)
db_session = scoped_session(sessionmaker(bind=engine))
Base = declarative_base()




# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database setup
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
             (id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              email TEXT UNIQUE NOT NULL,
              password TEXT NOT NULL,
              subscription_status TEXT DEFAULT 'free',
              stripe_customer_id TEXT)''')
    conn.commit()
    conn.close()

init_db()

@app.route('/webhook', methods=['POST'])
def webhook():
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, os.environ.get('STRIPE_WEBHOOK_SECRET')
        )
    except ValueError:
        return 'Invalid payload', 400
    except stripe.error.SignatureVerificationError:
        return 'Invalid signature', 400
    
    if event['type'] == 'checkout.session.completed':
        session = event['data']['object']
        # Update user subscription
        
    elif event['type'] == 'customer.subscription.deleted':
        # Downgrade user to free
        pass
    
    return {'status': 'success'}

# User class
class User(UserMixin):
    def __init__(self, id, username, email):
        self.id = id
        self.username = username
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = c.fetchone()
    conn.close()
    if user:
        return User(user[0], user[1], user[2])
    return None

# Ensure user-specific data.csv exists
def get_user_csv_path(username):
    user_folder = f'data/{username}'
    if not os.path.exists(user_folder):
        os.makedirs(user_folder)
    csv_path = f'{user_folder}/data.csv'
    if not os.path.exists(csv_path):
        with open(csv_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['product_name', 'quantity', 'cost', 'sell', 'platform', 'profit', 'total_profit', 'date'])
    return csv_path

def check_flip_limit(username):
    csv_path = get_user_csv_path(username)
    try:
        with open(csv_path, 'r') as f:
            flip_count = len(f.readlines()) - 1  # Minus header
    except:
        flip_count = 0
    
    # Get subscription status
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT subscription_status FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    
    status = result[0] if result else 'free'
    
    if status == 'free' and flip_count >= 10:
        return False  # Hit limit
    return True  # Can still add flips


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Validate
        if len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return redirect(url_for('register'))
        
        # Hash password
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        # Save to database
        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                     (username, email, hashed_password))
            conn.commit()
            conn.close()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[3], password):
            user_obj = User(user[0], user[1], user[2])
            login_user(user_obj)
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', username=current_user.username)

@app.route('/history')
@login_required
def history():
    csv_path = get_user_csv_path(current_user.username)
    flips = []
    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Ensure all values are properly formatted
                row['cost'] = float(row.get('cost', 0))
                row['sell'] = float(row.get('sell', 0))
                row['quantity'] = int(row.get('quantity', 1))
                row['profit'] = float(row.get('profit', 0))
                row['total_profit'] = float(row.get('total_profit', 0))
                flips.append(row)
    except FileNotFoundError:
        pass
    except Exception as e:
        print(f"Error reading CSV: {e}")
    
    # Prepare chart data
    chart_labels = [flip['product_name'] for flip in flips]
    chart_profits = [flip['total_profit'] for flip in flips]
    chart_data = json.dumps({'labels': chart_labels, 'profits': chart_profits})
    
    return render_template('history.html', flips=flips, chart_data=chart_data)

@app.route('/calculator')
@login_required
def calculator():
    return render_template('calculator.html')

@app.route('/calculate', methods=['POST'])
@login_required
def calculate():
    if not check_flip_limit(current_user.username):
        flash('Free limit reached (10 flips). Upgrade to continue!', 'error')
        return redirect(url_for('upgrade'))
    csv_path = get_user_csv_path(current_user.username)
    
    product_name = request.form['product_name']
    quantity = int(request.form['quantity'])
    cost = float(request.form['cost'])
    sell = float(request.form['sell'])
    platform = request.form['platform']
    
    fees = {'ebay': 0.129, 'vinted': 0.05, 'depop': 0.10}
    fee = sell * fees[platform]
    profit = sell - cost - fee
    total_profit = profit * quantity
    
    # Save to CSV
    with open(csv_path, 'a', newline='') as f:
        writer = csv.writer(f)
        date = datetime.now().strftime('%Y-%m-%d %H:%M')
        writer.writerow([product_name, quantity, cost, sell, platform, round(profit, 2), round(total_profit, 2), date])
    
    return render_template('results.html', 
                         product_name=product_name,
                         quantity=quantity,
                         cost=cost, 
                         sell=sell,
                         platform=platform, 
                         fee=fee, 
                         profit=profit)

@app.route('/upgrade')
@login_required
def upgrade():
    return render_template('upgrade.html', 
                         stripe_key=STRIPE_PUBLISHABLE_KEY)


@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=current_user.email,
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'gbp',
                    'unit_amount': 500,  # £5.00 in pence
                    'product_data': {
                        'name': 'Pro Plan',
                        'description': 'Unlimited flips + all features',
                    },
                    'recurring': {
                        'interval': 'month',
                    },
                },
                'quantity': 1,
            }],
            mode='subscription',
            success_url=request.host_url + 'success?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'upgrade',
        )
        return {'id': checkout_session.id}
    except Exception as e:
        return str(e), 403

@app.route('/success')
@login_required
def success():
    session_id = request.args.get('session_id')
    
    if session_id:
        session = stripe.checkout.Session.retrieve(session_id)
        customer_id = session.customer
        
        # Update user to Pro
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('UPDATE users SET subscription_status = ?, stripe_customer_id = ? WHERE username = ?',
                 ('pro', customer_id, current_user.username))
        conn.commit()
        conn.close()
        
        flash('Upgrade successful! You now have unlimited flips.', 'success')
    
    return redirect(url_for('dashboard'))


@app.route('/edit/<int:index>')
@login_required
def edit(index):
    csv_path = get_user_csv_path(current_user.username)
    flips = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        flips = list(reader)
    
    if index < len(flips):
        return render_template('edit.html', flip=flips[index], index=index)
    else:
        return redirect(url_for('history'))

@app.route('/update/<int:index>', methods=['POST'])
@login_required
def update(index):
    csv_path = get_user_csv_path(current_user.username)
    
    product_name = request.form['product_name']
    quantity = int(request.form['quantity'])
    cost = float(request.form['cost'])
    sell = float(request.form['sell'])
    platform = request.form['platform']
    
    fees = {'ebay': 0.129, 'vinted': 0.05, 'depop': 0.10}
    fee = sell * fees[platform]
    profit = sell - cost - fee
    total_profit = profit * quantity
    
    # Read all rows
    flips = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        flips = list(reader)
    
    # Update the specific row
    if index < len(flips):
        date = flips[index].get('date', datetime.now().strftime('%Y-%m-%d %H:%M'))
        flips[index] = {
            'product_name': product_name,
            'quantity': quantity,
            'cost': cost,
            'sell': sell,
            'platform': platform,
            'profit': round(profit, 2),
            'total_profit': round(total_profit, 2),
            'date': date
        }
    
    # Write back to CSV
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['product_name', 'quantity', 'cost', 'sell', 'platform', 'profit', 'total_profit', 'date']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flips)
    
    return redirect(url_for('history'))

@app.route('/delete/<int:index>')
@login_required
def delete(index):
    csv_path = get_user_csv_path(current_user.username)
    
    # Read all rows
    flips = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        flips = list(reader)
    
    # Remove the specific row
    if index < len(flips):
        flips.pop(index)
    
    # Write back to CSV
    with open(csv_path, 'w', newline='') as f:
        fieldnames = ['product_name', 'quantity', 'cost', 'sell', 'platform', 'profit', 'total_profit', 'date']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flips)
    
    return redirect(url_for('history'))

@app.route('/export')
@login_required
def export():
    csv_path = get_user_csv_path(current_user.username)
    
    # Read CSV manually
    import openpyxl
    from openpyxl import Workbook
    
    wb = Workbook()
    ws = wb.active
    ws.title = "Flip History"
    
    # Read CSV and write to Excel
    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        for row in reader:
            ws.append(row)
    
    # Create Excel file
    excel_filename = f'flip_history_{current_user.username}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'
    wb.save(excel_filename)
    
    return send_file(excel_filename, 
                    as_attachment=True,
                    download_name=excel_filename,
                    mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

if __name__ == '__main__':
    app.run(debug=True)