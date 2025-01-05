import sqlite3
import random
import jwt
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from dotenv import load_dotenv
import os
import string
import bcrypt
import secrets
import matplotlib.pyplot as plt 
import io 
import seaborn as sns
import base64
import pandas as pd
import matplotlib.dates as mdates
from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import tempfile
load_dotenv()  # Load environment variables from .env file

app = Flask(__name__)
app.secret_key = 'supersecretkey'
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'existing_database.db')
JWT_SECRET = 'your_jwt_secret'  # Add a secret key for JWT

# Configuring Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')

mail = Mail(app)
s = URLSafeTimedSerializer(app.secret_key)

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

EMAIL_ADDRESS = "hifieats21@gmail.com"  # Replace with your Gmail address
EMAIL_PASSWORD = "morz awdj fqgb srcv"  # Replace with your Gmail password

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'hifieats21@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'morz awdj fqgb srcv'  # Replace with your email password
app.config['MAIL_DEFAULT_SENDER'] = 'hifieats21@gmail.com'  # Replace with your email

mail = Mail(app)
# Configuring OAuth


# Configuring OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='131047593159-l1ud0f5hs3e3pq39k6ko5kchka7pd07d.apps.googleusercontent.com',  # Your Google client ID
    client_secret='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',  # Your Google client secret
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'token_endpoint_auth_method': 'client_secret_basic'
    }
)


facebook = oauth.register(
    name='facebook',
    client_id=os.environ.get('FACEBOOK_CLIENT_ID'),  # Your Facebook client ID
    client_secret=os.environ.get('FACEBOOK_CLIENT_SECRET'),  # Your Facebook client secret
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://127.0.0.1:5000/facebook/callback',  # Your redirect URI
    client_kwargs={ 'scope': 'openid email profile', 'token_endpoint_auth_method': 'client_secret_basic', 'userinfo_endpoint': 'https://openidconnect.googleapis.com/v1/userinfo', 'jwks_uri': 'https://www.googleapis.com/oauth2/v3/certs'}

)

twitter = oauth.register(
    name='twitter',
    client_id=os.environ.get('TWITTER_CLIENT_ID'),  # Your Twitter client ID
    client_secret=os.environ.get('TWITTER_CLIENT_SECRET'),  # Your Twitter client secret
    request_token_url='https://api.twitter.com/oauth/request_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
    access_token_url='https://api.twitter.com/oauth/access_token',
    access_token_params=None,
    redirect_uri='http://localhost:5000/twitter/callback',  # Your redirect URI
    client_kwargs={'scope': 'email'}
)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def create_token(email):
    payload = {
        'email': email,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=1)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload['email']
    except jwt.ExpiredSignatureError:
        return None

# Function to generate a random OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

# Function to send OTP email
def send_otp_email(recipient, otp):
    msg = Message('Your OTP Code', recipients=[recipient])
    msg.body = f'Your OTP code is {otp}'
    msg.sender = app.config['MAIL_DEFAULT_SENDER']  # Ensure sender is specified
    mail.send(msg)

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        contact_info = request.form['contact_info']
        
        # Generate OTP and store it in the session
        otp = generate_otp()
        session['otp'] = otp
        session['contact_info'] = contact_info
        
        # Send OTP to user's email
        send_otp_email(contact_info, otp)
        
        flash('OTP sent to your registered contact.', 'success')
        return redirect(url_for('verify_otp'))
    
    return render_template('forgot.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        verification_code = request.form['verification_code']
        
        # Retrieve the OTP from the session
        stored_otp = session.get('otp')
        
        if verification_code == stored_otp:
            flash('Verification successful!', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Invalid verification code. Please try again.', 'error')
            return redirect(url_for('verify_otp'))
    
    return render_template('verify_otp.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not email or not new_password or not confirm_password:
            flash('All fields are required!', 'error')
            return redirect(url_for('reset_password'))

        if new_password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('reset_password'))

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()

        if user:
            hashed_password = hash_password(new_password)
            cursor.execute('UPDATE users SET password_hash = ? WHERE email = ?', (hashed_password, email))
            conn.commit()
            conn.close()
            flash('Password reset successful. Please sign in.', 'success')
            return redirect(url_for('signin'))
        else:
            conn.close()
            flash('Email not found!', 'error')
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html')


def verify_password(plain_password, hashed_password):
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm-password']
        full_name = request.form['full-name']
        phone_number = request.form['phone-number']

        if password != confirm_password:
            flash('Passwords do not match!', 'error')
            return redirect(url_for('signup'))
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        existing_user = cursor.fetchone()
        
        if existing_user:
            flash('Email already exists!', 'error')
            return redirect(url_for('signup'))
        
        hashed_password = hash_password(password)
        cursor.execute('INSERT INTO users (email, password_hash, full_name, phone_number, is_active) VALUES (?, ?, ?, ?, ?)',
                       (email, hashed_password, full_name, phone_number, 0))  # Initially inactive
        conn.commit()

        # Send confirmation email
        token = s.dumps(email, salt='email-confirm')
        msg = Message('Confirm your email', sender=os.environ.get('EMAIL_USER'), recipients=[email])
        link = url_for('confirm_email', token=token, _external=True)
        msg.body = f"Hello, welcome to HiFi Eats! Please confirm your email by clicking the link below:\n\n{link}"
        mail.send(msg)
        
        flash('Registration successful! A confirmation email has been sent to your email address.', 'success')
        return redirect(url_for('signin'))
    
    return render_template('signup.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['phone-email']
        password = request.form['password']
        
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        
        if user and verify_password(password, user['password_hash']):
            session['user_id'] = user['user_id']
            session['user'] = user['email']  # Set the user email in session
            session['is_admin'] = user['is_admin']

            conn.close()
            flash('Sign in successful', 'success')
            return redirect(url_for('dashboard'))  # Redirect to the dashboard route
        else:
            conn.close()
            flash('Invalid credentials', 'error')
            return redirect(url_for('signin'))
    return render_template('signin.html')

@app.route('/assign_role/<int:user_id>', methods=['GET', 'POST'])
def assign_role(user_id):
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        role_id = request.form['role']
        
        # Assign role to user
        cursor.execute('UPDATE users SET role_id = ? WHERE user_id = ?', (role_id, user_id))
        conn.commit()
        conn.close()

        flash('Role assigned successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    
    else:
        # Retrieve user and role details to populate the form
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        
        cursor.execute('SELECT * FROM roles')
        roles = cursor.fetchall()
        conn.close()

        return render_template('assign_role.html', user=user, roles=roles)

@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if request.method == 'POST':
        # Process the form data and update the user
        email = request.form['email']
        full_name = request.form['full_name']
        phone_number = request.form['phone_number']
        is_active = request.form.get('is_active', False)

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET email = ?, full_name = ?, phone_number = ?, is_active = ? WHERE user_id = ?',
                       (email, full_name, phone_number, is_active, user_id))
        conn.commit()
        conn.close()

        flash('User updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        # Retrieve user details to populate the form
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()

        return render_template('edit_user.html', user=user)

@app.route('/assign_role_page', methods=['GET', 'POST'])
def assign_role_page():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    
    cursor.execute('SELECT * FROM roles')
    roles = cursor.fetchall()
    
    conn.close()
    
    return render_template('assign_role_page.html', users=users, roles=roles)
@app.route('/user_list')
def user_list():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()

    return render_template('user_list.html', users=users)
def fetch_top_selling_items_by_month(month):
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
    SELECT m.name, SUM(oi.quantity) AS total_quantity_sold
    FROM order_items oi
    JOIN menu_items m ON oi.item_id = m.menu_item_id
    JOIN orders o ON oi.order_id = o.order_id
    WHERE strftime('%Y-%m', o.order_date) = ?
    GROUP BY m.name
    ORDER BY total_quantity_sold DESC
    '''
    cursor.execute(query, (month,))
    data = cursor.fetchall()
    conn.close()
    
    return data

def get_most_sold_item(data):
    df = pd.DataFrame(data, columns=['name', 'total_quantity_sold'])
    most_sold_item = df.loc[df['total_quantity_sold'].idxmax()]
    return most_sold_item

import matplotlib.pyplot as plt

def generate_top_selling_items_pie_chart(month):
    data = fetch_top_selling_items_by_month(month)
    
    if not data:
        return None  # Handle case when there is no data for the selected month

    df = pd.DataFrame(data, columns=['name', 'total_quantity_sold'])
    most_sold_item = df.loc[df['total_quantity_sold'].idxmax()]
    explode = [0.1 if name == most_sold_item['name'] else 0 for name in df['name']]
    plt.figure(figsize=(10, 8))
    plt.pie(df['total_quantity_sold'], labels=df['name'], labeldistance=0.8, explode=explode, autopct='%1.1f%%', startangle=140, colors=sns.color_palette('viridis', len(df)))
    plt.title(f'Top Selling Items for {month}')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

@app.route('/top_selling_items', methods=['GET', 'POST'])
def top_selling_items():
    if request.method == 'POST':
        month = request.form.get('month')
        img_buffer = generate_top_selling_items_pie_chart(month)
        plot_url = base64.b64encode(img_buffer.getvalue()).decode() if img_buffer else None
        return render_template('top_selling_items.html', plot_url=plot_url, selected_month=month)
    
    return render_template('top_selling_items.html', plot_url=None, selected_month=None)


@app.route('/sales_trends', methods=['GET'])
def sales_trends():
    period = request.args.get('period', 'monthly')
    chart_type = request.args.get('chart_type', 'line')
    
    plot_url, _ = generate_sales_trend_chart_with_peaks(period, chart_type)
    print(plot_url)  # Check if this is a valid base64 string
    
    return render_template(
        'sales_trends.html',
        plot_url=plot_url,
        period=period,
        chart_type=chart_type
    )

from flask import send_file
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
import os
import tempfile

def send_email_with_attachment(recipient_email, attachment_path):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = recipient_email
    msg['Subject'] = "Sales Report"

    # Attach PDF file
    part = MIMEBase('application', 'octet-stream')
    with open(attachment_path, 'rb') as attachment:
        part.set_payload(attachment.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f'attachment; filename="sales_report.pdf"')
    msg.attach(part)

    # Send email
    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)

@app.route('/download_sales_report')
def download_sales_report():
    buffer = io.BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter
    
    # Fetch sales data
    period = request.args.get('period', 'monthly')  # Get the period from query params (daily, weekly, monthly)
    chart_type = request.args.get('chart_type', 'line')  # Get the chart type from query params (line, bar)
    sales_data = fetch_sales_data(period)
    df = pd.DataFrame(sales_data, columns=['period', 'total_sales'])
    
    # Add title and sales data table to the PDF
    p.setFont("Helvetica", 14)
    p.drawString(30, height - 40, f"Sales Report ({period.capitalize()})")
    
    p.setFont("Helvetica", 10)
    x, y = 30, height - 60
    for index, row in df.iterrows():
        p.drawString(x, y, f"{row['period']}: {row['total_sales']}")
        y -= 12

    # Generate the chart and save as a temporary file
    plot_url, img_buffer = generate_sales_trend_chart_with_peaks(period, chart_type)
    temp_file_path = tempfile.NamedTemporaryFile(delete=False, suffix=".png").name
    with open(temp_file_path, 'wb') as f:
        f.write(img_buffer.getvalue())
    
    # Add the chart image to the PDF
    p.drawImage(temp_file_path, x, y - 200, width - 2 * x, 200)
    
    p.showPage()
    p.save()
    
    # Save the buffer content to a temporary PDF file
    pdf_temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    with open(pdf_temp_file.name, 'wb') as f:
        f.write(buffer.getvalue())
    
    # Send email with PDF attachment
    recipient_email = "recipient_email@gmail.com"  # Replace with recipient email address
    send_email_with_attachment(recipient_email, pdf_temp_file.name)
    
    # Clean up the temporary files
    buffer.seek(0)
    os.remove(temp_file_path)
    os.remove(pdf_temp_file.name)
    
    return send_file(buffer, as_attachment=True, download_name="sales_report.pdf", mimetype='application/pdf')

def highlight_peaks(df, ax):
    peak_threshold = df['total_sales'].mean() + df['total_sales'].std()  # Example threshold
    peaks = df[df['total_sales'] > peak_threshold]
    
    for idx, row in peaks.iterrows():
        ax.annotate('Peak', xy=(row['period'], row['total_sales']), xytext=(row['period'], row['total_sales'] + 5),
                    arrowprops=dict(facecolor='red', shrink=0.05),
                    horizontalalignment='center', verticalalignment='bottom')
def generate_sales_trend_chart_with_peaks(period='monthly', chart_type='line'):
    data = fetch_sales_data(period)
    
    df = pd.DataFrame(data, columns=['period', 'total_sales'])
    
    # Convert period to datetime
    try:
        if period == 'daily':
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m-%d')
        elif period == 'weekly':
            df['period'] = pd.to_datetime(df['period'] + '-1', format='%Y-%W-%w')  # Monday as start of the week
        else:  # monthly
            df['period'] = pd.to_datetime(df['period'], format='%Y-%m')
    except ValueError as e:
        print(f"Error parsing dates: {e}")
        return None  # Handle the error gracefully
    
    plt.figure(figsize=(10, 6))
    
    if chart_type == 'bar':
        ax = df.plot(x='period', y='total_sales', kind='bar', color='skyblue')
    else:  # line chart
        ax = df.plot(x='period', y='total_sales', marker='o', linestyle='-', color='skyblue')
    
    highlight_peaks(df, ax)
    
    plt.xlabel('Period')
    plt.ylabel('Total Sales')
    plt.title(f'Sales Trends ({period.capitalize()})')
    plt.xticks(rotation=45)
    
    # Set date format on x-axis
    if period == 'daily':
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m-%d'))
    elif period == 'weekly':
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%W'))
    else:  # monthly
        ax.xaxis.set_major_formatter(mdates.DateFormatter('%Y-%m'))
    
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    plot_url = base64.b64encode(img_buffer.getvalue()).decode()
    
    return plot_url, img_buffer


def generate_sales_trend_chart(period='monthly', chart_type='line'):
    data = fetch_sales_data(period)
    
    df = pd.DataFrame(data, columns=['period', 'total_sales'])
    
    plt.figure(figsize=(10, 6))
    if chart_type == 'bar':
        plt.bar(df['period'], df['total_sales'], color='skyblue')
    else:  # Default to line chart
        plt.plot(df['period'], df['total_sales'], marker='o', linestyle='-', color='skyblue')
    
    plt.xlabel('Period')
    plt.ylabel('Total Sales')
    plt.title(f'Sales Trends ({period.capitalize()})')
    plt.xticks(rotation=45)
    plt.tight_layout()
    
    img = io.BytesIO()
    plt.savefig(img, format='png')
    img.seek(0)
    plot_url = base64.b64encode(img.getvalue()).decode()
    
    return plot_url

def fetch_sales_data(period='monthly'):
    conn = get_db()
    cursor = conn.cursor()
    
    if period == 'daily':
        query = '''
        SELECT strftime('%Y-%m-%d', o.order_date) as period, SUM(o.total_price) as total_sales
        FROM orders o
        GROUP BY period
        ORDER BY period;
        '''
    elif period == 'weekly':
        query = '''
        SELECT strftime('%Y-%W', o.order_date) as period, SUM(o.total_price) as total_sales
        FROM orders o
        GROUP BY period
        ORDER BY period;
        '''
    else:  # Default to monthly
        query = '''
        SELECT strftime('%Y-%m', o.order_date) as period, SUM(o.total_price) as total_sales
        FROM orders o
        GROUP BY period
        ORDER BY period;
        '''
    
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    
    return data

@app.route('/admin/dashboard')
def admin_dashboard():
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT users.user_id, users.email, users.full_name, users.phone_number, roles.role_name
        FROM users
        LEFT JOIN roles ON users.role_id = roles.role_id
    ''')
    users = cursor.fetchall()
    conn.close()

    return render_template('admin_dashboard.html', users=users)

def is_admin():
    user_email = session.get('user')
    if not user_email:
        print("No user in session")
        return False
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT is_admin FROM users WHERE email = ?', (user_email,))
    user = cursor.fetchone()
    conn.close()
    if user:
        print(f"User {user_email} is {'an admin' if user['is_admin'] == 1 else 'not an admin'}")
    return user and user['is_admin'] == 1

@app.route('/')
def index():
    return render_template('index.html')



@app.route('/admin/deactivate_user/<int:user_id>')
def deactivate_user(user_id):
    if not is_admin():
        flash('Access denied. Admins only.', 'error')
        print("hello")
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_active = 0 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()
    flash('User deactivated successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

# Google login route
@app.route('/google_login')
def google_login():
    nonce = secrets.token_urlsafe()
    session['nonce'] = nonce
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)

@app.route('/google/callback')
def google_auth():
    token = oauth.google.authorize_access_token()
    nonce = session.pop('nonce', None)
    user_info = oauth.google.parse_id_token(token, nonce=nonce)

    email = user_info['email']
    full_name = user_info.get('name', 'Google User')

    # Check if user already exists in the database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        session['user_id'] = user['user_id']
    else:
        # User doesn't exist, create a new account
        cursor.execute('INSERT INTO users (email, full_name, is_active) VALUES (?, ?, ?)', (email, full_name, 1))
        conn.commit()
        user_id = cursor.lastrowid
        session['user_id'] = user_id

    conn.close()
    flash('You have successfully logged in with Google.', 'success')
    return redirect(url_for('dashboard'))

# Facebook login route
@app.route('/facebook_login')
def facebook_login():
    redirect_uri = url_for('facebook_auth', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)

@app.route('/facebook/callback')
def facebook_auth():
    token = oauth.facebook.authorize_access_token()
    user_info = oauth.facebook.get('me?fields=id,name,email').json()

    email = user_info['email']
    full_name = user_info.get('name', 'Facebook User')

    # Check if user already exists in the database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        session['user_id'] = user['user_id']
    else:
        # User doesn't exist, create a new account
        cursor.execute('INSERT INTO users (email, full_name, is_active) VALUES (?, ?, ?)', (email, full_name, 1))
        conn.commit()
        user_id = cursor.lastrowid
        session['user_id'] = user_id

    conn.close()
    flash('You have successfully logged in with Facebook.', 'success')
    return redirect(url_for('dashboard'))

# Twitter login route
@app.route('/twitter_login')
def twitter_login():
    redirect_uri = url_for('twitter_auth', _external=True)
    return oauth.twitter.authorize_redirect(redirect_uri)

@app.route('/twitter/callback')
def twitter_auth():
    token = oauth.twitter.authorize_access_token()
    user_info = oauth.twitter.get('account/verify_credentials.json').json()

    email = user_info.get('email', f"{user_info['screen_name']}@twitter.com")
    full_name = user_info.get('name', 'Twitter User')

    # Check if user already exists in the database
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    user = cursor.fetchone()

    if user:
        # User exists, log them in
        session['user_id'] = user['user_id']
    else:
        # User doesn't exist, create a new account
        cursor.execute('INSERT INTO users (email, full_name, is_active) VALUES (?, ?, ?)', (email, full_name, 1))
        conn.commit()
        user_id = cursor.lastrowid
        session['user_id'] = user_id

    conn.close()
    flash('You have successfully logged in with Twitter.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        # Update user status to confirmed in the database
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('UPDATE users SET is_active = 1 WHERE email = ?', (email,))
        conn.commit()
        conn.close()
    except SignatureExpired:
        flash('The confirmation link has expired.')
        return redirect(url_for('signup'))

    flash('Email confirmed successfully! You can now log in.')
    return redirect(url_for('signin'))

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        user_email = session['user']
        if session.get('is_admin'):
            print("Admin user detected, redirecting to admin dashboard")
            return redirect(url_for('admin_dashboard'))
        print("Regular user detected, rendering user dashboard")
        return render_template('dashboard.html', user_email=user_email)
    else:
        flash('You need to log in first.', 'error')
        return redirect(url_for('signin'))
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if not session.get('is_admin'):
        flash('Access denied. Admins only.', 'error')
        return redirect(url_for('index'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE user_id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))

def fetch_delivery_data_for_agent(agent_id):
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
    SELECT delivery_id, order_id, agent_id, status, pickup_time, delivery_time
    FROM deliveries
    WHERE agent_id = ?
    '''
    cursor.execute(query, (agent_id,))
    data = cursor.fetchall()
    conn.close()
    
    return data

import matplotlib.pyplot as plt
import io
import base64

def generate_average_delivery_time_chart(average_delivery_time):
    fig, ax = plt.subplots(figsize=(6, 3))
    ax.barh(['Average Delivery Time'], [average_delivery_time], color='skyblue')
    ax.set_xlim(0, max(60, average_delivery_time * 1.2))  # Ensure some padding on the right
    ax.set_xlabel('Time (minutes)')
    plt.title('Average Delivery Time')
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer
def generate_on_time_delivery_rate_chart(on_time_rate):
    labels = ['On-Time', 'Late']
    sizes = [on_time_rate, 1 - on_time_rate]
    colors = ['lightgreen', 'lightcoral']
    explode = (0.1, 0)  # explode the On-Time slice
    
    fig, ax = plt.subplots(figsize=(6, 6))
    ax.pie(sizes, explode=explode, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
    plt.title('On-Time Delivery Rate')
    plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle.
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png')
    img_buffer.seek(0)
    
    return img_buffer

def calculate_on_time_delivery_rate(data, on_time_threshold=30):
    df = pd.DataFrame(data, columns=['delivery_id', 'order_id', 'agent_id', 'status', 'pickup_time', 'delivery_time'])
    df['pickup_time'] = pd.to_datetime(df['pickup_time'])
    df['delivery_time'] = pd.to_datetime(df['delivery_time'])
    
    df['delivery_duration'] = (df['delivery_time'] - df['pickup_time']).dt.total_seconds() / 60  # Convert to minutes
    
    if len(df) == 0:
        return 0  # No deliveries, so on-time rate is 0
    
    on_time_deliveries = df[df['delivery_duration'] <= on_time_threshold]
    on_time_rate = len(on_time_deliveries) / len(df)
    
    return on_time_rate

def calculate_average_delivery_time(data):
    df = pd.DataFrame(data, columns=['delivery_id', 'order_id', 'agent_id', 'status', 'pickup_time', 'delivery_time'])
    df['pickup_time'] = pd.to_datetime(df['pickup_time'])
    df['delivery_time'] = pd.to_datetime(df['delivery_time'])
    
    df['delivery_duration'] = (df['delivery_time'] - df['pickup_time']).dt.total_seconds() / 60  # Convert to minutes
    
    if len(df) == 0:
        return 0  # No deliveries, so average delivery time is 0
    
    average_delivery_time = df['delivery_duration'].mean()
    
    return average_delivery_time

@app.route('/delivery_metrics', methods=['GET', 'POST'])
def delivery_metrics():
    if request.method == 'POST':
        agent_id = request.form.get('agent_id')
        data = fetch_delivery_data_for_agent(agent_id)
        average_delivery_time = calculate_average_delivery_time(data)
        on_time_rate = calculate_on_time_delivery_rate(data)
        
        if data:
            avg_time_img_buffer = generate_average_delivery_time_chart(average_delivery_time)
            on_time_rate_img_buffer = generate_on_time_delivery_rate_chart(on_time_rate)
            
            avg_time_plot_url = base64.b64encode(avg_time_img_buffer.getvalue()).decode()
            on_time_rate_plot_url = base64.b64encode(on_time_rate_img_buffer.getvalue()).decode()
        else:
            avg_time_plot_url = None
            on_time_rate_plot_url = None
        
        return render_template('delivery_metrics.html', 
                               avg_time_plot_url=avg_time_plot_url, 
                               on_time_rate_plot_url=on_time_rate_plot_url, 
                               agent_id=agent_id)
    
    return render_template('Restaurant_dashboard.html', 
                           avg_time_plot_url=None, 
                           on_time_rate_plot_url=None, 
                           agent_id=None)

def update_delivery_status(delivery_id, status, delivery_time=None):
    conn = get_db()
    cursor = conn.cursor()
    
    if delivery_time:
        query = '''
        UPDATE deliveries
        SET status = ?, delivery_time = ?
        WHERE delivery_id = ?
        '''
        cursor.execute(query, (status, delivery_time, delivery_id))
    else:
        query = '''
        UPDATE deliveries
        SET status = ?
        WHERE delivery_id = ?
        '''
        cursor.execute(query, (status, delivery_id))
    
    conn.commit()
    conn.close()

def add_delivery(order_id, agent_id, status, pickup_time, delivery_time):
    conn = get_db()
    cursor = conn.cursor()
    
    query = '''
    INSERT INTO deliveries (order_id, agent_id, status, pickup_time, delivery_time)
    VALUES (?, ?, ?, ?, ?)
    '''
    cursor.execute(query, (order_id, agent_id, status, pickup_time, delivery_time))
    conn.commit()
    conn.close()

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.')
    return redirect(url_for('signin'))

if __name__ == '__main__':
    app.run(debug=True)
