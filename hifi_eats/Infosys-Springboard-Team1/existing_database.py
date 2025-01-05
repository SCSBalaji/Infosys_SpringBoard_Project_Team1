import sqlite3
import bcrypt
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'existing_database.db')

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_tables():
    print("Connecting to database...")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Creating Users table...")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        full_name TEXT,
        phone_number TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        is_admin INTEGER DEFAULT 0,
        is_delivery_boy INTEGER DEFAULT 0,
        role_id INTEGER,
        FOREIGN KEY(role_id) REFERENCES roles(role_id)
    )
    ''')

    print("Creating Roles table...")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS roles (
        role_id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name TEXT NOT NULL UNIQUE,
        role_description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')

    print("Creating EmailVerifications table...")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS email_verifications (
        verification_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        verification_token TEXT,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        verified_at TIMESTAMP,
        status TEXT CHECK(status IN ('Pending', 'Verified')) DEFAULT 'Pending',
        FOREIGN KEY(user_id) REFERENCES users(user_id)
    )
    ''')

    print("Creating Menu Items table...")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS menu_items (
        menu_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT,
        price DECIMAL(10,2) NOT NULL,
        category_id INTEGER,
        availability_status BOOLEAN DEFAULT 1,
        image_url TEXT,
        created_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        modified_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(category_id) REFERENCES categories(category_id)
    )
    ''')

    print("Creating Orders table...")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        order_id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER,
        total_price DECIMAL(10,2) NOT NULL,
        order_status VARCHAR(50) NOT NULL,
        delivery_location VARCHAR(255) NOT NULL,
        order_date DATE DEFAULT CURRENT_TIMESTAMP,
        order_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY(customer_id) REFERENCES users(user_id)
    )
    ''')

    print("Creating Order Items table...")
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS order_items (
        order_item_id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER,
        item_id INTEGER,
        quantity INTEGER NOT NULL,
        price DECIMAL(10,2) NOT NULL,
        FOREIGN KEY(order_id) REFERENCES orders(order_id),
        FOREIGN KEY(item_id) REFERENCES menu_items(menu_item_id)
    )
    ''')

    conn.commit()
    conn.close()
    print("Tables created successfully.")

def insert_initial_data():
    print("Inserting initial data...")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Inserting roles...")
    roles = [
        ('admin', 'Administrator role'),
        ('delivery_boy', 'Delivery Boy role'),
        ('user', 'Regular user role')
    ]
    cursor.executemany('INSERT OR IGNORE INTO roles (role_name, role_description) VALUES (?, ?)', roles)

    print("Inserting admin user...")
    password_hash = hash_password('admin_password')
    admin_user = ('admin@example.com', password_hash, 'Admin User', '1234567890', 1, 1, 0, None)  # Setting role_id to None initially
    cursor.execute('INSERT OR IGNORE INTO users (email, password_hash, full_name, phone_number, is_active, is_admin, is_delivery_boy, role_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', admin_user)

    conn.commit()
    conn.close()
    print("Initial data inserted successfully.")

if __name__ == '__main__':
    create_tables()
    insert_initial_data()
