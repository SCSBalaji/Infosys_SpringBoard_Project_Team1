import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'existing_database.db')

def add_role_id_column():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Check if the 'role_id' column exists in the 'users' table
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]
    if 'role_id' not in columns:
        # Add the 'role_id' column to the 'users' table
        cursor.execute('ALTER TABLE users ADD COLUMN role_id INTEGER')
        print("Added 'role_id' column to 'users' table.")
    else:
        print("'role_id' column already exists in 'users' table.")

    conn.commit()
    conn.close()

if __name__ == '__main__':
    add_role_id_column()
    print("Database schema updated successfully.")
