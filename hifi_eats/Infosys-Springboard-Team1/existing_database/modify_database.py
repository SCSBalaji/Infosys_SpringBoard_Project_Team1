import sqlite3

# Path to your SQLite database
DATABASE = 'C:\\Users\\gokul\\OneDrive\\Documents\\hifi_eats\\Infosys-Springboard-Team1\\existing_database\\create_tables.py'

def add_column():
    print("Connecting to database...")
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Adding is_delivery_boy column to Users table...")
    try:
        # Add is_delivery_boy column
        cursor.execute('''
        ALTER TABLE users ADD COLUMN is_delivery_boy INTEGER DEFAULT 0
        ''')
        conn.commit()
        print("Column added successfully.")
    except sqlite3.OperationalError as e:
        print(f"An error occurred: {e}")

    conn.close()

if __name__ == '__main__':
    add_column()
