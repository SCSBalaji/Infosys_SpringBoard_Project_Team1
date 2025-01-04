import sqlite3

# Path to your SQLite database
DATABASE = 'C:\\Users\\gokul\\OneDrive\\Documents\\hifi_eats\\Infosys-Springboard-Team1\\existing_database.db'


def view_users():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

if __name__ == '__main__':
    users = view_users()
    print("Users table:")
    for user in users:
        print(user)
