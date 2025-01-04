import sqlite3

# Path to your SQLite database
DATABASE = 'C:\\Users\\gokul\\OneDrive\\Documents\\hifi_eats\\Infosys-Springboard-Team1\\existing_database.db'


def delete_all_users():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users")
    conn.commit()
    conn.close()

if __name__ == '__main__':
    delete_all_users()
    print("All users have been deleted from the database.")
