import sqlite3

# Path to your SQLite database
DATABASE = 'C:\\Users\\gokul\\OneDrive\\Documents\\hifi_eats\\Infosys-Springboard-Team1\\existing_database.db'

def list_tables():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    conn.close()
    return tables

def get_table_schema(table_name):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute(f"PRAGMA table_info({table_name});")
    schema = cursor.fetchall()
    conn.close()
    return schema

if __name__ == '__main__':
    tables = list_tables()
    print("Tables in the database:")
    for table in tables:
        print(f"- {table[0]}")
        schema = get_table_schema(table[0])
        print(f"Schema of {table[0]}:")
        for column in schema:
            print(column)
        print()
