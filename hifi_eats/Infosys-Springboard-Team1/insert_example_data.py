import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'existing_database.db')

def insert_menu_items():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Inserting menu items...")
    menu_items = [
        ('Burger', 'A delicious beef burger', 5.99, 1, 1, 'https://yourwebsite.com/images/burger.jpg'),
        ('Pizza', 'A cheesy pizza with pepperoni', 7.99, 2, 1, 'https://yourwebsite.com/images/pizza.jpg'),
        ('Pasta', 'Creamy Alfredo pasta', 6.99, 3, 1, 'https://yourwebsite.com/images/pasta.jpg'),
        ('Salad', 'Fresh garden salad', 4.99, 4, 1, 'https://yourwebsite.com/images/salad.jpg'),
        ('Taco', 'Spicy chicken taco', 3.99, 5, 1, 'https://yourwebsite.com/images/taco.jpg')
    ]
    cursor.executemany('''
    INSERT OR IGNORE INTO menu_items (name, description, price, category_id, availability_status, image_url)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', menu_items)
    
    conn.commit()
    conn.close()
    print("Menu items inserted successfully.")

def insert_orders():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    print("Inserting orders and order items...")
    orders = [
        (1, 29.95, 'Completed', '123 Main St', '2023-01-15', '2023-01-15 10:00:00'),
        (2, 19.98, 'Completed', '456 Elm St', '2023-02-20', '2023-02-20 12:00:00'),
        (3, 23.97, 'Completed', '789 Maple St', '2023-03-25', '2023-03-25 14:00:00'),
        (4, 17.97, 'Completed', '321 Oak St', '2023-04-30', '2023-04-30 16:00:00'),
        (5, 11.97, 'Completed', '654 Pine St', '2023-05-10', '2023-05-10 18:00:00')
    ]
    cursor.executemany('''
    INSERT INTO orders (customer_id, total_price, order_status, delivery_location, order_date, order_time)
    VALUES (?, ?, ?, ?, ?, ?)
    ''', orders)
    
    order_items = [
        (1, 1, 3, 5.99),  # Order 1, 3 Burgers
        (1, 2, 1, 7.99),  # Order 1, 1 Pizza
        (2, 3, 2, 6.99),  # Order 2, 2 Pasta
        (2, 4, 1, 4.99),  # Order 2, 1 Salad
        (3, 5, 3, 3.99),  # Order 3, 3 Tacos
        (3, 1, 1, 5.99),  # Order 3, 1 Burger
        (4, 2, 2, 7.99),  # Order 4, 2 Pizzas
        (4, 3, 1, 6.99),  # Order 4, 1 Pasta
        (5, 4, 3, 4.99),  # Order 5, 3 Salads
        (5, 5, 1, 3.99)   # Order 5, 1 Taco
    ]
    cursor.executemany('''
    INSERT INTO order_items (order_id, item_id, quantity, price)
    VALUES (?, ?, ?, ?)
    ''', order_items)
    
    conn.commit()
    conn.close()
    print("Orders and order items inserted successfully.")

if __name__ == '__main__':
    insert_menu_items()
    insert_orders()
