"""
Database Initialization Script
Creates necessary tables and populates with sample data
"""

import sqlite3
import hashlib
import os
from datetime import datetime


def create_logs_directory():
    """Create logs directory if it doesn't exist"""
    if not os.path.exists('logs'):
        os.makedirs('logs')
        print("✓ Created logs directory")


def init_database():
    """Initialize the database with tables and sample data"""
    
    print("\n" + "="*60)
    print("SQL Injection Detection - Database Initialization")
    print("="*60 + "\n")
    
    # Remove old database if exists
    if os.path.exists('app.db'):
        os.remove('app.db')
        print("✓ Removed old database")
    
    # Create new database
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    print("✓ Created new database: app.db")
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    print("✓ Created 'users' table")
    
    # Create products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            stock INTEGER DEFAULT 0,
            category TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    print("✓ Created 'products' table")
    
    # Create audit log table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            user_id INTEGER,
            ip_address TEXT,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    print("✓ Created 'audit_log' table")
    
    # Insert sample users
    print("\nInserting sample users...")
    sample_users = [
        ('admin', 'admin123', 'admin@sqlshield.com', 'admin'),
        ('john_doe', 'password123', 'john@example.com', 'user'),
        ('jane_smith', 'secure456', 'jane@example.com', 'user'),
        ('bob_wilson', 'test789', 'bob@example.com', 'user'),
        ('alice_brown', 'pass321', 'alice@example.com', 'moderator'),
    ]
    
    for username, password, email, role in sample_users:
        # Hash password with SHA256 (for demo purposes)
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            cursor.execute(
                'INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)',
                (username, hashed_password, email, role)
            )
            print(f"  → Added user: {username} (password: {password})")
        except sqlite3.IntegrityError:
            print(f"  ✗ User {username} already exists")
    
    # Insert sample products
    print("\nInserting sample products...")
    sample_products = [
        ('Laptop Pro', 'High-performance laptop with 16GB RAM', 999.99, 10, 'Electronics'),
        ('Wireless Mouse', 'Ergonomic wireless mouse', 29.99, 50, 'Accessories'),
        ('Mechanical Keyboard', 'RGB mechanical keyboard', 79.99, 30, 'Accessories'),
        ('4K Monitor', '27-inch 4K IPS monitor', 399.99, 15, 'Electronics'),
        ('USB-C Hub', '7-in-1 USB-C hub adapter', 49.99, 40, 'Accessories'),
        ('Webcam HD', '1080p HD webcam with microphone', 69.99, 25, 'Electronics'),
        ('Desk Lamp', 'LED desk lamp with dimmer', 34.99, 35, 'Office'),
        ('Office Chair', 'Ergonomic office chair', 249.99, 12, 'Furniture'),
        ('Standing Desk', 'Adjustable standing desk', 499.99, 8, 'Furniture'),
        ('Headphones', 'Noise-cancelling headphones', 149.99, 20, 'Electronics'),
    ]
    
    for name, description, price, stock, category in sample_products:
        try:
            cursor.execute(
                'INSERT INTO products (name, description, price, stock, category) VALUES (?, ?, ?, ?, ?)',
                (name, description, price, stock, category)
            )
            print(f"  → Added product: {name}")
        except sqlite3.IntegrityError:
            print(f"  ✗ Product {name} already exists")
    
    # Commit changes
    conn.commit()
    conn.close()
    
    print("\n" + "="*60)
    print("Database initialization completed successfully!")
    print("="*60 + "\n")
    
    # Display summary
    print("Summary:")
    print(f"  • Users: {len(sample_users)}")
    print(f"  • Products: {len(sample_products)}")
    print(f"  • Tables: users, products, audit_log")
    
    print("\nTest Credentials:")
    print("  Username: admin")
    print("  Password: admin123")
    
    print("\nDatabase ready for use!")
    print("Run 'python app.py' to start the application\n")


def display_database_contents():
    """Display current database contents"""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    print("\n" + "="*60)
    print("Current Database Contents")
    print("="*60 + "\n")
    
    # Users
    cursor.execute("SELECT id, username, email, role FROM users")
    users = cursor.fetchall()
    print("USERS:")
    print(f"{'ID':<5} {'Username':<15} {'Email':<25} {'Role':<10}")
    print("-" * 60)
    for user in users:
        print(f"{user[0]:<5} {user[1]:<15} {user[2]:<25} {user[3]:<10}")
    
    print("\n")
    
    # Products
    cursor.execute("SELECT id, name, price, stock, category FROM products")
    products = cursor.fetchall()
    print("PRODUCTS:")
    print(f"{'ID':<5} {'Name':<25} {'Price':<10} {'Stock':<8} {'Category':<15}")
    print("-" * 70)
    for product in products:
        print(f"{product[0]:<5} {product[1]:<25} ${product[2]:<9.2f} {product[3]:<8} {product[4]:<15}")
    
    conn.close()
    print("\n")


if __name__ == '__main__':
    # Create necessary directories
    create_logs_directory()
    
    # Initialize database
    init_database()
    
    # Display contents
    display_database_contents()
    
    print("Setup complete! You can now run the application.")
    print("Command: python app.py\n")
