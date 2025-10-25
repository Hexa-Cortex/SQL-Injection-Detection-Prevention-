"""
SQL Injection Detection & Prevention - Main Application
Demonstrates vulnerable vs secure implementations
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import sqlite3
import hashlib
import secrets
from datetime import datetime
from detector import SQLInjectionDetector

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Initialize detector
detector = SQLInjectionDetector()

# Database setup
def init_db():
    """Initialize the database with sample data"""
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
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
    
    # Create products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL,
            stock INTEGER DEFAULT 0
        )
    ''')
    
    # Insert sample users (passwords are hashed with SHA256 for demo)
    sample_users = [
        ('admin', hashlib.sha256('admin123'.encode()).hexdigest(), 'admin@example.com', 'admin'),
        ('john_doe', hashlib.sha256('password123'.encode()).hexdigest(), 'john@example.com', 'user'),
        ('jane_smith', hashlib.sha256('secure456'.encode()).hexdigest(), 'jane@example.com', 'user'),
    ]
    
    for user in sample_users:
        try:
            cursor.execute('INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)', user)
        except sqlite3.IntegrityError:
            pass  # User already exists
    
    # Insert sample products
    sample_products = [
        ('Laptop', 'High-performance laptop', 999.99, 10),
        ('Mouse', 'Wireless mouse', 29.99, 50),
        ('Keyboard', 'Mechanical keyboard', 79.99, 30),
        ('Monitor', '27-inch 4K monitor', 399.99, 15),
    ]
    
    for product in sample_products:
        try:
            cursor.execute('INSERT INTO products (name, description, price, stock) VALUES (?, ?, ?, ?)', product)
        except sqlite3.IntegrityError:
            pass
    
    conn.commit()
    conn.close()


# ============================================================================
# VULNERABLE ENDPOINTS (For educational purposes only!)
# ============================================================================

@app.route('/vulnerable/login', methods=['GET', 'POST'])
def vulnerable_login():
    """VULNERABLE: Demonstrates SQL injection vulnerability"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # VULNERABLE CODE - DO NOT USE IN PRODUCTION
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        # String concatenation makes this vulnerable to SQL injection
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{hashlib.sha256(password.encode()).hexdigest()}'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
            
            if user:
                return jsonify({
                    'success': True,
                    'message': 'Login successful!',
                    'user': {'username': user[1], 'role': user[4]},
                    'vulnerability': 'SQL Injection Present'
                })
            else:
                return jsonify({
                    'success': False,
                    'message': 'Invalid credentials',
                    'executed_query': query
                })
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'Database error: {str(e)}',
                'executed_query': query
            })
    
    return render_template('vulnerable.html')


@app.route('/vulnerable/search', methods=['GET'])
def vulnerable_search():
    """VULNERABLE: Search products with SQL injection vulnerability"""
    product_id = request.args.get('id', '')
    
    # Detection check
    is_malicious, details = detector.detect(product_id)
    
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    # VULNERABLE CODE
    query = f"SELECT * FROM products WHERE id={product_id}"
    
    try:
        cursor.execute(query)
        products = cursor.fetchall()
        conn.close()
        
        return jsonify({
            'success': True,
            'products': [{'id': p[0], 'name': p[1], 'description': p[2], 'price': p[3]} for p in products],
            'executed_query': query,
            'detection': {
                'malicious': is_malicious,
                'confidence': details.get('confidence', 0),
                'patterns': details.get('detected_patterns', [])
            }
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'executed_query': query,
            'detection': details
        })


# ============================================================================
# SECURE ENDPOINTS (Best practices)
# ============================================================================

@app.route('/secure/login', methods=['GET', 'POST'])
def secure_login():
    """SECURE: Properly implemented login with parameterized queries"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Input validation
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'})
        
        if len(username) > 50 or len(password) > 100:
            return jsonify({'success': False, 'message': 'Input too long'})
        
        # Detection check
        is_malicious, details = detector.detect(username + password)
        if is_malicious:
            return jsonify({
                'success': False,
                'message': 'Suspicious input detected',
                'detection': details
            }), 400
        
        # SECURE CODE - Using parameterized queries
        conn = sqlite3.connect('app.db')
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, hashlib.sha256(password.encode()).hexdigest())
        )
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            return jsonify({
                'success': True,
                'message': 'Login successful!',
                'user': {'username': user[1], 'role': user[4]},
                'security': 'Parameterized Query Used'
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'})
    
    return render_template('secure.html')


@app.route('/secure/search', methods=['GET'])
def secure_search():
    """SECURE: Search products with proper validation and parameterized queries"""
    product_id = request.args.get('id', '')
    
    # Input validation
    if not product_id:
        return jsonify({'success': False, 'message': 'Product ID required'})
    
    # Type validation
    try:
        product_id = int(product_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid product ID format'}), 400
    
    # SECURE CODE
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM products WHERE id=?", (product_id,))
    products = cursor.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'products': [{'id': p[0], 'name': p[1], 'description': p[2], 'price': p[3]} for p in products],
        'security': 'Parameterized query with input validation'
    })


# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.route('/api/detect', methods=['POST'])
def detect_injection():
    """API endpoint to detect SQL injection in provided input"""
    data = request.get_json()
    
    if not data or 'input' not in data:
        return jsonify({'error': 'No input provided'}), 400
    
    input_string = data['input']
    is_malicious, details = detector.detect(input_string)
    
    return jsonify({
        'is_malicious': is_malicious,
        'details': details,
        'timestamp': datetime.now().isoformat()
    })


@app.route('/api/analyze', methods=['POST'])
def analyze_query():
    """Detailed analysis of a query"""
    data = request.get_json()
    
    if not data or 'query' not in data:
        return jsonify({'error': 'No query provided'}), 400
    
    analysis = detector.analyze_query(data['query'])
    return jsonify(analysis)


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get statistics about detected attacks"""
    try:
        with open('logs/attack_logs.json', 'r') as f:
            logs = [json.loads(line) for line in f]
        
        stats = {
            'total_attacks': len(logs),
            'attack_types': {},
            'risk_levels': {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0},
            'recent_attacks': logs[-10:]  # Last 10 attacks
        }
        
        for log in logs:
            # Count attack types
            for attack_type in log.get('attack_type', []):
                stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1
            
            # Count risk levels
            risk = log.get('risk_level', 'LOW')
            stats['risk_levels'][risk] += 1
        
        return jsonify(stats)
    except FileNotFoundError:
        return jsonify({'total_attacks': 0, 'message': 'No attacks logged yet'})


# ============================================================================
# WEB PAGES
# ============================================================================

@app.route('/')
def index():
    """Homepage"""
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    """Security dashboard"""
    return render_template('dashboard.html')


@app.route('/learn')
def learn():
    """Educational resources"""
    return render_template('learn.html')


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    # Initialize database
    init_db()
    
    print("=" * 60)
    print("SQL Injection Detection & Prevention System")
    print("=" * 60)
    print("\n🔒 Server starting on http://localhost:5000")
    print("\n⚠️  WARNING: This application contains intentionally vulnerable code")
    print("   Only use in isolated, controlled environments!")
    print("\nEndpoints:")
    print("  - /                    : Homepage")
    print("  - /dashboard           : Security dashboard")
    print("  - /vulnerable/login    : Vulnerable login demo")
    print("  - /secure/login        : Secure login demo")
    print("  - /api/detect          : Detection API")
    print("=" * 60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
