# Usage Guide

Comprehensive guide for using the SQL Injection Detection & Prevention System.

## Table of Contents
- [Getting Started](#getting-started)
- [Web Interface](#web-interface)
- [API Usage](#api-usage)
- [Detection Engine](#detection-engine)
- [Examples](#examples)
- [Best Practices](#best-practices)

---

## Getting Started

### Starting the Application

```bash
# Activate virtual environment
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Start the server
python app.py
```

### Stopping the Application

Press `Ctrl+C` in the terminal to stop the server.

---

## Web Interface

### Homepage (/)

The main landing page provides:
- Overview of the system
- Quick navigation to demos
- Feature highlights
- Educational resources

### Security Dashboard (/dashboard)

Real-time monitoring interface showing:
- **Attack Statistics**: Total attacks, risk levels
- **Detection Test**: Interactive query testing
- **Attack Distribution**: Types of attacks detected
- **Recent Attacks**: Live feed of attack attempts

#### Using the Dashboard

1. **View Statistics**: Check total attacks and risk distribution
2. **Test Detection**: Enter a query in the test box
3. **Click "Analyze Query"**: See detection results
4. **Monitor Attacks**: View recent attack attempts in real-time

### Vulnerable Demo (/vulnerable/login)

⚠️ **Educational purposes only - DO NOT use in production**

This demonstrates common SQL injection vulnerabilities:

#### Testing Authentication Bypass

```
Username: admin' OR '1'='1
Password: anything
```

**What happens:**
- Query becomes: `SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='...'`
- The `OR '1'='1'` makes the condition always true
- Authentication is bypassed

#### Other Test Vectors

```
Username: admin'--
Username: ' OR 1=1--
Username: admin' #
Username: ' OR 'x'='x
```

### Secure Demo (/secure/login)

Demonstrates proper security implementation:

#### Features
- Parameterized queries
- Input validation
- Real-time detection
- Proper error handling

#### Try the Same Attacks

The secure version will:
1. Detect malicious input
2. Block the request
3. Log the attempt
4. Return appropriate error message

---

## API Usage

### Detection API (/api/detect)

Check if input contains SQL injection patterns.

#### Request

```bash
POST /api/detect
Content-Type: application/json

{
  "input": "admin' OR '1'='1"
}
```

#### Response

```json
{
  "is_malicious": true,
  "details": {
    "confidence": 0.85,
    "risk_level": "HIGH",
    "attack_type": ["classic", "comment"],
    "detected_patterns": [
      "unbalanced_quotes",
      "classic_or_pattern"
    ],
    "timestamp": "2025-10-25T10:30:00"
  }
}
```

#### Python Example

```python
import requests

def check_sql_injection(user_input):
    url = "http://localhost:5000/api/detect"
    payload = {"input": user_input}
    
    response = requests.post(url, json=payload)
    result = response.json()
    
    if result['is_malicious']:
        print(f"⚠️ MALICIOUS: {result['details']['risk_level']}")
        print(f"Confidence: {result['details']['confidence']:.2%}")
        print(f"Types: {', '.join(result['details']['attack_type'])}")
    else:
        print("✅ Input appears safe")
    
    return result

# Test
check_sql_injection("admin' OR '1'='1")
```

#### JavaScript Example

```javascript
async function checkSQLInjection(input) {
    const response = await fetch('http://localhost:5000/api/detect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ input: input })
    });
    
    const result = await response.json();
    
    if (result.is_malicious) {
        console.warn('⚠️ Malicious input detected!');
        console.log('Risk Level:', result.details.risk_level);
        console.log('Confidence:', result.details.confidence);
    } else {
        console.log('✅ Input appears safe');
    }
    
    return result;
}

// Test
checkSQLInjection("admin' OR '1'='1");
```

### Analysis API (/api/analyze)

Get detailed analysis with recommendations.

#### Request

```bash
POST /api/analyze
Content-Type: application/json

{
  "query": "SELECT * FROM users WHERE id=1 OR 1=1"
}
```

#### Response

```json
{
  "query": "SELECT * FROM users WHERE id=1 OR 1=1",
  "is_safe": false,
  "risk_assessment": {
    "confidence": 0.92,
    "risk_level": "HIGH",
    "attack_type": ["classic", "boolean_blind"]
  },
  "recommendations": [
    "Block this request immediately",
    "Use parameterized queries/prepared statements",
    "Implement proper error handling",
    "Log this attempt for security audit"
  ]
}
```

### Statistics API (/api/stats)

Get attack statistics and trends.

#### Request

```bash
GET /api/stats
```

#### Response

```json
{
  "total_attacks": 42,
  "attack_types": {
    "classic": 18,
    "union": 10,
    "time_based": 8,
    "comment": 6
  },
  "risk_levels": {
    "HIGH": 25,
    "MEDIUM": 12,
    "LOW": 5
  },
  "recent_attacks": [...]
}
```

---

## Detection Engine

### Using the Detector Programmatically

```python
from detector import SQLInjectionDetector

# Initialize detector
detector = SQLInjectionDetector()

# Simple detection
is_malicious, details = detector.detect("admin' OR '1'='1")

print(f"Malicious: {is_malicious}")
print(f"Confidence: {details['confidence']:.2f}")
print(f"Risk Level: {details['risk_level']}")
print(f"Attack Types: {', '.join(details['attack_type'])}")

# Detailed analysis
analysis = detector.analyze_query("SELECT * FROM users WHERE id=1 OR 1=1")

print(f"\nQuery: {analysis['query']}")
print(f"Safe: {analysis['is_safe']}")
print(f"\nRecommendations:")
for rec in analysis['recommendations']:
    print(f"  • {rec}")
```

### Custom Detection Patterns

Add custom patterns to the detector:

```python
detector = SQLInjectionDetector()

# Add custom signature
custom_pattern = r"custom_attack_pattern"
detector.signatures['custom'] = [custom_pattern]

# Test detection
is_malicious, details = detector.detect("input with custom pattern")
```

---

## Examples

### Example 1: Protecting a Login Form

```python
from flask import request, jsonify
from detector import SQLInjectionDetector

detector = SQLInjectionDetector()

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Check for SQL injection
    is_malicious, details = detector.detect(username + password)
    
    if is_malicious:
        # Log the attempt
        app.logger.warning(f"SQL injection attempt: {details}")
        
        # Return error
        return jsonify({
            'error': 'Invalid input detected',
            'risk_level': details['risk_level']
        }), 400
    
    # Proceed with secure authentication
    # Use parameterized queries here
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, hash_password(password))
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({'success': True, 'user': user[1]})
    else:
        return jsonify({'success': False}), 401
```

### Example 2: Middleware for All Requests

```python
@app.before_request
def check_sql_injection():
    # Check all request parameters
    for key, value in request.values.items():
        is_malicious, details = detector.detect(str(value))
        
        if is_malicious:
            app.logger.warning(
                f"SQL injection attempt in {key}: {value}"
            )
            return jsonify({
                'error': 'Suspicious input detected',
                'parameter': key
            }), 400
```

### Example 3: Batch Input Validation

```python
def validate_batch_inputs(inputs):
    """Validate multiple inputs at once"""
    results = []
    
    for i, input_str in enumerate(inputs):
        is_malicious, details = detector.detect(input_str)
        
        results.append({
            'index': i,
            'input': input_str,
            'is_safe': not is_malicious,
            'details': details
        })
    
    return results

# Usage
user_inputs = [
    "john_doe",
    "admin' OR '1'='1",
    "user@email.com",
    "1 UNION SELECT * FROM users"
]

validation_results = validate_batch_inputs(user_inputs)

for result in validation_results:
    status = "✅ SAFE" if result['is_safe'] else "⚠️ MALICIOUS"
    print(f"{status}: {result['input']}")
```

### Example 4: Real-time Input Monitoring

```javascript
// Frontend JavaScript
document.getElementById('searchInput').addEventListener('input', async (e) => {
    const input = e.target.value;
    
    if (input.length > 3) {
        const result = await checkSQLInjection(input);
        
        const indicator = document.getElementById('securityIndicator');
        
        if (result.is_malicious) {
            indicator.className = 'danger';
            indicator.textContent = '⚠️ Suspicious input detected';
        } else {
            indicator.className = 'safe';
            indicator.textContent = '✅ Input OK';
        }
    }
});
```

---

## Best Practices

### 1. Input Validation

```python
def validate_user_input(input_str, max_length=100):
    """Validate user input before processing"""
    
    # Check length
    if len(input_str) > max_length:
        return False, "Input too long"
    
    # Check for SQL injection
    is_malicious, details = detector.detect(input_str)
    if is_malicious:
        return False, f"Malicious input: {details['risk_level']}"
    
    # Additional validation (alphanumeric, email, etc.)
    # ...
    
    return True, "Valid"
```

### 2. Always Use Parameterized Queries

```python
# ❌ NEVER do this
query = f"SELECT * FROM users WHERE id={user_id}"
cursor.execute(query)

# ✅ ALWAYS do this
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
```

### 3. Log All Detection Events

```python
def log_detection(is_malicious, details, request_info):
    """Log detection events for audit"""


### Integration with Existing Applications

```python
# Add to your existing Flask app
from # Usage Guide

Comprehensive guide for using the SQL Injection Detection & Prevention System.

## Table of Contents
- [Getting Started](#getting-started)
- [Web Interface](#web-interface)
- [API Usage](#api-usage)
- [Detection Engine](#detection-engine)
- [Examples](#examples)
- [Best Practices](#best-practices)

---

## Getting Started

### Starting the Application

```bash
# Activate virtual environment
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Start the server
python app.py
```

### Stopping the Application

Press `Ctrl+C` in the terminal to stop the server.

---

## Web Interface

### Homepage (/)

The main landing page provides:
- Overview of the system
- Quick navigation to demos
- Feature highlights
- Educational resources

### Security Dashboard (/dashboard)

Real-time monitoring interface showing:
- **Attack Statistics**: Total attacks, risk levels
- **Detection Test**: Interactive query testing
- **Attack Distribution**: Types of attacks detected
- **Recent Attacks**: Live feed of attack attempts

#### Using the Dashboard

1. **View Statistics**: Check total attacks and risk distribution
2. **Test Detection**: Enter a query in the test box
3. **Click "Analyze Query"**: See detection results
4. **Monitor Attacks**: View recent attack attempts in real-time

### Vulnerable Demo (/vulnerable/login)

⚠️ **Educational purposes only - DO NOT use in production**

This demonstrates common SQL injection vulnerabilities:

#### Testing Authentication Bypass

```
Username: admin' OR '1'='1
Password: anything
```

**What happens:**
- Query becomes: `SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='...'`
- The `OR '1'='1'` makes the condition always true
- Authentication is bypassed

#### Other Test Vectors

```
Username: admin'--
Username: ' OR 1=1--
Username: admin' #
Username: ' OR 'x'='x
```

### Secure Demo (/secure/login)

Demonstrates proper security implementation:

#### Features
- Parameterized queries
- Input validation
- Real-time detection
- Proper error handling

#### Try the Same Attacks

The secure version will:
1. Detect malicious input
2. Block the request
3. Log the attempt
4. Return appropriate error message

---

## API Usage

### Detection API (/api/detect)

Check if input contains SQL injection patterns.

#### Request

```bash
POST /api/detect
Content-Type: application/json

{
  "input": "admin' OR '1'='1"
}
```

#### Response

```json
{
  "is_malicious": true,
  "details": {
    "confidence": 0.85,
    "risk_level": "HIGH",
    "attack_type": ["classic", "comment"],
    "detected_patterns": [
      "unbalanced_quotes",
      "classic_or_pattern"
    ],
    "timestamp": "2025-10-25T10:30:00"
  }
}
```

#### Python Example

```python
import requests

def check_sql_injection(user_input):
    url = "http://localhost:5000/api/detect"
    payload = {"input": user_input}
    
    response = requests.post(url, json=payload)
    result = response.json()
    
    if result['is_malicious']:
        print(f"⚠️ MALICIOUS: {result['details']['risk_level']}")
        print(f"Confidence: {result['details']['confidence']:.2%}")
        print(f"Types: {', '.join(result['details']['attack_type'])}")
    else:
        print("✅ Input appears safe")
    
    return result

# Test
check_sql_injection("admin' OR '1'='1")
```

#### JavaScript Example

```javascript
async function checkSQLInjection(input) {
    const response = await fetch('http://localhost:5000/api/detect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ input: input })
    });
    
    const result = await response.json();
    
    if (result.is_malicious) {
        console.warn('⚠️ Malicious input detected!');
        console.log('Risk Level:', result.details.risk_level);
        console.log('Confidence:', result.details.confidence);
    } else {
        console.log('✅ Input appears safe');
    }
    
    return result;
}

// Test
checkSQLInjection("admin' OR '1'='1");
```

### Analysis API (/api/analyze)

Get detailed analysis with recommendations.

#### Request

```bash
POST /api/analyze
Content-Type: application/json

{
  "query": "SELECT * FROM users WHERE id=1 OR 1=1"
}
```

#### Response

```json
{
  "query": "SELECT * FROM users WHERE id=1 OR 1=1",
  "is_safe": false,
  "risk_assessment": {
    "confidence": 0.92,
    "risk_level": "HIGH",
    "attack_type": ["classic", "boolean_blind"]
  },
  "recommendations": [
    "Block this request immediately",
    "Use parameterized queries/prepared statements",
    "Implement proper error handling",
    "Log this attempt for security audit"
  ]
}
```

### Statistics API (/api/stats)

Get attack statistics and trends.

#### Request

```bash
GET /api/stats
```

#### Response

```json
{
  "total_attacks": 42,
  "attack_types": {
    "classic": 18,
    "union": 10,
    "time_based": 8,
    "comment": 6
  },
  "risk_levels": {
    "HIGH": 25,
    "MEDIUM": 12,
    "LOW": 5
  },
  "recent_attacks": [...]
}
```

---

## Detection Engine

### Using the Detector Programmatically

```python
from detector import SQLInjectionDetector

# Initialize detector
detector = SQLInjectionDetector()

# Simple detection
is_malicious, details = detector.detect("admin' OR '1'='1")

print(f"Malicious: {is_malicious}")
print(f"Confidence: {details['confidence']:.2f}")
print(f"Risk Level: {details['risk_level']}")
print(f"Attack Types: {', '.join(details['attack_type'])}")

# Detailed analysis
analysis = detector.analyze_query("SELECT * FROM users WHERE id=1 OR 1=1")

print(f"\nQuery: {analysis['query']}")
print(f"Safe: {analysis['is_safe']}")
print(f"\nRecommendations:")
for rec in analysis['recommendations']:
    print(f"  • {rec}")
```

### Custom Detection Patterns

Add custom patterns to the detector:

```python
detector = SQLInjectionDetector()

# Add custom signature
custom_pattern = r"custom_attack_pattern"
detector.signatures['custom'] = [custom_pattern]

# Test detection
is_malicious, details = detector.detect("input with custom pattern")
```

---

## Examples

### Example 1: Protecting a Login Form

```python
from flask import request, jsonify
from detector import SQLInjectionDetector

detector = SQLInjectionDetector()

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    # Check for SQL injection
    is_malicious, details = detector.detect(username + password)
    
    if is_malicious:
        # Log the attempt
        app.logger.warning(f"SQL injection attempt: {details}")
        
        # Return error
        return jsonify({
            'error': 'Invalid input detected',
            'risk_level': details['risk_level']
        }), 400
    
    # Proceed with secure authentication
    # Use parameterized queries here
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, hash_password(password))
    )
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return jsonify({'success': True, 'user': user[1]})
    else:
        return jsonify({'success': False}), 401
```

### Example 2: Middleware for All Requests

```python
@app.before_request
def check_sql_injection():
    # Check all request parameters
    for key, value in request.values.items():
        is_malicious, details = detector.detect(str(value))
        
        if is_malicious:
            app.logger.warning(
                f"SQL injection attempt in {key}: {value}"
            )
            return jsonify({
                'error': 'Suspicious input detected',
                'parameter': key
            }), 400
```

### Example 3: Batch Input Validation

```python
def validate_batch_inputs(inputs):
    """Validate multiple inputs at once"""
    results = []
    
    for i, input_str in enumerate(inputs):
        is_malicious, details = detector.detect(input_str)
        
        results.append({
            'index': i,
            'input': input_str,
            'is_safe': not is_malicious,
            'details': details
        })
    
    return results

# Usage
user_inputs = [
    "john_doe",
    "admin' OR '1'='1",
    "user@email.com",
    "1 UNION SELECT * FROM users"
]

validation_results = validate_batch_inputs(user_inputs)

for result in validation_results:
    status = "✅ SAFE" if result['is_safe'] else "⚠️ MALICIOUS"
    print(f"{status}: {result['input']}")
```

### Example 4: Real-time Input Monitoring

```javascript
// Frontend JavaScript
document.getElementById('searchInput').addEventListener('input', async (e) => {
    const input = e.target.value;
    
    if (input.length > 3) {
        const result = await checkSQLInjection(input);
        
        const indicator = document.getElementById('securityIndicator');
        
        if (result.is_malicious) {
            indicator.className = 'danger';
            indicator.textContent = '⚠️ Suspicious input detected';
        } else {
            indicator.className = 'safe';
            indicator.textContent = '✅ Input OK';
        }
    }
});
```

---

## Best Practices

### 1. Input Validation

```python
def validate_user_input(input_str, max_length=100):
    """Validate user input before processing"""
    
    # Check length
    if len(input_str) > max_length:
        return False, "Input too long"
    
    # Check for SQL injection
    is_malicious, details = detector.detect(input_str)
    if is_malicious:
        return False, f"Malicious input: {details['risk_level']}"
    
    # Additional validation (alphanumeric, email, etc.)
    # ...
    
    return True, "Valid"
```

### 2. Always Use Parameterized Queries

```python
# ❌ NEVER do this
query = f"SELECT * FROM users WHERE id={user_id}"
cursor.execute(query)

# ✅ ALWAYS do this
cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
```

### 3. Log All Detection Events

```python
def log_detection(is_malicious, details, request_info):
    """Log detection events for audit"""
    log_entry = {
        'timestamp': datetime.now().isoformat(),
        'malicious': is_malicious,
        'confidence': details['confidence'],
        'risk_level': details['risk_level'],
        'ip_address': request_info.get('ip'),
        'user_agent': request_info.get('user_agent'),
        'endpoint': request_info.get('endpoint')
    }
    
    logger.warning(json.dumps(log_entry))
```

### 4. Implement Rate Limiting

```python
from flask_limiter import Limiter

limiter = Limiter(app, key_func=lambda: request.remote_addr)

@app.route('/api/detect', methods=['POST'])
@limiter.limit("10 per minute")
def detect():
    # Your detection logic
    pass
```

### 5. Context-Aware Detection

```python
def context_aware_detection(input_str, input_type):
    """Adjust detection based on input context"""
    
    # Different validation for different types
    if input_type == 'email':
        # Email-specific validation
        if '@' not in input_str:
            return False, "Invalid email"
    
    elif input_type == 'numeric':
        # Numeric validation
        if not input_str.isdigit():
            return False, "Must be numeric"
    
    # SQL injection check
    is_malicious, details = detector.detect(input_str)
    
    return not is_malicious, details
```

---

## Advanced Usage

### Creating Custom Detection Rules

```python
class CustomDetector(SQLInjectionDetector):
    def __init__(self):
        super().__init__()
        
        # Add industry-specific patterns
        self.signatures['custom_finance'] = [
            r"account.*balance",
            r"transaction.*amount"
        ]
    
    def custom_rule(self, input_str):
        """Add custom detection logic"""
        # Your custom logic here
        pass
```

### Integration with Existing Applications

```python
# Add to your existing Flask app
from detector import SQLInjectionDetector

detector = SQLInjectionDetector()

# Use in existing routes
@app.route('/api/user/<user_id>')
def get_user(user_id):
    # Validate input
    is_malicious, _ = detector.detect(user_id)
    
    if is_malicious:
        abort(400, "Invalid input")
    
    # Your existing logic
    pass
```

---

## Support

For questions or issues:
- Check the [troubleshooting guide](INSTALLATION.md#troubleshooting)
- Review [attack types documentation](docs/ATTACK_TYPES.md)
- Submit issues on GitHub

---

Happy Learning! 🔒 import SQLInjectionDetector

detector = ()

# Use in existing routes
@app.route('/api/user/<user_id>')
def get_user(user_id):
    # Validate input
    is_malicious, _ = detector.detect(user_id)
    
    if is_malicious:
        abort(400, "Invalid input")
    
    # Your existing logic
    pass
```

---

## Support

For questions or issues:
- Check the [troubleshooting guide](INSTALLATION.md#troubleshooting)
- Review [attack types documentation](docs/ATTACK_TYPES.md)
- Submit issues on GitHub

---

Happy Learning! 🔒
