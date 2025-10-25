# SQL Injection Detection & Prevention System

A comprehensive cybersecurity project that demonstrates SQL injection vulnerabilities, detection mechanisms, and prevention techniques.

## 🔒 Project Overview

This project provides a complete framework for understanding, detecting, and preventing SQL injection attacks. It includes vulnerable and secure code examples, real-time detection systems, and educational resources.

## ✨ Features

- **Vulnerable Web Application**: Demonstrates common SQL injection vulnerabilities
- **Secure Implementation**: Shows proper parameterized queries and input validation
- **Real-time Detection Engine**: AI-powered SQL injection pattern detection
- **Attack Signature Database**: Comprehensive collection of SQL injection patterns
- **Logging & Monitoring**: Track and analyze attack attempts
- **Educational Dashboard**: Interactive interface to learn about SQL injection
- **Cryptographic Protection**: Implements encryption for sensitive data

## 🛠️ Tech Stack

- **Backend**: Python (Flask)
- **Database**: SQLite (easily adaptable to PostgreSQL/MySQL)
- **Frontend**: HTML, CSS, JavaScript
- **Security**: bcrypt, parameterized queries, input validation
- **Detection**: Regular expressions, ML-based pattern matching

## 📁 Project Structure

```
sql-injection-detection/
├── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
├── app/
│   ├── __init__.py
│   ├── vulnerable_app.py      # Intentionally vulnerable code
│   ├── secure_app.py           # Secured implementation
│   ├── detector.py             # SQL injection detection engine
│   └── models.py               # Database models
├── detection/
│   ├── __init__.py
│   ├── pattern_matcher.py      # Pattern-based detection
│   ├── ml_detector.py          # ML-based detection
│   └── signatures.json         # Attack signatures
├── static/
│   ├── css/
│   ├── js/
│   └── img/
├── templates/
│   ├── index.html
│   ├── vulnerable.html
│   ├── secure.html
│   └── dashboard.html
├── tests/
│   ├── test_detection.py
│   ├── test_vulnerable.py
│   └── test_secure.py
├── logs/
│   └── attack_logs.json
└── docs/
    ├── INSTALLATION.md
    ├── USAGE.md
    └── ATTACK_TYPES.md
```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip
- virtualenv (recommended)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/sql-injection-detection.git
cd sql-injection-detection

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Initialize database
python init_db.py

# Run the application
python run.py
```

The application will be available at `http://localhost:5000`

## 📚 Usage Examples

### Testing Vulnerable Endpoint

```bash
# Basic SQL injection test
curl "http://localhost:5000/vulnerable/login?username=admin' OR '1'='1&password=anything"

# Union-based injection
curl "http://localhost:5000/vulnerable/search?id=1 UNION SELECT username,password FROM users--"
```

### Testing Secure Endpoint

```bash
# Same attempts will be safely handled
curl "http://localhost:5000/secure/login?username=admin' OR '1'='1&password=anything"
```

### Using Detection API

```bash
# Check if input contains SQL injection
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"query": "SELECT * FROM users WHERE id=1 OR 1=1"}'
```

## 🔍 Detection Mechanisms

### 1. Pattern-Based Detection
- Regex patterns for common SQL injection signatures
- Detection of SQL keywords in unusual contexts
- Comment pattern identification (`--`, `/**/`)

### 2. Syntax Analysis
- Tokenization of input strings
- Detection of unbalanced quotes
- Identification of logical operators

### 3. Machine Learning Detection
- Trained on labeled dataset of malicious/benign queries
- Feature extraction from query structure
- Real-time classification

## 🛡️ Prevention Techniques Implemented

1. **Parameterized Queries (Prepared Statements)**
   ```python
   cursor.execute("SELECT * FROM users WHERE username=?", (username,))
   ```

2. **Input Validation & Sanitization**
   - Whitelist validation
   - Type checking
   - Length restrictions

3. **Least Privilege Principle**
   - Database user permissions
   - Role-based access control

4. **Web Application Firewall (WAF) Rules**
   - Request filtering
   - Rate limiting

5. **Output Encoding**
   - Prevents XSS in conjunction with SQL injection

## 📊 Dashboard Features

- Real-time attack visualization
- Attack pattern statistics
- Geographic distribution of attack sources
- Severity classification
- Historical trend analysis

## 🧪 Testing

```bash
# Run all tests
pytest

# Run specific test suite
pytest tests/test_detection.py

# Run with coverage
pytest --cov=app tests/
```

## 🔐 Security Considerations

**⚠️ IMPORTANT**: This project contains intentionally vulnerable code for educational purposes.

- Never deploy the vulnerable application to production
- Use only in isolated, controlled environments
- The vulnerable code is clearly marked and separated
- Always follow secure coding practices in real applications

## 📖 Educational Resources

### Types of SQL Injection Covered

1. **Classic SQL Injection**
2. **Blind SQL Injection**
   - Boolean-based
   - Time-based
3. **Union-based Injection**
4. **Error-based Injection**
5. **Second-order Injection**

See [docs/ATTACK_TYPES.md](docs/ATTACK_TYPES.md) for detailed explanations.

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

## ⚖️ Legal Disclaimer

This tool is for educational and research purposes only. Users must:
- Only test on systems they own or have explicit permission to test
- Comply with all applicable laws and regulations
- Not use this tool for malicious purposes

The authors are not responsible for misuse or damage caused by this tool.

## 👥 Authors

- Your Name - [GitHub Profile](https://github.com/yourusername)

## 🙏 Acknowledgments

- OWASP Top 10 Project
- SQL Injection Knowledge Base
- Security research community

## 📞 Contact

Project Link: [https://github.com/yourusername/sql-injection-detection](https://github.com/yourusername/sql-injection-detection)

---

⭐ If you find this project helpful, please consider giving it a star!
