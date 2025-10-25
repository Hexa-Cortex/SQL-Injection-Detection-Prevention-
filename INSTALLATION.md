# Installation Guide

Complete guide to setting up the SQL Injection Detection & Prevention System.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation Steps](#installation-steps)
- [Configuration](#configuration)
- [Running the Application](#running-the-application)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements
- **Operating System**: Windows, macOS, or Linux
- **Python**: 3.8 or higher
- **RAM**: Minimum 2GB
- **Disk Space**: 500MB free space

### Required Software
- Python 3.8+
- pip (Python package manager)
- Git (for cloning the repository)
- Virtual environment support (recommended)

### Verify Prerequisites

```bash
# Check Python version
python --version
# or
python3 --version

# Check pip
pip --version

# Check Git
git --version
```

---

## Installation Steps

### 1. Clone the Repository

```bash
# Clone from GitHub
git clone https://github.com/yourusername/sql-injection-detection.git

# Navigate to project directory
cd sql-injection-detection
```

### 2. Create Virtual Environment

**On Windows:**
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate
```

**On macOS/Linux:**
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate
```

You should see `(venv)` in your terminal prompt indicating the virtual environment is active.

### 3. Install Dependencies

```bash
# Upgrade pip (recommended)
pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed Flask-3.0.0 Werkzeug-3.0.1 pytest-7.4.3 ...
```

### 4. Initialize Database

```bash
# Run database initialization script
python init_db.py
```

**Expected output:**
```
============================================================
SQL Injection Detection - Database Initialization
============================================================

✓ Created new database: app.db
✓ Created 'users' table
✓ Created 'products' table
✓ Created 'audit_log' table

Inserting sample users...
  → Added user: admin (password: admin123)
  → Added user: john_doe (password: password123)
  ...

Database initialization completed successfully!
```

### 5. Create Required Directories

```bash
# Create logs directory (if not exists)
mkdir logs
```

---

## Configuration

### Environment Variables (Optional)

Create a `.env` file in the project root:

```bash
# .env file
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///app.db
```

### Application Settings

Edit `app.py` to customize:

```python
# Debug mode (disable in production)
app.config['DEBUG'] = True

# Secret key for sessions
app.secret_key = 'your-secret-key'

# Database path
DATABASE = 'app.db'
```

---

## Running the Application

### Start the Server

```bash
# Run the Flask application
python app.py
```

**Expected output:**
```
============================================================
SQL Injection Detection & Prevention System
============================================================

🔒 Server starting on http://localhost:5000

⚠️  WARNING: This application contains intentionally vulnerable code
   Only use in isolated, controlled environments!

Endpoints:
  - /                    : Homepage
  - /dashboard           : Security dashboard
  - /vulnerable/login    : Vulnerable login demo
  - /secure/login        : Secure login demo
  - /api/detect          : Detection API
============================================================

 * Running on http://localhost:5000
```

### Access the Application

Open your web browser and navigate to:
- **Homepage**: http://localhost:5000
- **Dashboard**: http://localhost:5000/dashboard
- **API**: http://localhost:5000/api/detect

### Default Credentials

```
Username: admin
Password: admin123
```

---

## Testing

### Run Unit Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_detection.py

# Run with coverage report
pytest --cov=app tests/
```

### Manual Testing

#### Test Detection API

```bash
# Using curl
curl -X POST http://localhost:5000/api/detect \
  -H "Content-Type: application/json" \
  -d '{"input": "admin OR 1=1"}'

# Using Python
python
>>> import requests
>>> response = requests.post('http://localhost:5000/api/detect', 
                            json={'input': "admin' OR '1'='1"})
>>> print(response.json())
```

#### Test Vulnerable Endpoint

```bash
# Authentication bypass test
curl "http://localhost:5000/vulnerable/login?username=admin'%20OR%20'1'='1&password=anything"
```

#### Test Secure Endpoint

```bash
# Same attempt on secure endpoint (should be blocked)
curl "http://localhost:5000/secure/login?username=admin'%20OR%20'1'='1&password=anything"
```

---

## Troubleshooting

### Common Issues

#### Issue 1: Port Already in Use

**Error:**
```
Address already in use
```

**Solution:**
```bash
# Find process using port 5000
# On Windows:
netstat -ano | findstr :5000

# On macOS/Linux:
lsof -i :5000

# Kill the process or change port in app.py
app.run(port=5001)
```

#### Issue 2: Module Not Found

**Error:**
```
ModuleNotFoundError: No module named 'flask'
```

**Solution:**
```bash
# Ensure virtual environment is activated
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Reinstall dependencies
pip install -r requirements.txt
```

#### Issue 3: Database Locked

**Error:**
```
sqlite3.OperationalError: database is locked
```

**Solution:**
```bash
# Close any applications accessing the database
# Delete and reinitialize database
rm app.db
python init_db.py
```

#### Issue 4: Permission Denied

**Error:**
```
PermissionError: [Errno 13] Permission denied: 'logs/attack_logs.json'
```

**Solution:**
```bash
# Create logs directory with proper permissions
mkdir -p logs
chmod 755 logs

# On Windows, run as administrator
```

#### Issue 5: Import Error for detector.py

**Error:**
```
ImportError: cannot import name 'SQLInjectionDetector'
```

**Solution:**
```bash
# Ensure you're in the correct directory
pwd  # Should show project root

# Check if detector.py exists
ls detector.py

# Verify Python path
python -c "import sys; print(sys.path)"
```

### Debug Mode

Enable debug mode for detailed error messages:

```python
# In app.py
if __name__ == '__main__':
    app.run(debug=True)
```

### Logging

Check logs for errors:

```bash
# View application logs
cat logs/attack_logs.log

# View attack JSON logs
cat logs/attack_logs.json

# Monitor logs in real-time
tail -f logs/attack_logs.log
```

---

## Docker Installation (Alternative)

### Create Dockerfile

```dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

RUN python init_db.py

EXPOSE 5000

CMD ["python", "app.py"]
```

### Build and Run

```bash
# Build Docker image
docker build -t sql-injection-detector .

# Run container
docker run -p 5000:5000 sql-injection-detector
```

---

## Production Deployment (WARNING)

⚠️ **DO NOT deploy the vulnerable components in production!**

For production deployment of the detection system only:

1. **Disable vulnerable endpoints**
2. **Use production WSGI server** (Gunicorn, uWSGI)
3. **Enable HTTPS**
4. **Set strong secret keys**
5. **Use production database** (PostgreSQL, MySQL)
6. **Enable rate limiting**
7. **Set up monitoring and alerts**

### Example Production Configuration

```bash
# Install Gunicorn
pip install gunicorn

# Run with Gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 app:app
```

---

## Next Steps

After successful installation:

1. ✅ Explore the web interface at http://localhost:5000
2. ✅ Read [USAGE.md](USAGE.md) for detailed usage instructions
3. ✅ Study [ATTACK_TYPES.md](docs/ATTACK_TYPES.md) to learn about different attacks
4. ✅ Try the interactive demos (vulnerable vs secure)
5. ✅ Test the detection API with various inputs

---

## Getting Help

- **Documentation**: Check the `docs/` directory
- **Issues**: Report on GitHub Issues
- **Community**: Join discussions
- **Email**: support@example.com

---

## Verification Checklist

- [ ] Python 3.8+ installed
- [ ] Virtual environment created and activated
- [ ] All dependencies installed successfully
- [ ] Database initialized with sample data
- [ ] Application starts without errors
- [ ] Can access homepage at localhost:5000
- [ ] Tests pass successfully
- [ ] Logs directory created

If all items are checked, you're ready to use the system! 🎉
