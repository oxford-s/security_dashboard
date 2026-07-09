# Security Dashboard

A comprehensive Flask web application providing a centralized dashboard for security tools.

## Features

1. **Authentication System**: User registration, login, logout with secure password hashing (bcrypt).
2. **Dashboard**: Central control panel showing alerts count, recent activity, and navigation to tools.
3. **Security Modules**:
   - **Password Analyzer**: Checks password strength and detects weak patterns.
   - **URL Checker**: Identifies unencrypted connections and suspicious URL patterns.
   - **Port Scanner**: Scans a target host for commonly open and potentially risky ports.
   - **File Encryption**: Securely encrypt and decrypt files using Fernet symmetric encryption.
4. **Alert System**: Automatically logs potential security risks identified by the tools.
5. **Database**: Persistent storage of users, alerts, and scan histories using SQLite and SQLAlchemy.

## Setup Instructions

Since you are on Windows, open a **PowerShell** terminal and run the following commands to set up and start the application:

1. **Navigate to the project directory:**
   ```powershell
   cd " folder address"/" folder name"
   ```

2. **Create a virtual environment:**
   ```powershell
   python -m venv venv
   ```

3. **Activate the virtual environment:**
   ```powershell
   .\venv\Scripts\activate
   ```

4. **Install the dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

5. **Run the application:**
   ```powershell
   python app.py
   ```

6. **Access the application:**
   Open your web browser and navigate to `http://127.0.0.1:5000/`.

Enjoy your new Security Dashboard!
