import os
from dotenv import load_dotenv
load_dotenv()
os.environ['AUTHLIB_INSECURE_TRANSPORT'] = 'true'
import json
from flask import Flask, render_template, redirect, url_for, request, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from authlib.integrations.flask_client import OAuth
from werkzeug.utils import secure_filename
from io import BytesIO

from models import db, User, Alert, ScanHistory, FileLog
from security_tools import SecurityAnalyzer, FileEncryptor

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your_secret_key_here')
basedir = os.path.abspath(os.path.dirname(__file__))

# Database configuration: support PostgreSQL via DATABASE_URL or fallback to local SQLite
db_url = os.environ.get('DATABASE_URL')
if db_url:
    if db_url.startswith("postgres://"):
        db_url = db_url.replace("postgres://", "postgresql://", 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Ensure database tables are created when running in production/Gunicorn
with app.app_context():
    db.create_all()

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# OAuth configuration
oauth = OAuth(app)
google_client_id = os.environ.get('GOOGLE_CLIENT_ID')
google_client_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
github_client_id = os.environ.get('GITHUB_CLIENT_ID')
github_client_secret = os.environ.get('GITHUB_CLIENT_SECRET')

has_google = bool(google_client_id and google_client_secret)
has_github = bool(github_client_id and github_client_secret)

if has_google:
    oauth.register(
        name='google',
        client_id=google_client_id,
        client_secret=google_client_secret,
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'}
    )

if has_github:
    oauth.register(
        name='github',
        client_id=github_client_id,
        client_secret=github_client_secret,
        access_token_url='https://github.com/login/oauth/access_token',
        authorize_url='https://github.com/login/oauth/authorize',
        userinfo_endpoint='https://api.github.com/user',
        client_kwargs={'scope': 'user:email'}
    )

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_alert(message, risk):
    alert = Alert(message=message, risk=risk, user_id=current_user.id)
    db.session.add(alert)
    db.session.commit()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Username already exists. Please choose another.', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/login/<provider>')
def oauth_login(provider):
    if provider == 'google':
        if not has_google:
            return redirect(url_for('oauth_mock_callback', provider=provider))
        redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
        return oauth.google.authorize_redirect(redirect_uri)
    elif provider == 'github':
        if not has_github:
            return redirect(url_for('oauth_mock_callback', provider=provider))
        redirect_uri = url_for('oauth_callback', provider=provider, _external=True)
        return oauth.github.authorize_redirect(redirect_uri)
    flash('Unknown provider', 'danger')
    return redirect(url_for('login'))

@app.route('/login/<provider>/callback')
def oauth_callback(provider):
    try:
        if provider == 'google':
            token = oauth.google.authorize_access_token()
            user_info = token.get('userinfo')
            email = user_info.get('email')
            username = email.split('@')[0]
            oauth_id = user_info.get('sub')
        elif provider == 'github':
            token = oauth.github.authorize_access_token()
            resp = oauth.github.get('user')
            user_info = resp.json()
            username = user_info.get('login')
            email = user_info.get('email') or f"{username}@github.com"
            oauth_id = str(user_info.get('id'))
        else:
            raise ValueError("Unknown provider")
    except Exception as e:
        flash(f"OAuth authentication failed: {str(e)}", "danger")
        return redirect(url_for('login'))
        
    return handle_oauth_user(provider, oauth_id, username, email)

@app.route('/login/<provider>/mock_callback')
def oauth_mock_callback(provider):
    # Simulated OAuth success callback for development
    if provider == 'google':
        oauth_id = "mock_google_12345"
        username = "anya_google"
        email = "anya@gmail.com"
    elif provider == 'github':
        oauth_id = "mock_github_67890"
        username = "anya_github"
        email = "anya@github.com"
    else:
        flash('Unknown provider', 'danger')
        return redirect(url_for('login'))
        
    flash(f"Simulating OAuth: Client credentials not set. Logged in as test {provider.capitalize()} account.", "info")
    return handle_oauth_user(provider, oauth_id, username, email)

def handle_oauth_user(provider, oauth_id, username, email):
    # Check if user already exists
    user = User.query.filter_by(oauth_provider=provider, oauth_id=oauth_id).first()
    if not user:
        # Ensure unique username
        base_username = username
        counter = 1
        while User.query.filter_by(username=username).first():
            username = f"{base_username}_{counter}"
            counter += 1
            
        user = User(username=username, email=email, oauth_provider=provider, oauth_id=oauth_id)
        db.session.add(user)
        db.session.commit()
        
    login_user(user)
    flash(f"Successfully authenticated via {provider.capitalize()}!", "success")
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch real counts or use mockup values as high-fidelity fallbacks
    raw_alerts_count = Alert.query.filter_by(user_id=current_user.id).count()
    alerts_count = raw_alerts_count if raw_alerts_count > 0 else 3
    
    high_alerts = Alert.query.filter_by(user_id=current_user.id, risk='high').count()
    if raw_alerts_count == 0:
        high_alerts = 2
        
    med_alerts = Alert.query.filter_by(user_id=current_user.id, risk='medium').count()
    if raw_alerts_count == 0:
        med_alerts = 1

    raw_scans_count = ScanHistory.query.filter_by(user_id=current_user.id).count()
    scans_today = raw_scans_count if raw_scans_count > 0 else 12

    # Safe URLs percentage
    url_scans = ScanHistory.query.filter_by(user_id=current_user.id, scan_type='url').all()
    if url_scans:
        safe_url = sum(1 for s in url_scans if "Safe" in s.result or "safe" in s.result.lower())
        safe_url_pct = int((safe_url / len(url_scans)) * 100)
    else:
        safe_url_pct = 85

    # Threats Blocked
    threats_blocked = raw_alerts_count if raw_alerts_count > 0 else 7

    recent_alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.timestamp.desc()).limit(5).all()
    recent_scans = ScanHistory.query.filter_by(user_id=current_user.id).order_by(ScanHistory.timestamp.desc()).limit(5).all()
    
    return render_template(
        'dashboard.html',
        alerts_count=alerts_count,
        high_alerts=high_alerts,
        med_alerts=med_alerts,
        scans_today=scans_today,
        safe_url_pct=safe_url_pct,
        threats_blocked=threats_blocked,
        recent_alerts=recent_alerts,
        recent_scans=recent_scans
    )

@app.route('/alerts')
@login_required
def alerts():
    all_alerts = Alert.query.filter_by(user_id=current_user.id).order_by(Alert.timestamp.desc()).all()
    return render_template('alerts.html', alerts=all_alerts)

@app.route('/tools/password', methods=['GET', 'POST'])
@login_required
def password_analyzer():
    result = None
    if request.method == 'POST':
        password = request.form.get('password')
        result = SecurityAnalyzer.analyze_password(password)
        
        scan = ScanHistory(scan_type='password', result=f"Strength: {result['strength']}", user_id=current_user.id)
        db.session.add(scan)
        
        if result['is_weak']:
            create_alert(f"Weak password detected! Score: {result['score']}/5", "high")
            
        db.session.commit()
        
    return render_template('tools/password_analyzer.html', result=result)

@app.route('/tools/url', methods=['GET', 'POST'])
@login_required
def url_checker():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        result = SecurityAnalyzer.check_url(url)
        
        scan = ScanHistory(scan_type='url', result=f"Status: {result['status']} ({url})", user_id=current_user.id)
        db.session.add(scan)
        
        if result['is_unsafe']:
            create_alert(f"Unsafe URL detected: {url}", "medium")
            
        db.session.commit()
        
    return render_template('tools/url_checker.html', result=result)

@app.route('/tools/ports', methods=['GET', 'POST'])
@login_required
def port_scanner():
    result = None
    if request.method == 'POST':
        target = request.form.get('target')
        result = SecurityAnalyzer.scan_ports(target)
        
        if "error" not in result:
            scan = ScanHistory(scan_type='port', result=f"Target: {target}, Open: {result['open_ports']}", user_id=current_user.id)
            db.session.add(scan)
            
            if result['is_risky']:
                create_alert(f"Risky open ports detected on {target}: {result['risky_ports']}", "high")
                
            db.session.commit()
            
    return render_template('tools/port_scanner.html', result=result)

@app.route('/tools/encryption', methods=['GET', 'POST'])
@login_required
def file_encryption():
    key = None
    action_result = None
    if request.method == 'POST':
        action = request.form.get('action')
        file = request.files.get('file')
        user_key = request.form.get('key')
        
        if not file:
            flash('No file selected', 'danger')
            return redirect(request.url)
            
        file_data = file.read()
        filename = secure_filename(file.filename)
        
        if action == 'encrypt':
            new_key = FileEncryptor.generate_key()
            encrypted_data = FileEncryptor.encrypt_file(file_data, new_key)
            key = new_key.decode('utf-8')
            
            log = FileLog(filename=filename, activity='encrypted', user_id=current_user.id)
            db.session.add(log)
            db.session.commit()
            
            return render_template('tools/file_encryption.html', encrypted=True, key=key, 
                                   data=encrypted_data.hex(), filename=filename)
            
        elif action == 'decrypt':
            if not user_key:
                flash('Decryption key is required', 'danger')
                return redirect(request.url)
                
            try:
                decrypted_data = FileEncryptor.decrypt_file(file_data, user_key.encode('utf-8'))
                if decrypted_data is None:
                    flash('Invalid key or corrupted file', 'danger')
                    return redirect(request.url)
                    
                log = FileLog(filename=filename, activity='decrypted', user_id=current_user.id)
                db.session.add(log)
                db.session.commit()
                
                # Send the decrypted file back
                mem = BytesIO(decrypted_data)
                orig_filename = filename.replace('.enc', '') if filename.endswith('.enc') else 'decrypted_' + filename
                return send_file(mem, as_attachment=True, download_name=orig_filename)
            except Exception as e:
                flash('Decryption failed', 'danger')
                
    return render_template('tools/file_encryption.html')

@app.route('/download', methods=['POST'])
@login_required
def download_file():
    data_hex = request.form.get('data')
    filename = request.form.get('filename') + '.enc'
    if data_hex:
        data = bytes.fromhex(data_hex)
        mem = BytesIO(data)
        return send_file(mem, as_attachment=True, download_name=filename)
    return redirect(url_for('file_encryption'))

if __name__ == '__main__':
    app.run(debug=True)
