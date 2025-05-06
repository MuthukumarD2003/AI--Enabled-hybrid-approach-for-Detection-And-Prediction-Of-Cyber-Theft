import re, sqlite3, hashlib, urllib.parse, requests, ssl, socket, joblib
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords
import nltk, numpy as np, ipaddress, tldextract
from bs4 import BeautifulSoup

# Ensure NLTK data is available
for resource in ['punkt', 'stopwords']:
    try: nltk.data.find(f'tokenizers/{resource}' if resource == 'punkt' else f'corpora/{resource}')
    except LookupError: nltk.download(resource)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secure_secret_key_here'
csrf = CSRFProtect(app)

def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT NOT NULL,
        result TEXT NOT NULL,
        scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    conn.commit(); conn.close()

init_db()

# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(4, 20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class ScanForm(FlaskForm):
    content = TextAreaField('Paste email or SMS content here', validators=[DataRequired()])
    submit = SubmitField('Scan')

# Feature extraction
def extract_features(text):
    features = {
        'text_length': len(text),
        'word_count': len(text.split()),
        'url_count': len(re.findall(r'https?://\S+', text)),
        'email_count': len(re.findall(r'[\w\.-]+@[\w\.-]+', text)),
        'phone_count': len(re.findall(r'\b(?:\+?(\d{1,3}))?[-. (]*\d{3}[-. )]*\d{3}[-. ]*\d{4}\b', text)),
        'special_char_ratio': len(re.findall(r'[^a-zA-Z0-9\s]', text)) / max(1, len(text)),
        'exclamation_count': text.count('!'),
        'question_count': text.count('?')
    }
    words = text.split()
    features['uppercase_ratio'] = len([w for w in words if w.isupper() and len(w) > 1]) / max(1, len(words))
    suspicious_words = ['urgent', 'alert', 'attention', 'bank', 'account', 'verify', 'click',
                        'confirm', 'update', 'password', 'credit', 'win', 'free', 'money',
                        'prize', 'lottery', 'million', 'offer', 'limited', 'bitcoin',
                        'cryptocurrency', 'wallet', 'payment', 'transfer', 'investment']
    for word in suspicious_words:
        features[f'contains_{word}'] = int(word in text.lower())
    return features

def analyze_url(url):
    result = {'is_suspicious': False, 'reasons': []}
    try:
        parsed = urllib.parse.urlparse(url)
        ext = tldextract.extract(url)
        domain, suffix, sub = ext.domain, ext.suffix, ext.subdomain

        def flag(reason): result.update(is_suspicious=True); result['reasons'].append(reason)

        if parsed.scheme == 'http': flag("Uses HTTP")
        if suffix in ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'work', 'date', 'racing']:
            flag(f"Suspicious TLD: .{suffix}")
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain): flag("Domain is IP address")
        if len(domain) > 25: flag("Long domain name")
        if len(sub) > 25: flag("Long subdomain")
        if sub.count('.') > 2: flag("Too many subdomains")
        if '@' in url: flag("Contains '@' symbol")
        if len(parsed.query) > 100: flag("Excessive query params")
        if any(w in domain.lower() for w in ['secure', 'account', 'banking', 'login', 'verify',
                                             'ebay', 'paypal', 'amazon', 'apple', 'microsoft',
                                             'netflix', 'bank', 'update', 'service']):
            flag("Suspicious keyword in domain")
        if any(short in url.lower() for short in ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com',
                                                  'is.gd', 'cli.gs', 'ow.ly', 'j.mp',
                                                  'tickurl.com', 'qr.net', 'cutt.ly']):
            flag("URL shortening service")
        if any(kd in parsed.path.lower() and kd not in domain.lower()
               for kd in ['paypal', 'google', 'apple', 'microsoft', 'amazon', 'facebook']):
            flag("Fake domain in path")
    except Exception as e:
        result.update(is_suspicious=True)
        result['reasons'].append(f"URL analysis error: {str(e)}")
    return result

def ml_prediction(text):
    features = extract_features(text)
    score = (
        20 * (features['url_count'] > 0) +
        10 * (features['special_char_ratio'] > 0.1) +
        15 * (features['uppercase_ratio'] > 0.3) +
        5 * (features['exclamation_count'] > 3) +
        5 * sum(v for k, v in features.items() if k.startswith('contains_'))
    )
    for url in re.findall(r'https?://\S+', text):
        if analyze_url(url)['is_suspicious']:
            score += 25
    return 'high_risk' if score >= 50 else 'medium_risk' if score >= 25 else 'low_risk'


def analyze_content(content):
    """Analyze email/SMS content for threats"""
    results = {
        'score': 0,  # 0-100
        'risk_level': 'unknown',
        'threats_detected': [],
        'recommendations': [],
        'urls_analysis': []
    }
    
    # Basic checks
    if not content.strip():
        results['risk_level'] = 'unknown'
        results['recommendations'].append("Empty content provided. Please submit text to analyze.")
        return results
    
    # Look for URLs in the content
    urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', content)
    if len(urls) > 0:
        results['threats_detected'].append(f"Contains {len(urls)} URL(s)")
        
        # Analyze each URL
        for url in urls:
            url_analysis = analyze_url(url)
            if url_analysis['is_suspicious']:
                results['urls_analysis'].append({
                    'url': url,
                    'is_suspicious': True,
                    'reasons': url_analysis['reasons']
                })
            else:
                results['urls_analysis'].append({
                    'url': url,
                    'is_suspicious': False,
                    'reasons': ["No immediate red flags detected"]
                })
    
    # Use ML model to predict risk level
    ml_result = ml_prediction(content)
    
    if ml_result == 'high_risk':
        results['risk_level'] = 'high'
        results['score'] = 85
        results['threats_detected'].append("Machine learning model classified this as high risk")
        results['recommendations'].append("Do not respond to this message")
        results['recommendations'].append("Do not click any links in this message")
        results['recommendations'].append("Do not provide any personal information")
        results['recommendations'].append("Report this as phishing to your email provider")
        
    elif ml_result == 'medium_risk':
        results['risk_level'] = 'medium'
        results['score'] = 50
        results['threats_detected'].append("Machine learning model found some suspicious patterns")
        results['recommendations'].append("Proceed with caution")
        results['recommendations'].append("Verify the sender through official channels before responding")
        results['recommendations'].append("Do not click links unless absolutely necessary")
        if len(urls) > 0:
            results['recommendations'].append("If you must visit a link, type the main domain directly in your browser instead")
            
    else:
        results['risk_level'] = 'low'
        results['score'] = 15
        results['recommendations'].append("Message appears to be legitimate, but always stay vigilant")
        
    # Special patterns to check
    if re.search(r'(urgent|immediate|alert|attention|warning|action required)', content.lower()):
        results['threats_detected'].append("Uses urgency tactics to prompt hasty action")
        results['score'] += 10
        
    if re.search(r'bank|account|verify|password|login|credentials|ssn|social security', content.lower()):
        results['threats_detected'].append("Requests sensitive personal or financial information")
        results['score'] += 15
        
    if re.search(r'won|winner|lottery|prize|million|reward|gift card', content.lower()):
        results['threats_detected'].append("Promises unrealistic rewards or prizes")
        results['score'] += 15
        
    if content.isupper() or re.search(r'[!]{2,}', content):
        results['threats_detected'].append("Uses excessive capitalization or punctuation")
        results['score'] += 5
        
    # Cap the score at 100
    results['score'] = min(results['score'], 100)
    
    # Set overall risk level based on final score
    if results['score'] >= 70:
        results['risk_level'] = 'high'
    elif results['score'] >= 40:
        results['risk_level'] = 'medium'
    elif results['score'] > 0:
        results['risk_level'] = 'low'
        
    return results

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and user['password'] == hashlib.sha256(password.encode()).hexdigest():
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = hashlib.sha256(form.password.data.encode()).hexdigest()
        
        conn = get_db_connection()
        
        try:
            conn.execute('INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
                      (username, email, password))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'danger')
        finally:
            conn.close()
            
    return render_template('register.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    scan_form = ScanForm()
    
    # Get recent scan history
    conn = get_db_connection()
    history = conn.execute('''
        SELECT * FROM scan_history 
        WHERE user_id = ? 
        ORDER BY scanned_at DESC LIMIT 5
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('dashboard.html', 
                           username=session['username'],
                           scan_form=scan_form,
                           history=history)

@app.route('/scan', methods=['POST'])
def scan():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = ScanForm()
    
    if form.validate_on_submit():
        content = form.content.data
        analysis_result = analyze_content(content)
        
        # Store scan result
        conn = get_db_connection()
        conn.execute('''
            INSERT INTO scan_history (user_id, content, result)
            VALUES (?, ?, ?)
        ''', (session['user_id'], content, str(analysis_result)))
        conn.commit()
        conn.close()
        
        return render_template('result.html', 
                              content=content,
                              result=analysis_result)
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/history')
def history():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    history = conn.execute('''
        SELECT * FROM scan_history 
        WHERE user_id = ? 
        ORDER BY scanned_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    
    return render_template('history.html', history=history)

# Templates
@app.route('/templates')
def get_templates():
    """Return HTML templates for the front-end"""
    templates = {
        'login.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>X-AI - Login</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f8f9fa;
            padding-top: 50px;
        }
        .login-container {
            max-width: 400px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo h1 {
            color: #0d6efd;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="login-container">
            <div class="logo">
                <h1>X-AI</h1>
                <p>Cyber Theft Detection & Prevention</p>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <form method="POST" action="{{ url_for('login') }}">
                {{ form.csrf_token }}
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    {{ form.username(class="form-control", placeholder="Enter your username") }}
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    {{ form.password(class="form-control", placeholder="Enter your password") }}
                </div>
                <div class="d-grid gap-2">
                    {{ form.submit(class="btn btn-primary") }}
                </div>
                <div class="mt-3 text-center">
                    <p>Don't have an account? <a href="{{ url_for('register') }}">Register here</a></p>
                </div>
            </form>
        </div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        ''',
        
        'register.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>X-AI - Register</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f8f9fa;
            padding-top: 50px;
        }
        .register-container {
            max-width: 400px;
            margin: 0 auto;
            padding: 20px;
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo h1 {
            color: #0d6efd;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="register-container">
            <div class="logo">
                <h1>X-AI</h1>
                <p>Create a new account</p>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ category }}">{{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <form method="POST" action="{{ url_for('register') }}">
                {{ form.csrf_token }}
                <div class="mb-3">
                    <label for="username" class="form-label">Username</label>
                    {{ form.username(class="form-control", placeholder="Choose a username") }}
                </div>
                <div class="mb-3">
                    <label for="email" class="form-label">Email</label>
                    {{ form.email(class="form-control", placeholder="Enter your email") }}
                </div>
                <div class="mb-3">
                    <label for="password" class="form-label">Password</label>
                    {{ form.password(class="form-control", placeholder="Choose a strong password") }}
                </div>
                <div class="mb-3">
                    <label for="confirm_password" class="form-label">Confirm Password</label>
                    {{ form.confirm_password(class="form-control", placeholder="Confirm your password") }}
                </div>
                <div class="d-grid gap-2">
                    {{ form.submit(class="btn btn-success") }}
                </div>
                <div class="mt-3 text-center">
                    <p>Already have an account? <a href="{{ url_for('login') }}">Login here</a></p>
                </div>
            </form>
        </div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        ''',
        
        'dashboard.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>X-AI - Dashboard</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .sidebar {
            background-color: #212529;
            color: white;
            min-height: 100vh;
            padding-top: 20px;
        }
        .sidebar .nav-link {
            color: rgba(255,255,255,0.8);
            padding: 15px 20px;
            border-radius: 5px;
            margin: 5px 10px;
        }
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            background-color: #0d6efd;
            color: white;
        }
        .sidebar .logo {
            text-align: center;
            margin-bottom: 30px;
            padding: 0 20px;
        }
        .sidebar .logo h2 {
            color: #0d6efd;
        }
        .main-content {
            padding: 20px;
        }
        .card {
            border: none;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .section-title {
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #dee2e6;
        }
        .scan-form {
            margin-bottom: 20px;
        }
        .scan-form textarea {
            resize: vertical;
            min-height: 150px;
        }
        .history-item {
            padding: 10px;
            border-bottom: 1px solid #eee;
            cursor: pointer;
        }
        .history-item:hover {
            background-color: #f8f9fa;
        }
        .history-item:last-child {
            border-bottom: none;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 d-md-block sidebar collapse">
                <div class="logo">
                    <h2>X-AI</h2>
                    <p>Cyber Theft Detection</p>
                </div>
                <ul class="nav flex-column">
                    <li class="nav-item">
                        <a class="nav-link active" href="{{ url_for('dashboard') }}">
                            <i class="fas fa-home me-2"></i> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('history') }}">
                            <i class="fas fa-history me-2"></i> Scan History
                        </a>
                    </li>
                    <li class="nav-item mt-auto">
                        <a class="nav-link" href="{{ url_for('logout') }}">
                            <i class="fas fa-sign-out-alt me-2"></i> Logout
                        </a>
                    </li>
                </ul>
            </div>
            
            <!-- Main Content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4 main-content">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Welcome, {{ username }}</h1>
                </div>
                
                <div class="row">
                    <div class="col-md-8">
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="fas fa-shield-alt me-2"></i> Scan for Threats</h5>
                            </div>
                            <div class="card-body">
                                <form method="POST" action="{{ url_for('scan') }}" class="scan-form">
                                    {{ scan_form.csrf_token }}
                                    <div class="mb-3">
                                        <label for="content" class="form-label">Paste suspicious email or SMS content</label>
                                        {{ scan_form.content(class="form-control", placeholder="Paste the full email or SMS content here...") }}
                                    </div>
                                    <div class="d-grid gap-2">
                                        {{ scan_form.submit(class="btn btn-primary btn-lg") }}
                                    </div>
                                </form>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0"><i class="fas fa-info-circle me-2"></i> How to Use</h5>
                            </div>
                            <div class="card-body">
                                <div class="mb-3">
                                    <h6><i class="fas fa-envelope me-2"></i> For Emails:</h6>
                                    <p>Copy the entire email content including sender, subject line, and body text. Paste it into the analysis box above and click Scan.</p>
                                </div>
                                <div class="mb-3">
                                    <h6><i class="fas fa-sms me-2"></i> For SMS:</h6>
                                    <p>Copy the entire message and paste it into the analysis box. Include the sender's number if available.</p>
                                </div>
                                <div>
                                    <h6><i class="fas fa-link me-2"></i> For URLs:</h6>
                                    <p>Paste the suspicious URL into the analysis box. Our system will analyze it for potential phishing indicators.</p>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-4">
                        <div class="card">
                            <div class="card-header bg-info text-white">
                                <h5 class="mb-0"><i class="fas fa-history me-2"></i> Recent Scans</h5>
                            </div>
                            <div class="card-body p-0">
                                {% if history %}
                                    <div class="list-group list-group-flush">
                                        {% for item in history %}
                                            <div class="history-item">
                                                <div class="d-flex justify-content-between">
                                                    <small class="text-muted">{{ item['scanned_at'] }}</small>
                                                    {% if 'high' in item['result'] %}
                                                        <span class="badge bg-danger">High Risk</span>
                                                    {% elif 'medium' in item['result'] %}
                                                        <span class="badge bg-warning">Medium Risk</span>
                                                    {% elif 'low' in item['result'] %}
                                                        <span class="badge bg-success">Low Risk</span>
                                                    {% else %}
                                                        <span class="badge bg-secondary">Unknown</span>
                                                    {% endif %}
                                                </div>
                                                <div class="text-truncate mt-1">
                                                    {{ item['content'][:50] }}{% if item['content']|length > 50 %}...{% endif %}
                                                </div>
                                            </div>
                                        {% endfor %}
                                    </div>
                                {% else %}
                                    <div class="p-3 text-center">
                                        <p class="text-muted">No scan history yet.</p>
                                    </div>
                                {% endif %}
                            </div>
                            <div class="card-footer">
                                <a href="{{ url_for('history') }}" class="btn btn-sm btn-outline-primary w-100">View All History</a>
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header bg-success text-white">
                                <h5 class="mb-0"><i class="fas fa-chart-pie me-2"></i> Stats</h5>
                            </div>
                            <div class="card-body">
                                <div class="row text-center">
                                    <div class="col">
                                        <h3 class="text-primary">{{ history|length }}</h3>
                                        <small class="text-muted">Total Scans</small>
                                    </div>
                                    <div class="col">
                                        <h3 class="text-danger">
                                            {% set high_risk = namespace(count=0) %}
                                            {% for item in history %}
                                                {% if 'high' in item['result'] %}
                                                    {% set high_risk.count = high_risk.count + 1 %}
                                                {% endif %}
                                            {% endfor %}
                                            {{ high_risk.count }}
                                        </h3>
                                        <small class="text-muted">High Risk</small>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        ''',
        
        'result.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>X-AI - Scan Results</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .sidebar {
            background-color: #212529;
            color: white;
            min-height: 100vh;
            padding-top: 20px;
        }
        .sidebar .nav-link {
            color: rgba(255,255,255,0.8);
            padding: 15px 20px;
            border-radius: 5px;
            margin: 5px 10px;
        }
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            background-color: #0d6efd;
            color: white;
        }
        .sidebar .logo {
            text-align: center;
            margin-bottom: 30px;
            padding: 0 20px;
        }
        .sidebar .logo h2 {
            color: #0d6efd;
        }
        .main-content {
            padding: 20px;
        }
        .card {
            border: none;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .risk-meter {
            height: 40px;
            border-radius: 20px;
            overflow: hidden;
            background-color: #e9ecef;
            margin: 20px 0;
        }
        .risk-level {
            height: 100%;
            text-align: center;
            color: white;
            font-weight: bold;
            line-height: 40px;
            transition: width 0.5s ease-in-out;
        }
        .risk-low {
            background-color: #28a745;
        }
        .risk-medium {
            background-color: #ffc107;
        }
        .risk-high {
            background-color: #dc3545;
        }
        .threat-item {
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 5px;
            background-color: #f8d7da;
            border-left: 5px solid #dc3545;
        }
        .recommendation-item {
            margin-bottom: 10px;
            padding: 10px;
            border-radius: 5px;
            background-color: #d4edda;
            border-left: 5px solid #28a745;
        }
        .content-preview {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            max-height: 200px;
            overflow-y: auto;
            margin-bottom: 20px;
            border: 1px solid #dee2e6;
        }
        .url-item {
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
        }
        .url-safe {
            background-color: #d4edda;
            border-left: 5px solid #28a745;
        }
        .url-suspicious {
            background-color: #f8d7da;
            border-left: 5px solid #dc3545;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 d-md-block sidebar collapse">
                <div class="logo">
                    <h2>X-AI</h2>
                    <p>Cyber Theft Detection</p>
                </div>
                <ul class="nav flex-column">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('dashboard') }}">
                            <i class="fas fa-home me-2"></i> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('history') }}">
                            <i class="fas fa-history me-2"></i> Scan History
                        </a>
                    </li>
                    <li class="nav-item mt-auto">
                        <a class="nav-link" href="{{ url_for('logout') }}">
                            <i class="fas fa-sign-out-alt me-2"></i> Logout
                        </a>
                    </li>
                </ul>
            </div>
            
            <!-- Main Content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4 main-content">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Scan Results</h1>
                    <div>
                        <a href="{{ url_for('dashboard') }}" class="btn btn-outline-primary">
                            <i class="fas fa-arrow-left me-2"></i> Back to Dashboard
                        </a>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-12">
                        <div class="card">
                            <div class="card-header">
                                <h5 class="mb-0">
                                    {% if result.risk_level == 'high' %}
                                        <i class="fas fa-exclamation-triangle text-danger me-2"></i>
                                        <span class="text-danger">High Risk Detected!</span>
                                    {% elif result.risk_level == 'medium' %}
                                        <i class="fas fa-exclamation-circle text-warning me-2"></i>
                                        <span class="text-warning">Medium Risk Detected</span>
                                    {% elif result.risk_level == 'low' %}
                                        <i class="fas fa-check-circle text-success me-2"></i>
                                        <span class="text-success">Low Risk Detected</span>
                                    {% else %}
                                        <i class="fas fa-question-circle text-secondary me-2"></i>
                                        <span class="text-secondary">Unknown Risk</span>
                                    {% endif %}
                                </h5>
                            </div>
                            <div class="card-body">
                                <h6>Risk Score: {{ result.score }}/100</h6>
                                <div class="risk-meter">
                                    {% if result.risk_level == 'high' %}
                                        <div class="risk-level risk-high" style="width: {{ result.score }}%;">HIGH RISK</div>
                                    {% elif result.risk_level == 'medium' %}
                                        <div class="risk-level risk-medium" style="width: {{ result.score }}%;">MEDIUM RISK</div>
                                    {% elif result.risk_level == 'low' %}
                                        <div class="risk-level risk-low" style="width: {{ result.score }}%;">LOW RISK</div>
                                    {% else %}
                                        <div class="risk-level" style="width: 0%;"></div>
                                    {% endif %}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="row">
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-danger text-white">
                                <h5 class="mb-0"><i class="fas fa-bug me-2"></i> Threats Detected</h5>
                            </div>
                            <div class="card-body">
                                {% if result.threats_detected %}
                                    {% for threat in result.threats_detected %}
                                        <div class="threat-item">
                                            <i class="fas fa-exclamation-triangle me-2"></i> {{ threat }}
                                        </div>
                                    {% endfor %}
                                {% else %}
                                    <p class="text-success"><i class="fas fa-check-circle me-2"></i> No specific threats detected.</p>
                                {% endif %}
                            </div>
                        </div>
                        
                        <div class="card">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="fas fa-file-alt me-2"></i> Content Preview</h5>
                            </div>
                            <div class="card-body">
                                <div class="content-preview">
                                    {{ content }}
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="col-md-6">
                        <div class="card">
                            <div class="card-header bg-success text-white">
                                <h5 class="mb-0"><i class="fas fa-shield-alt me-2"></i> Recommendations</h5>
                            </div>
                            <div class="card-body">
                                {% if result.recommendations %}
                                    {% for recommendation in result.recommendations %}
                                        <div class="recommendation-item">
                                            <i class="fas fa-check me-2"></i> {{ recommendation }}
                                        </div>
                                    {% endfor %}
                                {% else %}
                                    <p class="text-muted">No specific recommendations available.</p>
                                {% endif %}
                            </div>
                        </div>
                        
                        {% if result.urls_analysis %}
                            <div class="card">
                                <div class="card-header bg-info text-white">
                                    <h5 class="mb-0"><i class="fas fa-link me-2"></i> URL Analysis</h5>
                                </div>
                                <div class="card-body">
                                    {% for url_data in result.urls_analysis %}
                                        <div class="url-item {% if url_data.is_suspicious %}url-suspicious{% else %}url-safe{% endif %}">
                                            <h6>
                                                {% if url_data.is_suspicious %}
                                                    <i class="fas fa-exclamation-triangle text-danger me-2"></i>
                                                    <span class="text-danger">Suspicious URL</span>
                                                {% else %}
                                                    <i class="fas fa-check-circle text-success me-2"></i>
                                                    <span class="text-success">Likely Safe URL</span>
                                                {% endif %}
                                            </h6>
                                            <div class="mb-2 text-break">
                                                <small>{{ url_data.url }}</small>
                                            </div>
                                            <div>
                                                <strong>Analysis:</strong>
                                                <ul class="mb-0 mt-1">
                                                    {% for reason in url_data.reasons %}
                                                        <li>{{ reason }}</li>
                                                    {% endfor %}
                                                </ul>
                                            </div>
                                        </div>
                                    {% endfor %}
                                </div>
                            </div>
                        {% endif %}
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        ''',
        
        'history.html': '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>X-AI - Scan History</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .sidebar {
            background-color: #212529;
            color: white;
            min-height: 100vh;
            padding-top: 20px;
        }
        .sidebar .nav-link {
            color: rgba(255,255,255,0.8);
            padding: 15px 20px;
            border-radius: 5px;
            margin: 5px 10px;
        }
        .sidebar .nav-link:hover, .sidebar .nav-link.active {
            background-color: #0d6efd;
            color: white;
        }
        .sidebar .logo {
            text-align: center;
            margin-bottom: 30px;
            padding: 0 20px;
        }
        .sidebar .logo h2 {
            color: #0d6efd;
        }
        .main-content {
            padding: 20px;
        }
        .card {
            border: none;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .history-item {
            padding: 15px;
            border-bottom: 1px solid #eee;
        }
        .history-item:last-child {
            border-bottom: none;
        }
        .history-content {
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            max-height: 100px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="row">
            <!-- Sidebar -->
            <div class="col-md-3 col-lg-2 d-md-block sidebar collapse">
                <div class="logo">
                    <h2>X-AI</h2>
                    <p>Cyber Theft Detection</p>
                </div>
                <ul class="nav flex-column">
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('dashboard') }}">
                            <i class="fas fa-home me-2"></i> Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link active" href="{{ url_for('history') }}">
                            <i class="fas fa-history me-2"></i> Scan History
                        </a>
                    </li>
                    <li class="nav-item mt-auto">
                        <a class="nav-link" href="{{ url_for('logout') }}">
                            <i class="fas fa-sign-out-alt me-2"></i> Logout
                        </a>
                    </li>
                </ul>
            </div>
            
            <!-- Main Content -->
            <main class="col-md-9 ms-sm-auto col-lg-10 px-md-4 main-content">
                <div class="d-flex justify-content-between flex-wrap flex-md-nowrap align-items-center pt-3 pb-2 mb-3 border-bottom">
                    <h1 class="h2">Scan History</h1>
                </div>
                
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h5 class="mb-0"><i class="fas fa-history me-2"></i> Your Scan History</h5>
                    </div>
                    <div class="card-body p-0">
                        {% if history %}
                            {% for item in history %}
                                <div class="history-item">
                                    <div class="d-flex justify-content-between align-items-center mb-2">
                                        <div>
                                            <span class="text-muted me-3">{{ item['scanned_at'] }}</span>
                                            {% if 'high' in item['result'] %}
                                                <span class="badge bg-danger">High Risk</span>
                                            {% elif 'medium' in item['result'] %}
                                                <span class="badge bg-warning">Medium Risk</span>
                                            {% elif 'low' in item['result'] %}
                                                <span class="badge bg-success">Low Risk</span>
                                            {% else %}
                                                <span class="badge bg-secondary">Unknown</span>
                                            {% endif %}
                                        </div>
                                    </div>
                                    <div class="history-content">
                                        {{ item['content'] }}
                                    </div>
                                </div>
                            {% endfor %}
                        {% else %}
                            <div class="p-4 text-center">
                                <p class="text-muted">No scan history found.</p>
                                <a href="{{ url_for('dashboard') }}" class="btn btn-primary">Go to Dashboard to Scan</a>
                            </div>
                        {% endif %}
                    </div>
                </div>
            </main>
        </div>
    </div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
        '''
    }
    
    return templates.get(template_name, "Template not found.")

if __name__ == '__main__':
    app.run(debug=True)