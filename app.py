from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash
import re
import requests
import numpy as np
import os
import tensorflow as tf
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Suppress TensorFlow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'  # 0=all, 1=info, 2=warning, 3=error

# Force CPU usage if needed
os.environ["CUDA_VISIBLE_DEVICES"] = "-1"  # Comment this line if you want to use GPU
print("Device set to use cpu")

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cyber-theft-prevention-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Load AI models - we'll load them lazily when needed
scam_detector = None


def get_scam_detector():
    global scam_detector
    if scam_detector is None:
        try:
            # Load a smaller model for faster inference
            model_name = "distilbert-base-uncased-finetuned-sst-2-english"
            scam_detector = pipeline("text-classification", model=model_name)
            logger.info(f"Loaded model: {model_name}")
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            # Fallback to rule-based detection only
            scam_detector = None
    return scam_detector


# User model for login system
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))
    name = db.Column(db.String(100))

    def __repr__(self):
        return f'<User {self.email}>'


# Message analysis history
class MessageAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content_type = db.Column(db.String(10))  # 'email' or 'sms'
    content = db.Column(db.Text)
    is_scam = db.Column(db.Boolean)
    confidence = db.Column(db.Float)
    reason = db.Column(db.Text)
    analysis_date = db.Column(db.DateTime, default=db.func.current_timestamp())

    def __repr__(self):
        return f'<Analysis {self.id}: {"Scam" if self.is_scam else "Legitimate"}>'


# Routes for home page
@app.route('/')
def index():
    return render_template('index.html')


# Routes for authentication
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        name = request.form.get('name')
        password = request.form.get('password')

        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please log in.')
            return redirect(url_for('login'))

        # Create new user
        new_user = User(
            email=email,
            name=name,
            password=generate_password_hash(password)
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating account: {str(e)}')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['user_email'] = user.email
            session['user_name'] = user.name
            flash('Login successful!')
            return redirect(url_for('dashboard'))

        flash('Invalid credentials. Please try again.')

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access your dashboard.')
        return redirect(url_for('login'))

    # Get user's history
    history = MessageAnalysis.query.filter_by(user_id=session['user_id']).order_by(
        MessageAnalysis.analysis_date.desc()).limit(10).all()

    return render_template('dashboard.html', history=history)


@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    if 'user_id' not in session:
        flash('Please log in to analyze messages.')
        return redirect(url_for('login'))

    if request.method == 'POST':
        content_type = request.form.get('type')  # 'email' or 'sms'
        content = request.form.get('content')

        if not content:
            flash('Please provide content to analyze.')
            return render_template('analyze.html')

        # Analyze content
        analysis_result = analyze_text_for_scam(content)

        # Check URLs if present
        urls = extract_urls(content)
        url_analysis = {}
        for url in urls:
            url_analysis[url] = check_url_safety(url)

        # Save analysis to database
        new_analysis = MessageAnalysis(
            user_id=session['user_id'],
            content_type=content_type,
            content=content,
            is_scam=analysis_result['is_scam'],
            confidence=analysis_result['confidence'],
            reason=analysis_result['reason']
        )

        try:
            db.session.add(new_analysis)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error saving analysis: {e}")

        return render_template(
            'result.html',
            content=content,
            content_type=content_type,
            result=analysis_result,
            urls=url_analysis
        )

    return render_template('analyze.html')


# API for scam detection
@app.route('/api/analyze', methods=['POST'])
def api_analyze_content():
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400

    # Get authentication token or check session as needed
    # For demo, we're using session, but in production use proper API authentication
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401

    data = request.json
    content_type = data.get('type', 'unknown')  # 'email' or 'sms'
    content = data.get('content')

    if not content:
        return jsonify({'error': 'No content provided'}), 400

    # Basic content analysis
    result = analyze_text_for_scam(content)

    # Check URLs if present
    urls = extract_urls(content)
    url_safety = {}
    for url in urls:
        url_safety[url] = check_url_safety(url)

    # Save to database
    new_analysis = MessageAnalysis(
        user_id=session['user_id'],
        content_type=content_type,
        content=content,
        is_scam=result['is_scam'],
        confidence=result['confidence'],
        reason=result['reason']
    )

    try:
        db.session.add(new_analysis)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error saving API analysis: {e}")

    return jsonify({
        'is_scam': result['is_scam'],
        'confidence': result['confidence'],
        'reason': result['reason'],
        'urls': url_safety
    })


def analyze_text_for_scam(text):
    # Enhanced rule-based filters with names, patterns, examples, and explanations
    red_flag_rules = [
        {
            'name': 'Urgency Tactics',
            'pattern': r'\b(urgent|immediate action|verify your account|act now|right away)\b',
            'example': 'Your account will be suspended unless you verify immediately',
            'explanation': 'Creates false urgency to bypass rational thinking'
        },
        {
            'name': 'Too Good To Be True',
            'pattern': r'\b(you have won|lottery|prize|million dollars|free gift|no cost)\b',
            'example': 'You have won a $1 million lottery prize!',
            'explanation': 'Classic advance-fee fraud technique offering unrealistic rewards'
        },
        {
            'name': 'Financial Credential Request',
            'pattern': r'\b(bank account.*verify|update.*payment information|credit card details)\b',
            'example': 'Please update your bank account information to continue service',
            'explanation': 'Attempts to steal financial credentials through fake requests'
        },
        {
            'name': 'Fake Security Alert',
            'pattern': r'\b(password.*expired|security.*breach|account.*compromised|suspicious activity)\b',
            'example': 'We detected suspicious activity on your account',
            'explanation': 'Fake security alerts designed to harvest credentials'
        },
        {
            'name': 'Generic Greeting',
            'pattern': r'\b(dear (customer|user|account holder|valued member)|hello friend)\b',
            'example': 'Dear valued customer, your account needs verification',
            'explanation': 'Impersonal greetings often used in mass phishing attempts'
        },
        {
            'name': 'Payment Demand',
            'pattern': r'\b(pay (now|immediately)|outstanding balance|overdue payment)\b',
            'example': 'Your account has an overdue payment of $299.99',
            'explanation': 'Fake payment demands to steal money'
        },
        {
            'name': 'Government Impersonation',
            'pattern': r'\b(irs|social security|tax refund|government grant)\b',
            'example': 'The IRS requires immediate payment for back taxes',
            'explanation': 'Scammers often impersonate government agencies'
        },
        {
            'name': 'Poor Grammar/Spelling',
            'pattern': r'\b(kindly do the needful|urgently require|pls|acount|informations)\b',
            'example': 'Kindly do the needful and send informations',
            'explanation': 'Poor grammar and spelling are common in scam messages'
        }
    ]

    detected_patterns = []
    text_lower = text.lower()

    for rule in red_flag_rules:
        matches = re.finditer(rule['pattern'], text_lower, re.IGNORECASE)
        for match in matches:
            matched_text = text[match.start():match.end()]
            detected_patterns.append({
                'name': rule['name'],
                'pattern': rule['pattern'],
                'matched_text': matched_text,
                'position': match.start(),
                'explanation': rule['explanation'],
                'example': rule['example']
            })

    # AI-based analysis if available
    model_score = 0.5  # Default neutral score
    detector = get_scam_detector()

    if detector:
        try:
            # Ensure text isn't too long for the model
            analysis_text = text[:512] if len(text) > 512 else text
            result = detector(analysis_text)
            # For this model, "POSITIVE" means legitimate (not scam)
            model_score = result[0]['score'] if result[0]['label'] == 'POSITIVE' else 1 - result[0]['score']
        except Exception as e:
            logger.error(f"Error in AI analysis: {e}")
            # Fall back to rule-based only
            model_score = 0.5

    # Combined analysis
    rule_based_weight = 0.7
    ai_weight = 0.3

    # If we found rule-based red flags, this strongly suggests a scam
    rule_based_score = min(0.9, 0.5 + (0.1 * len(detected_patterns))) if detected_patterns else 0.3

    # Final weighted score (higher = more likely a scam)
    combined_score = (rule_based_weight * rule_based_score) + (ai_weight * (1 - model_score))

    # Decision threshold
    is_scam = combined_score > 0.5

    # Explanation
    if detected_patterns:
        unique_categories = list({pattern['name'] for pattern in detected_patterns})
        reason = f"Detected {len(unique_categories)} suspicious patterns: {', '.join(unique_categories[:3])}"
    elif combined_score > 0.5:
        reason = "AI analysis indicates potential scam based on content patterns"
    else:
        reason = "Content appears legitimate with no obvious scam indicators"

    return {
        'is_scam': is_scam,
        'confidence': min(round(combined_score, 4), 0.99),
        'reason': reason,
        'detected_patterns': detected_patterns,
        'text': text  # Include original text for highlighting
    }

def extract_urls(text):
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    return re.findall(url_pattern, text)


def check_url_safety(url):
    # Enhanced URL safety check with more detailed explanations
    results = {
        'safe': True,
        'reason': 'No obvious threats detected',
        'details': []
    }

    # Check for URL shorteners (often used in phishing)
    suspicious_domains = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'tiny.cc', 'is.gd', 'cli.gs', 'ow.ly']
    for domain in suspicious_domains:
        if domain in url.lower():
            results['safe'] = False
            results['reason'] = 'URL shortener detected - potential phishing risk'
            results['details'].append({
                'issue': 'URL Shortener',
                'explanation': 'URL shorteners hide the actual destination, making it easier to disguise malicious links.'
            })
            break

    # Check for suspicious TLDs often used in phishing
    suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz']
    for tld in suspicious_tlds:
        if url.lower().endswith(tld):
            results['safe'] = False
            results['reason'] = f'Domain uses {tld} TLD - commonly used in phishing'
            results['details'].append({
                'issue': 'Suspicious TLD',
                'explanation': f'The domain uses {tld} TLD which is often available for free and commonly used in phishing campaigns.'
            })
            break

    # Check for IP addresses in URLs (suspicious)
    ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.match(ip_pattern, url):
        results['safe'] = False
        results['reason'] = 'IP address used in URL instead of domain name - suspicious'
        results['details'].append({
            'issue': 'IP Address URL',
            'explanation': 'Legitimate websites typically use domain names, not raw IP addresses. IP addresses in URLs are often used to hide the true identity of the website.'
        })

    # Check for excessive subdomains (can be a sign of phishing)
    parts = url.split('/')
    if len(parts) > 3:
        domain_part = parts[2]
        if domain_part.count('.') > 3:
            results['safe'] = False
            results['reason'] = 'Excessive subdomains detected - potential phishing technique'
            results['details'].append({
                'issue': 'Multiple Subdomains',
                'explanation': 'The URL contains an unusual number of subdomains, which is often used to make phishing URLs look legitimate.'
            })

    # Check for deceptive domains (e.g., paypal-secure.something.com)
    trusted_brands = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'netflix', 'bank']
    domain_part = url.split('/')[2] if len(url.split('/')) > 2 else ""

    for brand in trusted_brands:
        if brand in domain_part.lower() and not domain_part.lower().startswith(brand + '.'):
            results['safe'] = False
            results['reason'] = f'Potential brand impersonation ({brand})'
            results['details'].append({
                'issue': 'Brand Impersonation',
                'explanation': f'This URL appears to reference {brand} but is not from the official {brand} domain.'
            })
            break

    return results


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)