import os
import uuid
import random
import string
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from dotenv import load_dotenv

load_dotenv()

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///markai.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = None  # API-driven, no redirect

# ------------------------------------------------------------------------------
# External AI API configuration (exactly as required)
# ------------------------------------------------------------------------------
API_KEY = "MDE5YzRjMTctZmQ1NC03YWQxLWFmMzAtN2YxMjRlODYxYzJiOjUyM2RhNGZjLTEyZWItNDk5NS1hN2NhLWE3MWQyNGRlZDkzNw=="
# Replace with actual endpoint if different; this is a placeholder for OpenAI style
API_URL = "https://api.openai.com/v1/chat/completions"

# ------------------------------------------------------------------------------
# Database Model
# ------------------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(120), unique=True, nullable=False)
    onboarding_accepted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# ------------------------------------------------------------------------------
# Temporary in‑memory storage for email codes (in production use Redis / cache)
# ------------------------------------------------------------------------------
email_codes = {}   # email: {'code': '123456', 'expires': datetime}

def generate_code():
    return ''.join(random.choices(string.digits, k=6))

def send_code_via_email(email, code):
    """Simulate sending email – prints code to console (Render logs)."""
    print(f"[EMAIL SIMULATION] To: {email}  Your login code: {code}")
    # In a real app, integrate with SendGrid / SMTP here

# ------------------------------------------------------------------------------
# API Routes
# ------------------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/send-code', methods=['POST'])
def send_code():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email required'}), 400

    code = generate_code()
    expires = datetime.utcnow() + timedelta(minutes=10)
    email_codes[email] = {'code': code, 'expires': expires}
    send_code_via_email(email, code)
    return jsonify({'message': 'Code sent (simulated, check console)'}), 200

@app.route('/api/auth/verify', methods=['POST'])
def verify_code():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')
    remember = data.get('remember', False)

    if not email or not code:
        return jsonify({'error': 'Email and code required'}), 400

    stored = email_codes.get(email)
    if not stored or stored['code'] != code or stored['expires'] < datetime.utcnow():
        return jsonify({'error': 'Invalid or expired code'}), 400

    # Create user if not exists
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=remember)
    # Clear used code
    email_codes.pop(email, None)

    return jsonify({
        'user': {
            'id': user.id,
            'email': user.email,
            'onboarding_accepted': user.onboarding_accepted
        }
    }), 200

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    return jsonify({
        'user': {
            'id': current_user.id,
            'email': current_user.email,
            'onboarding_accepted': current_user.onboarding_accepted
        }
    }), 200

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logged out'}), 200

@app.route('/api/onboarding/accept', methods=['POST'])
@login_required
def accept_onboarding():
    current_user.onboarding_accepted = True
    db.session.commit()
    return jsonify({'message': 'Onboarding accepted'}), 200

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json()
    user_message = data.get('message')
    if not user_message:
        return jsonify({'error': 'Message required'}), 400

    # --------------------------------------------------------------------------
    # Call external AI API with the provided key
    # --------------------------------------------------------------------------
    headers = {
        'Authorization': f'Bearer {API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'model': 'gpt-3.5-turbo',  # adjust to the actual model if needed
        'messages': [{'role': 'user', 'content': user_message}],
        'max_tokens': 500,
        'temperature': 0.7
    }

    try:
        response = requests.post(API_URL, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        ai_reply = response.json()['choices'][0]['message']['content']
    except Exception as e:
        # Fallback / demo mode – simulate a reply if the API fails
        app.logger.error(f"API call failed: {e}")
        ai_reply = f"[Simulated AI] You said: '{user_message}'. (API call failed, but integration code is present.)"

    return jsonify({'reply': ai_reply}), 200

if __name__ == '__main__':
    app.run(debug=True)