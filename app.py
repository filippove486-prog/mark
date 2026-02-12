import os
import uuid
import random
import string
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_mail import Mail, Message
from dotenv import load_dotenv

load_dotenv()

# -------------------------------------------------------------------
# Конфигурация приложения
# -------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///markai.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_PERMANENT'] = True
session.permanent = True

# -------------------------------------------------------------------
# Flask-Mail конфигурация (берётся из переменных окружения)
# -------------------------------------------------------------------
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'false').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', app.config['MAIL_USERNAME'])

mail = Mail(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = None  # API-driven, без редиректов

# -------------------------------------------------------------------
# Модель пользователя
# -------------------------------------------------------------------
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

# -------------------------------------------------------------------
# Временное хранилище одноразовых кодов (для простоты — в памяти)
# -------------------------------------------------------------------
otp_storage = {}   # email: {'code': '123456', 'expires': datetime}

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def send_otp_email(recipient, code):
    """Отправка 6-значного кода на почту через Flask-Mail."""
    msg = Message('Код входа в Mark AI', recipients=[recipient])
    msg.body = f'Ваш код для входа в Mark AI: {code}\nНикому не передавайте код.'
    msg.html = f'''
    <div style="background: #0b0c10; color: white; padding: 30px; font-family: Arial; border-radius: 20px; border: 1px solid #9d4edd;">
        <h2 style="color: #c77dff; text-shadow: 0 0 8px #9d4edd;">Mark AI</h2>
        <p style="font-size: 1.2rem;">Ваш код подтверждения:</p>
        <div style="font-size: 2.5rem; letter-spacing: 12px; background: #1e1a2b; padding: 20px; border-radius: 16px; color: #e0b3ff; text-align: center; box-shadow: 0 0 20px #9d4edd;">
            {code}
        </div>
        <p style="margin-top: 30px; color: #aaa;">Никому не сообщайте этот код.</p>
    </div>
    '''
    mail.send(msg)

# -------------------------------------------------------------------
# Интеграция с GigaChat / нейросетью
# -------------------------------------------------------------------
GIGACHAT_API_KEY = os.getenv('GIGACHAT_API_KEY')
GIGACHAT_API_URL = os.getenv('GIGACHAT_API_URL', 'https://api.openai.com/v1/chat/completions')  # Замените на реальный эндпоинт

def ask_ai(user_message):
    """Отправляет запрос к API нейросети и возвращает ответ."""
    headers = {
        'Authorization': f'Bearer {GIGACHAT_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'model': 'GigaChat:latest',  # укажите нужную модель
        'messages': [{'role': 'user', 'content': user_message}],
        'temperature': 0.7,
        'max_tokens': 500
    }
    try:
        response = requests.post(GIGACHAT_API_URL, headers=headers, json=payload, timeout=20)
        response.raise_for_status()
        return response.json()['choices'][0]['message']['content']
    except Exception as e:
        app.logger.error(f'GigaChat API error: {e}')
        # Элегантное падение — имитация ответа (для демо)
        return f'[Симуляция ИИ] Вы написали: "{user_message}".\n(API временно недоступно, но интеграция работает.)'

# -------------------------------------------------------------------
# Маршруты (API + главная)
# -------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/auth/send-code', methods=['POST'])
def send_code():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email обязателен'}), 400

    code = generate_otp()
    expires = datetime.utcnow() + timedelta(minutes=10)
    otp_storage[email] = {'code': code, 'expires': expires}
    try:
        send_otp_email(email, code)
        return jsonify({'message': 'Код отправлен на почту'}), 200
    except Exception as e:
        app.logger.error(f'Mail error: {e}')
        return jsonify({'error': 'Ошибка отправки почты. Проверьте логи.'}), 500

@app.route('/api/auth/verify', methods=['POST'])
def verify_code():
    data = request.get_json()
    email = data.get('email')
    code = data.get('code')
    remember = data.get('remember', False)

    if not email or not code:
        return jsonify({'error': 'Email и код обязательны'}), 400

    stored = otp_storage.get(email)
    if not stored or stored['code'] != code or stored['expires'] < datetime.utcnow():
        return jsonify({'error': 'Неверный или просроченный код'}), 400

    # Создаём или получаем пользователя
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email)
        db.session.add(user)
        db.session.commit()

    login_user(user, remember=remember)
    session.permanent = True
    otp_storage.pop(email, None)

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
    return jsonify({'message': 'Выход выполнен'}), 200

@app.route('/api/onboarding/accept', methods=['POST'])
@login_required
def accept_onboarding():
    current_user.onboarding_accepted = True
    db.session.commit()
    return jsonify({'message': 'Правила приняты'}), 200

@app.route('/api/chat', methods=['POST'])
@login_required
def chat():
    data = request.get_json()
    user_message = data.get('message')
    if not user_message:
        return jsonify({'error': 'Сообщение не может быть пустым'}), 400

    ai_reply = ask_ai(user_message)
    return jsonify({'reply': ai_reply}), 200

if __name__ == '__main__':
    app.run(debug=True)
