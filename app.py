import os
import uuid
import requests
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

# -------------------------------------------------------------------
# Конфигурация приложения
# -------------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_PERMANENT'] = True  # конфиг, безопасен вне контекста

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = None  # API-driven

# -------------------------------------------------------------------
# Модель пользователя
# -------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    onboarding_accepted = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

# -------------------------------------------------------------------
# Интеграция с GigaChat / нейросетью
# -------------------------------------------------------------------
GIGACHAT_API_KEY = os.getenv('MDE5YzRjMTctZmQ1NC03YWQxLWFmMzAtN2YxMjRlODYxYzJiOjUyM2RhNGZjLTEyZWItNDk5NS1hN2NhLWE3MWQyNGRlZDkzNw==')
GIGACHAT_API_URL = os.getenv('https://gigachat.devices.sberbank.ru/api/v1/chat/completions')  # замените на реальный эндпоинт

def ask_ai(user_message):
    """Отправляет запрос к API нейросети и возвращает ответ."""
    headers = {
        'Authorization': f'Bearer {GIGACHAT_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'model': 'GigaChat:latest',
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
        return f'[Симуляция ИИ] Вы написали: "{user_message}".\n(API временно недоступно, но интеграция работает.)'

# -------------------------------------------------------------------
# Маршруты (API + главная)
# -------------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

# -------------------- РЕГИСТРАЦИЯ --------------------
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password')
    password_confirm = data.get('password_confirm')

    if not username or not password or not password_confirm:
        return jsonify({'error': 'Все поля обязательны'}), 400
    if password != password_confirm:
        return jsonify({'error': 'Пароли не совпадают'}), 400
    if len(password) < 6:
        return jsonify({'error': 'Пароль должен быть не менее 6 символов'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Пользователь с таким логином уже существует'}), 400

    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    login_user(user, remember=True)
    session.permanent = True   # устанавливаем постоянную сессию

    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'onboarding_accepted': user.onboarding_accepted
        }
    }), 200

# -------------------- ВХОД --------------------
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Логин и пароль обязательны'}), 400

    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'error': 'Неверный логин или пароль'}), 400

    login_user(user, remember=True)
    session.permanent = True

    return jsonify({
        'user': {
            'id': user.id,
            'username': user.username,
            'onboarding_accepted': user.onboarding_accepted
        }
    }), 200

# -------------------- ТЕКУЩИЙ ПОЛЬЗОВАТЕЛЬ --------------------
@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    return jsonify({
        'user': {
            'id': current_user.id,
            'username': current_user.username,
            'onboarding_accepted': current_user.onboarding_accepted
        }
    }), 200

# -------------------- ВЫХОД --------------------
@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Выход выполнен'}), 200

# -------------------- ПРИНЯТИЕ ПРАВИЛ --------------------
@app.route('/api/onboarding/accept', methods=['POST'])
@login_required
def accept_onboarding():
    current_user.onboarding_accepted = True
    db.session.commit()
    return jsonify({'message': 'Правила приняты'}), 200

# -------------------- ЧАТ С ИИ --------------------
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

