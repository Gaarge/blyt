from flask import Flask, request, redirect, url_for, render_template, flash, session, jsonify
from web3 import Web3
import pymysql
import hashlib
import hmac
import random
import string
from datetime import datetime, timedelta, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from eth_account import Account
import secrets
import jwt

# Flask Setup
app = Flask(__name__)
app.secret_key = "supersecretkey"

# MySQL Configuration
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '123',
    'database': 'users',
    'cursorclass': pymysql.cursors.DictCursor
}

# Web3 Setup
web3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"))

# Google OAuth2 Configuration
CLIENT_SECRETS_FILE = "client_secrets.json"
SCOPES = [
    "openid",  # Область для получения основного профиля
    "https://www.googleapis.com/auth/userinfo.email",  # Область для получения email пользователя
    "https://www.googleapis.com/auth/userinfo.profile"  # Область для получения дополнительной информации о пользователе
]
REDIRECT_URI = "https://127.0.0.1:5000/callback"

# JWT Configuration
JWT_SECRET_KEY = "0eda2a7b65ff86183aea31295f62d4e7c09997c78a07a2c5a4ed054520e2851f"  # Секретный ключ для подписи токенов
JWT_ALGORITHM = "HS256" # Алгоритм подписи токенов
JWT_EXPIRATION = 30 # Срок действия токена (в днях)

# Helper Functions
def generate_jwt(user_data):
    payload = {
        "user_id": user_data["id"],
        "email": user_data["email"],
        "nickname": user_data.get("nickname"),
        "exp": datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRATION),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

def verify_jwt(token):
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# Generate random codes
def generate_verification_code():
    return str(random.randint(100000, 999999))

def generate_temporary_password():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=10))

# Email sending
def send_email(to_email, subject, body):
    smtp_server = "smtp.yandex.ru"
    smtp_port = 465
    sender_email = "nft.n@yandex.com"
    sender_password = "ihibahgubydcauzm"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    message = None
    if request.method == 'POST':
        email = request.form.get('email')
        nickname = request.form.get('nickname')
        password = request.form.get('password')

        if not email or not nickname or not password:
            message = "Пожалуйста, заполните все поля."
            return render_template('register.html', message=message)

        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        # Проверяем, существует ли email в таблице users
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            message = "Этот email уже зарегистрирован через Google. Войдите через Google."
            return render_template('register.html', message=message)

        # Проверяем, существует ли email в таблице usersWithEmail
        cursor.execute("SELECT * FROM usersWithEmail WHERE email = %s", (email,))
        if cursor.fetchone():
            message = "Этот email уже зарегистрирован. Войдите через email."
            return render_template('register.html', message=message)

        # Проверяем, существует ли nickname в таблице usersWithEmail
        cursor.execute("SELECT * FROM usersWithEmail WHERE nickname = %s", (nickname,))
        if cursor.fetchone():
            message = "Этот никнейм уже занят. Выберите другой."
            return render_template('register.html', message=message)

        # Генерируем проверочный код
        verification_code = generate_verification_code()
        session['email'] = email
        session['nickname'] = nickname
        session['password'] = password
        session['verification_code'] = verification_code
        session['auth_type'] = 'register'

        send_email(email, "Подтверждение регистрации", f"Ваш код подтверждения: {verification_code}")

        flash("На вашу почту отправлен код подтверждения.")
        return redirect(url_for('verify_email'))

    return render_template('register.html', message=message)


@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        email = session.get('email')
        nickname = session.get('nickname')
        password = session.get('password')  # Извлекаем сохранённый пароль
        input_code = request.form['code']
        stored_code = session.get('verification_code')
        auth_type = session.get('auth_type')

        if not email or not stored_code or input_code != stored_code:
            flash("Неверный код подтверждения. Повторите попытку.")
            return redirect(url_for('verify_email'))

        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        if auth_type == 'register':  # Регистрация
            # Создание кошелька
            account = web3.eth.account.create()
            address = account.address
            private_key = account.key.hex()
            session['private_key'] = private_key

            # Сохранение в таблице
            cursor.execute('''INSERT INTO usersWithEmail (email, nickname, password, wallet_address, created_at)
                              VALUES (%s, %s, %s, %s, %s)''',
                           (email, nickname, password, address, datetime.now()))
            conn.commit()
            user_id = cursor.lastrowid  # Получаем ID нового пользователя
            flash("Регистрация успешна.")

        elif auth_type == 'login':  # Вход
            cursor.execute("SELECT id FROM usersWithEmail WHERE email = %s", (email,))
            user = cursor.fetchone()
            if not user:
                flash("Пользователь не найден. Попробуйте войти снова.")
                return redirect(url_for('login_email'))
            user_id = user['id']
            flash("Вход выполнен успешно.")

        cursor.close()
        conn.close()

        # Генерация JWT
        user_data = {"id": user_id, "email": email, "nickname": nickname, "address": address}
        token = generate_jwt(user_data)

        # Сохранение токена в cookie
        response = redirect(url_for('dashboard'))
        response.set_cookie("access_token", token, httponly=True)
        return response

    return render_template('verify_email.html')




@app.route('/login_email', methods=['GET', 'POST'])
def login_email():
    message = None
    if request.method == 'POST':
        auth = request.form.get('authWithLoginOrNickname')
        password = request.form.get('password')
        print(password)
        print(auth)

        if not auth or not password:
            message = "Пожалуйста, введите email/никнейм и пароль."
            return render_template('login_email.html', message=message)

        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        # Ищем пользователя по email или nickname
        cursor.execute("SELECT * FROM usersWithEmail WHERE email = %s OR nickname = %s", (auth, auth))
        user = cursor.fetchone()

        if not user or user['password'] != password:
            message = "Неверный логин или пароль."
            return render_template('login_email.html', message=message)

        # Сохраняем данные в сессии
        session.clear()  # Очищаем сессию перед сохранением новых данных
        session['email'] = user['email']
        session['nickname'] = user['nickname']
        session['auth_type'] = 'login'
        session['password'] = password  # Сохраняем пароль, если нужно для верификации

        # Генерируем проверочный код и отправляем его
        verification_code = generate_verification_code()
        session['verification_code'] = verification_code

        send_email(user['email'], "Подтверждение входа", f"Ваш код подтверждения: {verification_code}")

        flash("Код подтверждения отправлен на вашу почту.")
        return redirect(url_for('verify_email'))  # Здесь перенаправляем, а не рендерим

    return render_template('login_email.html', message=message)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM usersWithEmail WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            flash("Email не найден.")
            return redirect(url_for('forgot_password'))

        temporary_password = generate_temporary_password()

        # Update password in database
        cursor.execute("UPDATE usersWithEmail SET password = %s WHERE email = %s", (temporary_password, email))
        conn.commit()

        send_email(email, "Временный пароль", f"Ваш временный пароль: {temporary_password}")

        flash("На вашу почту отправлен временный пароль.")
        return redirect(url_for('login_email'))

    return render_template('forgot_password.html')

@app.route('/dashboard')
def dashboard():
    token = request.cookies.get("access_token")
    print(f"Received token: {token}")
    if not token:
        flash("Вы не авторизованы. Выполните вход.")
        return redirect(url_for('login_email'))
    
    # Проверяем токен
    user_data1 = verify_jwt(token)
    if not user_data1:
        flash("Срок действия сессии истёк. Выполните вход.")
        return redirect(url_for('login_email'))

    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()

    # Извлекаем данные пользователя из базы
    cursor.execute("SELECT email, nickname, wallet_address FROM usersWithEmail WHERE email = %s", (user_data1["email"],))
    user_profile = cursor.fetchone()

    if not user_profile:
        cursor.execute("SELECT email, first_name AS nickname, wallet_address FROM users WHERE email = %s", (user_data1["email"],))
        user_profile = cursor.fetchone()

    cursor.close()
    conn.close()

    if not user_profile:
        flash("Пользователь не найден.")
        return redirect(url_for('login_email'))

    user_profile['private_key']=session.get('private_key')
    

    return render_template('dashboard.html', user_data=user_profile)

@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI

    # Генерация URL для авторизации
    auth_url, state = flow.authorization_url(access_type='offline', prompt='consent')

    # Сохранение state для защиты от CSRF-атак
    session['state'] = state
    return redirect(auth_url)


@app.route('/callback')
def callback():
    if 'state' not in session:
        return "Ошибка: отсутствует state. Пожалуйста, повторите попытку."

    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=session['state'])
    flow.redirect_uri = REDIRECT_URI
    authorization_response = request.url

    try:
        flow.fetch_token(authorization_response=authorization_response)
    except Exception as e:
        return f"Ошибка авторизации: {str(e)}"

    credentials = flow.credentials

    # Проверяем токен
    google_request = Request()
    try:
        id_info = id_token.verify_oauth2_token(credentials.id_token, google_request, clock_skew_in_seconds=60)

    except ValueError as e:
        return f"Ошибка проверки токена: {str(e)}"

    if not id_info:
        return "Не удалось подтвердить пользователя через Google."

    google_id = id_info.get("sub")
    email = id_info.get("email")
    first_name = id_info.get("given_name")
    last_name = id_info.get("family_name")

    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()

    # Проверяем, существует ли пользователь с таким google_id
    cursor.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
    user = cursor.fetchone()

    if user:
        print(2222222222)
        session.clear()
        # Генерация JWT
        user_data = {"id": google_id, "email": email, "nickname": first_name, "address": user['wallet_address']}
        token = generate_jwt(user_data)
        # Сохранение токена в cookie
        response = redirect(url_for('dashboard'))
        response.set_cookie("access_token", token, httponly=True)
        return response
    if not user:
        print(333333333333333)
        cursor.execute("SELECT * FROM usersWithEmail WHERE email = %s", (email,))
        user = cursor.fetchone()
    if user:
        print(44444444444444)
        session.clear()
        # Генерация JWT
        user_data = {"id": google_id, "email": email, "nickname": first_name, "address": user['wallet_address']}
        token = generate_jwt(user_data)
        # Сохранение токена в cookie
        response = redirect(url_for('dashboard'))
        response.set_cookie("access_token", token, httponly=True)
        return response
    print(555555555555555555555)
    # Создаем нового пользователя
    account = web3.eth.account.create()
    address = account.address
    private_key = account.key.hex()
    

    cursor.execute('''INSERT INTO users (google_id, email, first_name, last_name, wallet_address, created_at)
                      VALUES (%s, %s, %s, %s, %s, %s)''',
                   (google_id, email, first_name, last_name, address, datetime.now()))
    conn.commit()

    session.clear()
    session['email'] = email
    session['private_key'] = private_key

    cursor.close()
    conn.close()
    # Генерация JWT
    user_data = {"id": google_id, "email": email, "nickname": first_name, "address": address}
    token = generate_jwt(user_data)
    print(f"Generated token: {token}")
    # Сохранение токена в cookie
    response = redirect(url_for('dashboard'))
    response.set_cookie("access_token", token, httponly=True)
    return response

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

#           Для телеги:

BOT_TOKEN = "7945721884:AAGlVRp4-G9iwySAc-JpqgGxqLyOXeUSwWQ"

# Функция для генерации криптокошелька
def create_wallet():
    Account.enable_unaudited_hdwallet_features()
    wallet = Account.create(secrets.token_hex(32))
    private_key = wallet.key.hex()
    address = wallet.address
    return address, private_key

# Функция для проверки подписи Telegram
def verify_telegram_auth(data, bot_token):
    auth_data = {k: v for k, v in data.items() if k != 'hash'}
    sorted_data = "\n".join([f"{k}={v}" for k, v in sorted(auth_data.items())])
    secret_key = hashlib.sha256(bot_token.encode()).digest()
    calculated_hash = hmac.new(secret_key, sorted_data.encode(), hashlib.sha256).hexdigest()
    return calculated_hash == data.get('hash')

@app.route('/auth', methods=['GET'])
def auth():
    data = request.args.to_dict()  # Получаем параметры из URL
    if not verify_telegram_auth(data, BOT_TOKEN):
        return "Invalid authentication", 403

    # Извлекаем данные пользователя из Telegram
    telegram_id = data.get('id')
    first_name = data.get('first_name', '')
    last_name = data.get('last_name', '')
    username = data.get('username', '')

    # Генерация криптокошелька
    address, private_key = create_wallet()

    # Сохраняем данные в таблицу `telegram_users`
    try:
        connection = pymysql.connect(**db_config)
        with connection.cursor() as cursor:
            sql = """
            INSERT INTO telegram_users (telegram_id, first_name, last_name, username, address)
            VALUES (%s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE first_name=%s, last_name=%s, username=%s
            """
            cursor.execute(sql, (telegram_id, first_name, last_name, username, address, first_name, last_name, username))
        connection.commit()
    except Exception as e:
        return f"Database error: {str(e)}", 500
    finally:
        connection.close()

    # Перенаправляем на страницу dashboard
    user_data = {
        'nickname': first_name or username,
        'wallet_address': address,
        'private_key': private_key
    }
    return render_template('dashboard.html', user_data=user_data)



if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))