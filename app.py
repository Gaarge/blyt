from flask import Flask, request, redirect, url_for, render_template, flash, session, request
from web3 import Web3
import pymysql
import random
import string
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2 import id_token
<<<<<<< HEAD
from web3 import Web3
import os
import pymysql  # Изменили на pymysql
from datetime import datetime
=======
>>>>>>> 47704b1 (login with password)


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

# Google API параметры
CLIENT_SECRETS_FILE = "client_secrets.json"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"]
REDIRECT_URI = "https://localhost:5000/callback"

# Web3 Setup
web3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"))

<<<<<<< HEAD
# Настройка MySQL
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '123',
    'database': 'users',
    'cursorclass': pymysql.cursors.DictCursor  # Добавили курсор для удобства работы с данными
}

def init_db():
    try:
        conn = pymysql.connect(**db_config)
        print("Подключение к базе данных успешно!")
    except pymysql.MySQLError as err:
        print(f"Ошибка подключения: {err}")

=======
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
    if request.method == 'POST':
        email = request.form['email']
        nickname = request.form['nickname']
        password = request.form['password']

        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        # Check if email exists in users
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            flash("Этот email уже зарегистрирован через Google.")
            return redirect(url_for('login'))

        # Check if email exists in usersWithEmail
        cursor.execute("SELECT * FROM usersWithEmail WHERE email = %s", (email,))
        if cursor.fetchone():
            flash("Этот email уже зарегистрирован.")
            return redirect(url_for('login_email'))

        # Check if nickname exists in usersWithEmail
        cursor.execute("SELECT * FROM usersWithEmail WHERE nickname = %s", (nickname,))
        if cursor.fetchone():
            flash("Этот никнейм уже занят. Выберите другой.")
            return redirect(url_for('register'))

        verification_code = generate_verification_code()
        session['verification_code'] = verification_code
        session['email'] = email
        session['nickname'] = nickname
        session['password'] = password

        send_email(email, "Подтверждение регистрации", f"Ваш код подтверждения: {verification_code}")

        flash("На вашу почту отправлен код подтверждения.")
        return redirect(url_for('verify_email'))

    return render_template('register.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        email = session.get('email')
        nickname = session.get('nickname')
        input_code = request.form['code']
        stored_code = session.get('verification_code')
        auth_type = session.get('auth_type')  # Проверяем, вход это или регистрация

        if not email or not stored_code or input_code != stored_code:
            flash("Неверный код подтверждения. Повторите попытку.")
            return redirect(url_for('verify_email'))

        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        if auth_type == 'register':  # Обработка регистрации
            password = session.get('password')

            # Создаем кошелек
            account = web3.eth.account.create()
            address = account.address
            private_key = account.key.hex()

            # Сохраняем нового пользователя
            cursor.execute('''INSERT INTO usersWithEmail (email, nickname, password, wallet_address, private_key, created_at)
                              VALUES (%s, %s, %s, %s, %s, %s)''',
                           (email, nickname, password, address, private_key, datetime.now()))
            conn.commit()
            flash("Регистрация успешна.")
        elif auth_type == 'login':  # Обработка входа
            flash("Вход выполнен успешно.")

        cursor.close()
        conn.close()

        # Перенаправление в личный кабинет
        return redirect(url_for('dashboard'))

    return render_template('verify_email.html')


@app.route('/login_email', methods=['GET', 'POST'])
def login_email():
    if request.method == 'POST':
        auth = request.form['authWithLoginOrPassword']
        password = request.form['password']

        conn = pymysql.connect(**db_config)
        cursor = conn.cursor()

        # Ищем пользователя по email или nickname
        cursor.execute("SELECT * FROM usersWithEmail WHERE email = %s OR nickname = %s", (auth, auth))
        user = cursor.fetchone()

        if not user or user['password'] != password:
            flash("Неверный логин или пароль.")
            return redirect(url_for('login_email'))

        # Сохраняем данные в сессии
        session.clear()
        session['email'] = user['email']
        session['nickname'] = user['nickname']
        session['auth_type'] = 'login'  # Указываем, что это вход, а не регистрация

        # Генерируем проверочный код и отправляем его
        verification_code = generate_verification_code()
        session['verification_code'] = verification_code

        send_email(user['email'], "Подтверждение входа", f"Ваш код подтверждения: {verification_code}")

        flash("Код подтверждения отправлен на вашу почту.")
        return redirect(url_for('verify_email'))

    return render_template('login_email.html')


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
    email = session.get('email')
    if not email:
        flash("Вы не авторизованы. Выполните вход.")
        return redirect(url_for('login_email'))

    conn = pymysql.connect(**db_config)
>>>>>>> 47704b1 (login with password)
    cursor = conn.cursor()

    # Проверяем в таблице usersWithEmail
    cursor.execute("SELECT email, nickname, wallet_address, private_key FROM usersWithEmail WHERE email = %s", (email,))
    user_data = cursor.fetchone()
    app.logger.debug(f"Data from usersWithEmail for {email}: {user_data}")

    if not user_data:
        # Проверяем в таблице users
        cursor.execute("SELECT email, first_name AS nickname, wallet_address, private_key FROM users WHERE email = %s", (email,))
        user_data = cursor.fetchone()
        app.logger.debug(f"Data from users for {email}: {user_data}")

    cursor.close()
    conn.close()

    if not user_data:
        flash("Пользователь не найден.")
        return redirect(url_for('login_email'))

    return render_template('dashboard.html', user_data=user_data)


@app.route('/login')
def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI
    auth_url, state = flow.authorization_url()
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
        id_info = id_token.verify_oauth2_token(credentials.id_token, google_request)
    except ValueError as e:
        return f"Ошибка проверки токена: {str(e)}"

    if not id_info:
        return "Не удалось подтвердить пользователя через Google."

    google_id = id_info.get("sub")
    email = id_info.get("email")
    first_name = id_info.get("given_name")
    last_name = id_info.get("family_name")

<<<<<<< HEAD
    # Подключаемся к базе данных
=======
>>>>>>> 47704b1 (login with password)
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()

    # Проверяем, существует ли пользователь с таким google_id
    cursor.execute("SELECT * FROM users WHERE google_id = %s", (google_id,))
    user = cursor.fetchone()

    if user:
<<<<<<< HEAD
        # Если пользователь уже существует, выводим его данные
        wallet_info = {
            "first_name": user['first_name'],
            "last_name": user['last_name'],
            "email": user['email'],
            "wallet_address": user['wallet_address'],
            "private_key": user['private_key'],
            "created_at": user['created_at']
        }
        return render_template("dashboard.html", user_data=wallet_info)
=======
        # Очищаем сессию и устанавливаем новые данные
        session.clear()
        session['email'] = user['email']
        flash("Вход через Google успешен.")
        return redirect(url_for('dashboard'))
>>>>>>> 47704b1 (login with password)

    # Создаем нового пользователя
    account = web3.eth.account.create()
    address = account.address
    private_key = account.key.hex()

    cursor.execute('''INSERT INTO users (google_id, email, first_name, last_name, wallet_address, private_key, created_at)
                      VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                   (google_id, email, first_name, last_name, address, private_key, datetime.now()))
    conn.commit()

    # Устанавливаем данные сессии
    session.clear()
    session['email'] = email

    cursor.close()
    conn.close()

    flash("Регистрация через Google успешна.")
    return redirect(url_for('dashboard'))


<<<<<<< HEAD
if __name__ == "__main__":
    print("1211")
    init_db()
    print("12")
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000)
=======

if __name__ == '__main__':
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'))
>>>>>>> 47704b1 (login with password)
