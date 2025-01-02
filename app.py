from flask import Flask, redirect, url_for, session, request, render_template
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from web3 import Web3
import os
import pymysql  # Изменили на pymysql
from datetime import datetime

app = Flask(__name__)
user_data = {}
app.secret_key = os.urandom(24)
app.config['SESSION_COOKIE_SECURE'] = True

# Google API параметры
CLIENT_SECRETS_FILE = "client_secrets.json"
SCOPES = ["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"]
REDIRECT_URI = "https://localhost:5000/callback"

# Настройка Web3
web3 = Web3(Web3.HTTPProvider("https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"))

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

    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        google_id VARCHAR(255) UNIQUE,
                        first_name VARCHAR(255),
                        last_name VARCHAR(255),
                        email VARCHAR(255),
                        wallet_address VARCHAR(255),
                        private_key TEXT,
                        created_at TIMESTAMP)''')
    conn.commit()
    cursor.close()
    conn.close()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI
    auth_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(auth_url)

@app.route("/callback")
def callback():
    if "state" not in session:
        return "Ошибка: отсутствует state. Пожалуйста, повторите попытку."

    flow = Flow.from_client_secrets_file(CLIENT_SECRETS_FILE, scopes=SCOPES, state=session["state"])
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

    # Подключаемся к базе данных
    conn = pymysql.connect(**db_config)
    cursor = conn.cursor()

    # Проверяем, существует ли пользователь с таким google_id
    cursor.execute('''SELECT * FROM users WHERE google_id = %s''', (google_id,))
    user = cursor.fetchone()

    if user:
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

    # Если пользователя нет, создаем новый кошелек
    account = web3.eth.account.create()
    address = account.address
    private_key = account.key.hex()

    # Сохраняем нового пользователя в базу данных
    cursor.execute('''INSERT INTO users (google_id, first_name, last_name, email, wallet_address, private_key, created_at)
                      VALUES (%s, %s, %s, %s, %s, %s, %s)''',
                   (google_id, first_name, last_name, email, address, private_key, datetime.now()))
    conn.commit()

    # Закрытие соединения с БД
    cursor.close()
    conn.close()

    # Возвращаем созданные данные
    wallet_info = {
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "wallet_address": address,
        "private_key": private_key
    }

    return render_template("dashboard.html", user_data=wallet_info)

if __name__ == "__main__":
    print("1211")
    init_db()
    print("12")
    app.run(debug=True, ssl_context=('cert.pem', 'key.pem'), host='0.0.0.0', port=5000)
