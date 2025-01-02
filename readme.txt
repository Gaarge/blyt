Чтобы все зависимости для питона сделать: "pip install -r requirements.txt"


База данных:
CREATE DATABASE users;

USE users;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    google_id VARCHAR(255) UNIQUE,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    email VARCHAR(255),
    wallet_address VARCHAR(255),
    private_key TEXT,
    created_at TIMESTAMP
);
