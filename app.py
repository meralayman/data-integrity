from flask import Flask, request, jsonify, send_file
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
import mysql.connector
import bcrypt, pyotp, qrcode, io

# Flask App Setup
app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = "your_jwt_secret_key"
jwt = JWTManager(app)

# Database Configuration
DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'auth_db'
}

# Function to connect to MySQL
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# Function to initialize database and tables
def init_db():
    conn = mysql.connector.connect(host=DB_CONFIG['host'], user=DB_CONFIG['user'], password=DB_CONFIG['password'])
    cursor = conn.cursor()
    
    # Create database if not exists
    cursor.execute("CREATE DATABASE IF NOT EXISTS auth_db")
    conn.commit()
    
    # Use the database
    cursor.execute("USE auth_db")

    # Create Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password VARCHAR(256) NOT NULL,
            twofa_secret VARCHAR(256) NOT NULL
        )
    """)

    # Create Products Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            description VARCHAR(255),
            price DECIMAL(10,2) NOT NULL,
            quantity INT NOT NULL
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()

# Call DB Initialization on Startup
init_db()

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    secret = pyotp.random_base32()

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)", 
                       (username, hashed_pw.decode('utf-8'), secret))
        conn.commit()
    except:
        return jsonify({"message": "User already exists"}), 400
    finally:
        cursor.close()
        conn.close()

    return jsonify({"message": "User registered", "twofa_secret": secret}), 201

# Generate QR Code for 2FA
@app.route('/generate_qr/<username>', methods=['GET'])
def generate_qr(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user:
        return jsonify({"message": "User not found"}), 404

    secret = user[0]
    otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="FlaskAuthApp")

    qr = qrcode.make(otp_uri)
    img_io = io.BytesIO()
    qr.save(img_io, 'PNG')
    img_io.seek(0)

    return send_file(img_io, mimetype='image/png')

# Login and Prompt for 2FA
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT password, twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user[0].encode('utf-8')):
        return jsonify({"message": "Invalid credentials"}), 401

    return jsonify({"message": "Enter 2FA Code", "username": username}), 200

# Verify 2FA and Generate JWT Token
@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    data = request.json
    username = data.get('username')
    code = data.get('code')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user or not pyotp.TOTP(user[0]).verify(code):
        return jsonify({"message": "Invalid 2FA code"}), 401

    access_token = create_access_token(identity=username, expires_delta=False)
    return jsonify({"token": access_token}), 200

# CRUD Operations for Products (JWT-Protected)

@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    data = request.json
    name, description, price, quantity = data.get('name'), data.get('description'), data.get('price'), data.get('quantity')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)", 
                   (name, description, price, quantity))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Product added"}), 201

@app.route('/products', methods=['GET'])
@jwt_required()
def get_products():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    cursor.close()
    conn.close()

    return jsonify(products), 200

@app.route('/products/<int:product_id>', methods=['PUT'])
@jwt_required()
def update_product(product_id):
    data = request.json
    name, description, price, quantity = data.get('name'), data.get('description'), data.get('price'), data.get('quantity')

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE products SET name=%s, description=%s, price=%s, quantity=%s WHERE id=%s",
                   (name, description, price, quantity, product_id))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Product updated"}), 200

@app.route('/products/<int:product_id>', methods=['DELETE'])
@jwt_required()
def delete_product(product_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM products WHERE id=%s", (product_id,))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Product deleted"}), 200
@app.route('/products/<int:product_id>', methods=['GET'])
@jwt_required()
def get_product(product_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()
    cursor.close()
    conn.close()

    if not product:
        return jsonify({"message": "Product not found"}), 404

    return jsonify(product), 200

# Run Flask App
if __name__ == '__main__':
    app.run(debug=True)
 