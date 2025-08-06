from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from datetime import datetime, timezone

app = Flask(__name__)
app.secret_key = os.urandom(24)
DB_FILE = "secure_passwords.db"

# ---------- Encryption Utilities ----------

def derive_key(script_password: str, private_key: str, salt: bytes) -> bytes:
    combined = (script_password + private_key).encode()
    key = hashlib.pbkdf2_hmac('sha256', combined, salt, 100000)
    return base64.urlsafe_b64encode(key)

def encrypt_password(password: str, script_password: str, private_key: str) -> tuple:
    salt = os.urandom(16)
    key = derive_key(script_password, private_key, salt)
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    return encrypted.decode(), base64.b64encode(salt).decode()

def decrypt_password(encrypted_password: str, salt_b64: str, script_password: str, private_key: str) -> str:
    salt = base64.b64decode(salt_b64)
    encrypted_password = encrypted_password.encode()
    key = derive_key(script_password, private_key, salt)
    f = Fernet(key)
    decrypted = f.decrypt(encrypted_password)
    return decrypted.decode()

# ---------- Database Setup ----------

def create_database():
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                salt TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_accessed TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, label)
            )
        ''')
        conn.commit()

def get_user_id(username, password):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=? AND password_hash=?", (username, password_hash))
        result = c.fetchone()
        return result[0] if result else None

def register_user(username, password):
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                      (username, password_hash, created_at))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

# ---------- Routes ----------

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user_id = get_user_id(username, password)
        if user_id:
            session["user_id"] = user_id
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if register_user(username, password):
            flash("User registered. You can log in now.", "success")
            return redirect(url_for("login"))
        else:
            flash("Username already taken.", "danger")
    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login"))
    with sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("SELECT label, created_at, last_accessed FROM passwords WHERE user_id=?", (session["user_id"],))
        rows = c.fetchall()
    return render_template("dashboard.html", passwords=rows, username=session["username"])

@app.route("/add", methods=["GET", "POST"])
def add():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        label = request.form["label"]
        password = request.form["password"]
        private_key = request.form["private_key"]
        script_password = request.form["script_password"]
        encrypted, salt = encrypt_password(password, script_password, private_key)
        now = datetime.now(timezone.utc).isoformat()
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            try:
                c.execute('''
                    INSERT OR REPLACE INTO passwords (user_id, label, encrypted_password, salt, created_at)
                    VALUES (?, ?, ?, ?, ?)
                ''', (session["user_id"], label, encrypted, salt, now))
                conn.commit()
                flash("Password stored.", "success")
                return redirect(url_for("dashboard"))
            except Exception as e:
                flash("Failed to store password.", "danger")
    return render_template("add.html")

@app.route("/view/<label>", methods=["GET", "POST"])
def view(label):
    if "user_id" not in session:
        return redirect(url_for("login"))
    if request.method == "POST":
        private_key = request.form["private_key"]
        script_password = request.form["script_password"]
        with sqlite3.connect(DB_FILE) as conn:
            c = conn.cursor()
            c.execute("SELECT encrypted_password, salt, created_at, last_accessed FROM passwords WHERE user_id=? AND label=?",
                      (session["user_id"], label))
            row = c.fetchone()
            if not row:
                flash("Label not found", "danger")
                return redirect(url_for("dashboard"))
            try:
                decrypted = decrypt_password(row[0], row[1], script_password, private_key)
                now = datetime.now(timezone.utc).isoformat()
                c.execute("UPDATE passwords SET last_accessed=? WHERE user_id=? AND label=?",
                          (now, session["user_id"], label))
                conn.commit()
                return render_template("view.html", label=label, password=decrypted,
                                       created_at=row[2], last_accessed=row[3])
            except:
                flash("Failed to decrypt. Wrong credentials?", "danger")
    return render_template("view.html", label=label)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Run ----------

if __name__ == "__main__":
    create_database()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

