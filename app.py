import os
import sqlite3
import threading
import webbrowser
import json
import re
from flask import Flask, request, render_template, jsonify, url_for, session, redirect, send_file,flash
from groq import Groq
import pymysql
import psycopg2
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import bcrypt
import stripe
from authlib.integrations.flask_client import OAuth
import logging
import secrets
from dotenv import load_dotenv
import requests
import random
import string

# Load environment variables from .env file
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# ---------- Config & Keys ----------
GROQ_API_KEY = os.environ.get("GROQ_API_KEY")
if not GROQ_API_KEY:
    logger.warning("GROQ_API_KEY not set in environment variables! Groq features will not work.")
    groq_client = None
else:
    try:
        groq_client = Groq(api_key=GROQ_API_KEY)
        logger.info("Groq client initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize Groq client: {str(e)}")
        groq_client = None

STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET")
if not STRIPE_SECRET_KEY:
    print("Warning: STRIPE_SECRET_KEY not set. Stripe endpoints will raise errors until set.")
else:
    stripe.api_key = STRIPE_SECRET_KEY

# OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
GITHUB_CLIENT_ID = os.environ.get("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.environ.get("GITHUB_CLIENT_SECRET")

# Resend API Configuration
RESEND_API_KEY = os.environ.get("RESEND_API_KEY")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "send@support.tokenmap.io")

DB_FOLDER = "databases"
os.makedirs(DB_FOLDER, exist_ok=True)
app = Flask(__name__, static_folder="static", template_folder=".")
app.secret_key = os.urandom(24)  # Required for sessions
app.config["UPLOAD_FOLDER"] = DB_FOLDER
# OAuth setup
oauth = OAuth(app)

# Google OAuth configuration
google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile'}
)

github = oauth.register(
    name='github',
    client_id=GITHUB_CLIENT_ID,
    client_secret=GITHUB_CLIENT_SECRET,
    authorize_url='https://github.com/login/oauth/authorize',
    access_token_url='https://github.com/login/oauth/access_token',
    client_kwargs={'scope': 'user:email'},
    api_base_url='https://api.github.com/'
)

# ---------- User Database Setup ----------
USER_DB = "users.db"

def init_user_db():
    with sqlite3.connect(USER_DB) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                subscription_tier TEXT DEFAULT 'free',
                email_verified INTEGER DEFAULT 0,
                verification_code TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_dbs (
                user_id INTEGER,
                db_name TEXT,
                db_type TEXT,
                db_path TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)
        conn.commit()

init_user_db()

# ---------- Create demo.db ----------
def create_demo_db():
    db_path = os.path.join(DB_FOLDER, "")
    with sqlite3.connect(db_path) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA case_sensitive_like = OFF;")
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS departments (
                department_id INTEGER PRIMARY KEY,
                department_name TEXT NOT NULL,
                location TEXT
            );

            CREATE TABLE IF NOT EXISTS instructors (
                instructor_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                department_id INTEGER,
                email TEXT,
                FOREIGN KEY (department_id) REFERENCES departments(department_id)
            );

            CREATE TABLE IF NOT EXISTS students (
                student_id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                major_id INTEGER,
                year INTEGER,
                email TEXT,
                FOREIGN KEY (major_id) REFERENCES departments(department_id)
            );

            CREATE TABLE IF NOT EXISTS courses (
                course_id INTEGER PRIMARY KEY,
                course_name TEXT NOT NULL,
                department_id INTEGER,
                credits INTEGER,
                instructor_id INTEGER,
                FOREIGN KEY (department_id) REFERENCES departments(department_id),
                FOREIGN KEY (instructor_id) REFERENCES instructors(instructor_id)
            );

            CREATE TABLE IF NOT EXISTS enrollments (
                enrollment_id INTEGER PRIMARY KEY,
                student_id INTEGER,
                course_id INTEGER,
                semester TEXT,
                grade TEXT,
                FOREIGN KEY (student_id) REFERENCES students(student_id),
                FOREIGN KEY (course_id) REFERENCES courses(course_id)
            );

            -- Insert data into departments (5 rows)
            INSERT OR IGNORE INTO departments (department_id, department_name, location) VALUES
            (1, 'Computer Science', 'Building A'),
            (2, 'Mathematics', 'Building B'),
            (3, 'Physics', 'Building C'),
            (4, 'History', 'Building D'),
            (5, 'Biology', 'Building E');

            -- Insert data into instructors (10 rows)
            INSERT OR IGNORE INTO instructors (instructor_id, name, department_id, email) VALUES
            (1, 'Dr. Alice Smith', 1, 'alice.smith@university.edu'),
            (2, 'Dr. Bob Johnson', 1, 'bob.johnson@university.edu'),
            (3, 'Dr. Carol White', 2, 'carol.white@university.edu'),
            (4, 'Dr. David Brown', 2, 'david.brown@university.edu'),
            (5, 'Dr. Emma Davis', 3, 'emma.davis@university.edu'),
            (6, 'Dr. Frank Wilson', 3, 'frank.wilson@university.edu'),
            (7, 'Dr. Grace Lee', 4, 'grace.lee@university.edu'),
            (8, 'Dr. Henry Martin', 4, 'henry.martin@university.edu'),
            (9, 'Dr. Isabella Clark', 5, 'isabella.clark@university.edu'),
            (10, 'Dr. James Taylor', 5, 'james.taylor@university.edu');

            -- Insert data into students (20 rows)
            INSERT OR IGNORE INTO students (student_id, name, major_id, year, email) VALUES
            (1, 'John Doe', 1, 1, 'john.doe@university.edu'),
            (2, 'Jane Roe', 1, 2, 'jane.roe@university.edu'),
            (3, 'Michael Chen', 1, 3, 'michael.chen@university.edu'),
            (4, 'Sarah Kim', 1, 4, 'sarah.kim@university.edu'),
            (5, 'Emily Zhang', 2, 1, 'emily.zhang@university.edu'),
            (6, 'David Patel', 2, 2, 'david.patel@university.edu'),
            (7, 'Laura Nguyen', 2, 3, 'laura.nguyen@university.edu'),
            (8, 'James Lee', 2, 4, 'james.lee@university.edu'),
            (9, 'Anna Brown', 3, 1, 'anna.brown@university.edu'),
            (10, 'Robert Wilson', 3, 2, 'robert.wilson@university.edu'),
            (11, 'Lisa Davis', 3, 3, 'lisa.davis@university.edu'),
            (12, 'Mark Taylor', 3, 4, 'mark.taylor@university.edu'),
            (13, 'Sophie Adams', 4, 1, 'sophie.adams@university.edu'),
            (14, 'Thomas Clark', 4, 2, 'thomas.clark@university.edu'),
            (15, 'Olivia Lewis', 4, 3, 'olivia.lewis@university.edu'),
            (16, 'William Walker', 4, 4, 'william.walker@university.edu'),
            (17, 'Mia Harris', 5, 1, 'mia.harris@university.edu'),
            (18, 'Ethan Martinez', 5, 2, 'ethan.martinez@university.edu'),
            (19, 'Ava Thompson', 5, 3, 'ava.thompson@university.edu'),
            (20, 'Noah White', 5, 4, 'noah.white@university.edu');

            -- Insert data into courses (15 rows)
            INSERT OR IGNORE INTO courses (course_id, course_name, department_id, credits, instructor_id) VALUES
            (1, 'Introduction to Programming', 1, 3, 1),
            (2, 'Data Structures', 1, 4, 2),
            (3, 'Algorithms', 1, 4, 1),
            (4, 'Calculus I', 2, 4, 3),
            (5, 'Linear Algebra', 2, 3, 4),
            (6, 'Differential Equations', 2, 4, 3),
            (7, 'Mechanics', 3, 4, 5),
            (8, 'Quantum Physics', 3, 3, 6),
            (9, 'Electromagnetism', 3, 4, 5),
            (10, 'World History', 4, 3, 7),
            (11, 'Modern History', 4, 3, 8),
            (12, 'Ancient Civilizations', 4, 3, 7),
            (13, 'Genetics', 5, 4, 9),
            (14, 'Ecology', 5, 3, 10),
            (15, 'Cell Biology', 5, 4, 9);

            -- Insert data into enrollments (30 rows)
            INSERT OR IGNORE INTO enrollments (enrollment_id, student_id, course_id, semester, grade) VALUES
            (1, 1, 1, 'Fall 2024', 'A'),
            (2, 1, 2, 'Spring 2025', 'B+'),
            (3, 2, 1, 'Fall 2024', 'A-'),
            (4, 2, 3, 'Spring 2025', 'B'),
            (5, 3, 2, 'Fall 2024', 'A'),
            (6, 3, 3, 'Spring 2025', 'A-'),
            (7, 4, 1, 'Fall 2024', 'B+'),
            (8, 4, 2, 'Spring 2025', 'A'),
            (9, 5, 4, 'Fall 2024', 'A'),
            (10, 5, 5, 'Spring 2025', 'B'),
            (11, 6, 4, 'Fall 2024', 'A-'),
            (12, 6, 6, 'Spring 2025', 'B+'),
            (13, 7, 5, 'Fall 2024', 'A'),
            (14, 7, 6, 'Spring 2025', 'A-'),
            (15, 8, 4, 'Fall 2024', 'B'),
            (16, 8, 5, 'Spring 2025', 'A'),
            (17, 9, 7, 'Fall 2024', 'A'),
            (18, 9, 8, 'Spring 2025', 'B+'),
            (19, 10, 7, 'Fall 2024', 'A-'),
            (20, 10, 9, 'Spring 2025', 'B'),
            (21, 11, 8, 'Fall 2024', 'A'),
            (22, 11, 9, 'Spring 2025', 'A-'),
            (23, 12, 7, 'Fall 2024', 'B+'),
            (24, 12, 8, 'Spring 2025', 'A'),
            (25, 13, 10, 'Fall 2024', 'A'),
            (26, 13, 11, 'Spring 2025', 'B+'),
            (27, 14, 10, 'Fall 2024', 'A-'),
            (28, 14, 12, 'Spring 2025', 'B'),
            (29, 15, 11, 'Fall 2024', 'A'),
            (30, 15, 12, 'Spring 2025', 'A-');
        """)
        conn.commit()

# ---------- Flask-Login Setup ----------
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_page"

class User(UserMixin):
    def __init__(self, id, email, subscription_tier):
        self.id = id
        self.email = email
        self.subscription_tier = subscription_tier

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect(USER_DB) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, subscription_tier FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            return User(user[0], user[1], user[2])
        return None

# ---------- Routes ----------
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect("/app")
    return render_template("index.html")

@app.route("/auth")
def auth_page():
    if current_user.is_authenticated:
        return redirect("/app")
    return render_template("auth.html")

@app.route("/tool")
def tool():
    return render_template("app.html")
@app.route("/app")
# @login_required
def app_page():
    return render_template("index.html")

def generate_verification_code():
    """Generate a 6-digit verification code"""
    return ''.join(random.choices(string.digits, k=6))

def send_verification_email(email, code):
    """Send verification email using Resend API"""
    if not RESEND_API_KEY:
        logger.error("RESEND_API_KEY not configured")
        return False
    
    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {RESEND_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "from": RESEND_FROM_EMAIL,
        "to": [email],
        "subject": "Verify Your Email - SQL Nurse",
        "html": f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <h2 style="color: #4361ee;">Email Verification</h2>
            <p>Thank you for signing up for SQL Nurse!</p>
            <p>Your verification code is:</p>
            <div style="background: #f8f9fa; padding: 20px; text-align: center; font-size: 32px; font-weight: bold; color: #4361ee; letter-spacing: 5px; border-radius: 8px; margin: 20px 0;">
                {code}
            </div>
            <p>Enter this code in the verification popup to complete your registration.</p>
            <p style="color: #6c757d; font-size: 12px;">This code will expire in 10 minutes.</p>
        </div>
        """,
        "text": f"Your verification code is: {code}\n\nEnter this code in the verification popup to complete your registration."
    }
    
    try:
        response = requests.post(url, json=data, headers=headers)
        if response.status_code in [200, 201]:
            logger.info(f"Verification email sent to {email}")
            return True
        else:
            logger.error(f"Failed to send email: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"Error sending verification email: {str(e)}")
        return False

@app.route("/signup", methods=["POST"])
def signup():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    otp_code = data.get("otp_code")
    
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    
    try:
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email_verified, verification_code FROM users WHERE email = ?", (email,))
            existing_user = cursor.fetchone()
            
            if existing_user:
                user_id, email_verified, stored_code = existing_user
                
                # If OTP code is provided, verify it
                if otp_code:
                    if email_verified:
                        return jsonify({"error": "Email already verified"}), 400
                    if stored_code and stored_code == otp_code:
                        # Verify email
                        cursor.execute(
                            "UPDATE users SET email_verified = 1, verification_code = NULL WHERE id = ?",
                            (user_id,)
                        )
                        conn.commit()
                        
                        # Get subscription tier
                        cursor.execute("SELECT subscription_tier FROM users WHERE id = ?", (user_id,))
                        tier = cursor.fetchone()[0]
                        user = User(user_id, email, tier)
                        login_user(user)
                        
                        return jsonify({
                            "status": "success",
                            "message": "Email verified successfully!",
                            "tier": tier,
                            "redirect": "/app"
                        })
                    else:
                        return jsonify({"error": "Invalid verification code"}), 400
                else:
                    # Resend verification code
                    if email_verified:
                        return jsonify({"error": "Email already verified. Please login."}), 400
                    
                    code = generate_verification_code()
                    cursor.execute(
                        "UPDATE users SET verification_code = ? WHERE id = ?",
                        (code, user_id)
                    )
                    conn.commit()
                    
                    if send_verification_email(email, code):
                        return jsonify({
                            "status": "otp_sent",
                            "message": "Verification code sent to your email. Please check your inbox."
                        })
                    else:
                        return jsonify({"error": "Failed to send verification email. Please try again."}), 500
            else:
                # New user signup
                hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                subscription_tier = "free"
                code = generate_verification_code()
                
                cursor.execute(
                    "INSERT INTO users (email, password, subscription_tier, email_verified, verification_code) VALUES (?, ?, ?, 0, ?)",
                    (email, hashed_pw, subscription_tier, code)
                )
                conn.commit()
                user_id = cursor.lastrowid
                
                if send_verification_email(email, code):
                    return jsonify({
                        "status": "otp_sent",
                        "message": "Verification code sent to your email. Please check your inbox."
                    })
                else:
                    return jsonify({"error": "Failed to send verification email. Please try again."}), 500
                    
    except Exception as e:
        logger.error(f"Signup error: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400
    try:
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, password, subscription_tier, email_verified FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            if user and bcrypt.checkpw(password.encode('utf-8'), user[2]):
                if not user[4]:  # email_verified is False
                    return jsonify({"error": "Please verify your email before logging in. Check your inbox for the verification code."}), 401
                login_user(User(user[0], user[1], user[3]))
                return jsonify({
                    "status": "Logged in",
                    "tier": user[3],
                    "redirect": "/app"
                })
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 400
@app.route("/google-login", methods=["GET"])
def google_login():
    callback_url = url_for('google_auth_callback', _external=True)
    nonce = secrets.token_urlsafe(16)
    session['google_nonce'] = nonce
    logger.debug(f"Initiating Google login with callback: {callback_url}, nonce: {nonce}")
    try:
        return google.authorize_redirect(callback_url, nonce=nonce)
    except Exception as e:
        logger.error(f"Google login initiation failed: {str(e)}")
        flash(f"Google login initiation failed: {str(e)}", "error")
        return redirect(url_for("auth_page"))

@app.route("/auth/google/callback", methods=["GET", "POST"])
def google_auth_callback():
    try:
        logger.debug(f"Received Google OAuth callback with request URL: {request.url}")
        token = google.authorize_access_token()
        logger.debug(f"Access token obtained: {json.dumps({k: v for k, v in token.items() if k != 'access_token'}, indent=2)}")
        nonce = session.pop('google_nonce', None)
        user_info = google.parse_id_token(token, nonce=nonce)
        email = user_info.get("email")
        if not email:
            logger.error("No email in user info")
            flash("Google login failed: Missing email information.", "error")
            return redirect(url_for("auth_page"))
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, subscription_tier FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            if not user:
                cursor.execute(
                    "INSERT INTO users (email, password, subscription_tier, email_verified) VALUES (?, ?, ?, 1)",
                    (email, "", "premium", 1)  # No password for OAuth users, email verified by OAuth
                )
                conn.commit()
                user_id = cursor.lastrowid
                user = (user_id, email, "premium")
            login_user(User(user[0], user[1], user[2]))
        flash("Logged in successfully via Google!", "success")
        return redirect(url_for("tool"))
    except Exception as e:
        logger.error(f"Google login failed: {str(e)}")
        flash(f"Google login failed: {str(e)}", "error")
        return redirect(url_for("auth_page"))

@app.route("/github-login", methods=["GET"])
def github_login():
    callback_url = url_for('github_auth_callback', _external=True)
    logger.debug(f"Initiating GitHub login with callback: {callback_url}")
    try:
        return github.authorize_redirect(callback_url)
    except Exception as e:
        logger.error(f"GitHub login initiation failed: {str(e)}")
        flash(f"GitHub login initiation failed: {str(e)}", "error")
        return redirect(url_for("auth_page"))

@app.route("/auth/github/callback", methods=["GET", "POST"])
def github_auth_callback():
    try:
        logger.debug(f"Received GitHub OAuth callback with request URL: {request.url}")
        token = github.authorize_access_token()
        resp = github.get('user', token=token)
        if resp.status_code != 200:
            logger.error(f"Failed to retrieve user info: {resp.status_code} {resp.text}")
            flash(f"GitHub login failed: Unable to retrieve user info.", "error")
            return redirect(url_for("auth_page"))
        user_info = resp.json()
        email = user_info.get('email')
        if not email:
            resp_emails = github.get('user/emails', token=token)
            if resp_emails.status_code != 200:
                logger.error(f"Failed to retrieve emails: {resp_emails.status_code} {resp_emails.text}")
                flash(f"GitHub login failed: Unable to retrieve email.", "error")
                return redirect(url_for("tool"))
            emails = resp_emails.json()
            email = next((e['email'] for e in emails if e['primary'] and e['verified']), None)
            if not email:
                logger.error("No verified primary email found")
                flash("GitHub login failed: No verified email.", "error")
                return redirect(url_for("auth_page"))
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, email, subscription_tier FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            if not user:
                cursor.execute(
                    "INSERT INTO users (email, password, subscription_tier, email_verified) VALUES (?, ?, ?, 1)",
                    (email, "", "premium", 1)  # No password for OAuth users, email verified by OAuth
                )
                conn.commit()
                user_id = cursor.lastrowid
                user = (user_id, email, "premium")
            login_user(User(user[0], user[1], user[2]))
        flash("Logged in successfully via GitHub!", "success")
        return redirect(url_for("app_page"))
    except Exception as e:
        logger.error(f"GitHub login failed: {str(e)}")
        flash(f"GitHub login failed: {str(e)}", "error")
        return redirect(url_for("auth_page"))

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    return jsonify({"status": "Logged out"})

@app.route("/user_info", methods=["GET"])
def user_info():
    if current_user.is_authenticated:
        return jsonify({"email": current_user.email, "tier": current_user.subscription_tier})
    return jsonify({"error": "Not logged in"}), 401

@app.route("/public_databases", methods=["GET"])
def public_databases():
    """List all databases excluding demo.db"""
    public_dbs = []  # No public databases
    try:
        if current_user.is_authenticated:
            with sqlite3.connect(USER_DB) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT db_name FROM user_dbs WHERE user_id = ?", (current_user.id,))
                personal_dbs = [row[0] for row in cursor.fetchall()]
        else:
            personal_dbs = []
    except Exception as e:
        personal_dbs = []
        logger.error(f"Error fetching user databases: {str(e)}")
    all_dbs = list(set(public_dbs + personal_dbs))
    return jsonify({"databases": ["Select a database"] + all_dbs})

@app.route("/download_db/<db_name>", methods=["GET"])
@login_required
def download_db(db_name):
    """Allow downloading a .db file"""
    if db_name == "":
        return jsonify({"error": "Cannot download demo.db"}), 403
    try:
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT db_path FROM user_dbs WHERE user_id = ? AND db_name = ?", (current_user.id, db_name))
            db_info = cursor.fetchone()
            if not db_info:
                return jsonify({"error": "Database not found or not owned by user"}), 403
            db_path = db_info[0]
        if not os.path.exists(db_path):
            return jsonify({"error": "Database file not found"}), 404
        return send_file(db_path, as_attachment=True, download_name=db_name)
    except Exception as e:
        logger.error(f"Error downloading database {db_name}: {str(e)}")
        return jsonify({"error": str(e)}), 400

@app.route("/databases", methods=["GET"])
@login_required
def list_databases():
    try:
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT db_name FROM user_dbs WHERE user_id = ?", (current_user.id,))
            dbs = [row[0] for row in cursor.fetchall()]
        return jsonify({"databases": dbs})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

def get_db_path(db_name):
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(current_user.id))
    os.makedirs(user_folder, exist_ok=True)
    return os.path.join(user_folder, db_name)

def connect_db(db_name):
    """Connect to SQLite database (case-insensitive for text)."""
    path = get_db_path(db_name)
    if not os.path.exists(path):
        raise ValueError(f"Database {db_name} not found!")
    conn = sqlite3.connect(path, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA case_sensitive_like = OFF;")
    conn.row_factory = sqlite3.Row
    return conn

def get_schema_info(conn):
    """Return schema with lowercase table and column names."""
    cursor = conn.cursor()
    tables = cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
    ).fetchall()
    schema = {}
    for (table_name,) in tables:
        cols = cursor.execute(f"PRAGMA table_info({table_name});").fetchall()
        schema[table_name.lower()] = [{"name": c[1].lower(), "type": c[2]} for c in cols]
    return schema

def generate_sql_with_groq(user_prompt, schema_info):
    if not groq_client:
        raise ValueError("Groq API is not configured. Please set GROQ_API_KEY in your .env file.")
    try:
        system_message = {
            "role": "system",
            "content": (
                "You are a SQL assistant. Your job is to translate natural language questions into SQL queries.\n"
                "STRICT RULES:\n"
                "1. Only return a valid SQL query — do NOT include explanations, formatting, markdown, or backticks.\n"
                "2. Always wrap string comparisons in LOWER() for case-insensitive matching. Example: "
                "WHERE LOWER(students.name) = 'john'.\n"
                "3. If multiple tables have a 'name' column (e.g., students, courses, departments), "
                "always prefix with the table name and alias it properly. Example: "
                "students.name AS student_name, courses.name AS course_name.\n"
                "4. Avoid SELECT * — explicitly list columns with clear aliases.\n"
                "Your output must ONLY be pure SQL that can be executed directly"
            )
        }
        user_message = {
            "role": "user",
            "content": f"Schema:\n{schema_info}\n\nQuestion: {user_prompt}"
        }
        resp = groq_client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[system_message, user_message]
        )
        sql_query = resp.choices[0].message.content.strip()
        if sql_query.startswith("```sql"):
            sql_query = sql_query.strip("```sql").strip("```").strip()
        return sql_query
    except Exception as e:
        error_msg = str(e)
        if "401" in error_msg or "Unauthorized" in error_msg:
            raise ValueError("Groq API authentication failed. Please check your GROQ_API_KEY in the .env file.")
        elif "429" in error_msg or "rate limit" in error_msg.lower():
            raise ValueError("Groq API rate limit exceeded. Please try again later.")
        else:
            raise ValueError(f"Groq API error: {error_msg}")

def fix_sql_string_literals(sql):
    pattern = r"(LOWER\([^)]+\)\s*=\s*)([^\s'\"()]+)"
    def replacer(match):
        return f"{match.group(1)}'{match.group(2)}'"
    return re.sub(pattern, replacer, sql, flags=re.IGNORECASE)

def run_sql(conn, query):
    try:
        cursor = conn.cursor()
        cursor.execute(query)
        rows = cursor.fetchall()
        cols = [desc[0] for desc in cursor.description] if cursor.description else []
        results = [dict(row) for row in rows]
        return {"columns": cols, "rows": results}
    except Exception as e:
        return {"error": str(e)}

def get_connection(db_type, **kwargs):
    """Return DB connection (SQLite, MySQL, PostgreSQL)"""
    if db_type.lower() == "sqlite":
        path = kwargs.get("path")
        if not os.path.exists(path):
            raise ValueError("SQLite DB file not found!")
        conn = sqlite3.connect(path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA case_sensitive_like = OFF;")
        return conn
    elif db_type.lower() == "mysql":
        conn = pymysql.connect(
            host=kwargs.get("host"),
            port=int(kwargs.get("port", 3306)),
            user=kwargs.get("user"),
            password=kwargs.get("password"),
            database=kwargs.get("database"),
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
        return conn
    elif db_type.lower() == "postgresql":
        conn = psycopg2.connect(
            host=kwargs.get("host"),
            port=int(kwargs.get("port", 5432)),
            user=kwargs.get("user"),
            password=kwargs.get("password"),
            dbname=kwargs.get("database")
        )
        return conn
    else:
        raise ValueError(f"Unsupported DB type: {db_type}")

def get_schema(conn, db_type):
    """Return schema for any DB with lowercase table/column names"""
    schema = {}
    cursor = conn.cursor()
    if db_type.lower() == "sqlite":
        tables = cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%';"
        ).fetchall()
        for (table_name,) in tables:
            cols = cursor.execute(f"PRAGMA table_info({table_name});").fetchall()
            schema[table_name.lower()] = [{"name": c[1].lower(), "type": c[2]} for c in cols]
    elif db_type.lower() == "mysql":
        cursor.execute("SHOW TABLES;")
        tables = [list(row.values())[0] for row in cursor.fetchall()]
        for table in tables:
            cursor.execute(f"DESCRIBE {table};")
            cols = cursor.fetchall()
            schema[table.lower()] = [{"name": c['Field'].lower(), "type": c['Type']} for c in cols]
    elif db_type.lower() == "postgresql":
        cursor.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema='public';"
        )
        tables = [row[0] for row in cursor.fetchall()]
        for table in tables:
            cursor.execute(
                f"SELECT column_name, data_type FROM information_schema.columns WHERE table_name='{table}';"
            )
            cols = cursor.fetchall()
            schema[table.lower()] = [{"name": c[0].lower(), "type": c[1]} for c in cols]
    return schema

@app.route("/schema", methods=["POST"])
def schema():
    data = request.json
    db_name = data.get("db_name")
    if db_name == "Select a database" or db_name == "":
        return jsonify({"error": "Please select a valid database"}), 400
    try:
        if not current_user.is_authenticated:
            return jsonify({"error": "Login required for this database"}), 401
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT db_type, db_path FROM user_dbs WHERE user_id = ? AND db_name = ?", (current_user.id, db_name))
            db_info = cursor.fetchone()
            if not db_info:
                return jsonify({"error": "Database not found or not owned by user"}), 403
            db_type, db_path = db_info
        if db_type == "sqlite":
            with connect_db(db_name) as conn:
                schema_info = get_schema_info(conn)
        else:
            conn = get_connection(db_type, path=db_path, host=data.get("host"), port=data.get("port"), database=data.get("database"), user=data.get("user"), password=data.get("password"))
            schema_info = get_schema(conn, db_type)
            conn.close()
        return jsonify({"schema": schema_info})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/db_description", methods=["POST"])
def db_description():
    data = request.json
    db_name = data.get("db_name")
    if db_name == "Select a database" or db_name == "":
        return jsonify({"error": "Please select a valid database"}), 400
    try:
        if not current_user.is_authenticated:
            return jsonify({"error": "Login required for this database"}), 401
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT db_type, db_path FROM user_dbs WHERE user_id = ? AND db_name = ?", (current_user.id, db_name))
            db_info = cursor.fetchone()
            if not db_info:
                return jsonify({"error": "Database not found or not owned by user"}), 403
            db_type, db_path = db_info
        if db_type == "sqlite":
            conn = connect_db(db_name)
        else:
            conn = get_connection(db_type, path=db_path, host=data.get("host"), port=data.get("port"), database=data.get("database"), user=data.get("user"), password=data.get("password"))
        schema_info = get_schema(conn, db_type)
        conn.close()
        schema_lower = {
            k.lower(): [{'name': c['name'].lower(), 'type': c['type']} for c in v]
            for k, v in schema_info.items()
        }
        if not groq_client:
            return jsonify({"error": "Groq API is not configured. Please set GROQ_API_KEY in your .env file."}), 400
        try:
            system_message = {
                "role": "system",
                "content": (
                    "You are a helpful assistant that summarizes database schemas "
                    "in simple English for laymen. Keep it short and clear."
                )
            }
            user_message = {
                "role": "user",
                "content": (
                    f"Schema:\n{schema_lower}\n\n"
                    "Provide a 2–3 line description of what this database is about "
                    "and what kind of information it stores."
                )
            }
            resp = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[system_message, user_message]
            )
            description = resp.choices[0].message.content.strip()
            return jsonify({"description": description})
        except Exception as e:
            error_msg = str(e)
            if "401" in error_msg or "Unauthorized" in error_msg:
                return jsonify({"error": "Groq API authentication failed. Please check your GROQ_API_KEY in the .env file."}), 400
            elif "429" in error_msg or "rate limit" in error_msg.lower():
                return jsonify({"error": "Groq API rate limit exceeded. Please try again later."}), 400
            else:
                return jsonify({"error": f"Groq API error: {error_msg}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/ask", methods=["POST"])
def ask():
    data = request.json
    db_name = data.get("db_name")
    question = data.get("question")
    if db_name == "Select a database" or db_name == "":
        return jsonify({"error": "Please select a valid database"}), 400
    try:
        tier = "free" if not current_user.is_authenticated else current_user.subscription_tier
        if not current_user.is_authenticated:
            return jsonify({"error": "Login required for this database"}), 401
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT db_type, db_path FROM user_dbs WHERE user_id = ? AND db_name = ?", (current_user.id, db_name))
            db_info = cursor.fetchone()
            if not db_info:
                return jsonify({"error": "Database not found or not owned by user"}), 403
            db_type, db_path = db_info
        if db_type == "sqlite":
            conn = connect_db(db_name)
        else:
            conn = get_connection(db_type, path=db_path, host=data.get("host"), port=data.get("port"), database=data.get("database"), user=data.get("user"), password=data.get("password"))
        schema_info = get_schema(conn, db_type)
        sql_query = generate_sql_with_groq(question, schema_info)
        sql_query = fix_sql_string_literals(sql_query)
        result = run_sql(conn, sql_query)
        conn.close()
        return jsonify({"sql": sql_query, "result": result})
    except Exception as e:
        return jsonify({"error": str(e)}), 400
@app.route("/visualize", methods=["POST"])
def visualize():
    data = request.json
    db_name = data.get("db_name")
    prompt = data.get("prompt")
    if db_name == "Select a database":
        return jsonify({"error": "Please select a valid database"}), 400
    try:
        is_public = db_name == "demo.db"
        if not current_user.is_authenticated:
            return jsonify({"error": "Login required for visualization"}), 401
        if current_user.subscription_tier != "premium":
            return jsonify({"error": "Premium subscription required for visualization"}), 403
        if not is_public:
            with sqlite3.connect(USER_DB) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT db_type, db_path FROM user_dbs WHERE user_id = ? AND db_name = ?", (current_user.id, db_name))
                db_info = cursor.fetchone()
                if not db_info:
                    return jsonify({"error": "Database not found or not owned by user"}), 403
                db_type, db_path = db_info
        else:
            db_type = "sqlite"
            db_path = get_db_path(db_name)
        if db_type == "sqlite":
            conn = connect_db(db_name)
        else:
            conn = get_connection(db_type, path=db_path, host=data.get("host"), port=data.get("port"), database=data.get("database"), user=data.get("user"), password=data.get("password"))
        schema_info = get_schema(conn, db_type)
        sql_query = generate_sql_with_groq(prompt, schema_info)
        result = run_sql(conn, sql_query)
        conn.close()
        if result.get("error"):
            return jsonify({"error": result["error"]}), 400
        if not groq_client:
            summary = "Groq API is not configured. Please set GROQ_API_KEY in your .env file."
        else:
            try:
                user_msg = {
                    "role": "user",
                    "content": (
                        f"Here is the data returned by SQL:\n"
                        f"Columns: {result['columns']}\nRows: {result['rows'][:5]}...\n\n"
                        "Write 2-3 concise sentences summarizing the key insights "
                        "for a professional data visualization caption."
                    )
                }
                resp = groq_client.chat.completions.create(
                    model="llama-3.3-70b-versatile",
                    messages=[{"role": "system", "content": "You are a data analyst."}, user_msg]
                )
                summary = resp.choices[0].message.content.strip()
            except Exception as e:
                error_msg = str(e)
                if "401" in error_msg or "Unauthorized" in error_msg:
                    summary = "Groq API authentication failed. Please check your GROQ_API_KEY in the .env file."
                elif "429" in error_msg or "rate limit" in error_msg.lower():
                    summary = "Groq API rate limit exceeded. Please try again later."
                else:
                    summary = f"Groq API error: {error_msg}"
        
        return jsonify({
            "sql": sql_query,
            "columns": result["columns"],
            "rows": result["rows"],
            "summary": summary
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400
@app.route("/create_db", methods=["POST"])
@login_required
def create_db():
    if current_user.subscription_tier not in ["free", "basic", "standard", "premium"]:
        return jsonify({"error": "Free, Basic, Standard, or Premium subscription required for creating databases"}), 403

    data = request.json
    db_name = data.get("db_name")
    prompt = data.get("prompt")

    if not db_name:
        return jsonify({"error": "Database name is required"}), 400

    if not db_name.endswith(".db"):
        db_name += ".db"

    # Create user-specific folder
    user_folder = os.path.join(app.config["UPLOAD_FOLDER"], str(current_user.id))
    os.makedirs(user_folder, exist_ok=True)

    # Full path to user's DB
    db_path = os.path.join(user_folder, db_name)

    # Check only if this user already has a DB with the same name
    with sqlite3.connect(USER_DB) as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT 1 FROM user_dbs WHERE user_id = ? AND db_name = ?",
            (current_user.id, db_name)
        )
        exists = cursor.fetchone()

    if exists:
        return jsonify({"error": "You already have a database with this name!"}), 400

    try:
        # Generate schema from LLM
        if not groq_client:
            return jsonify({"error": "Groq API is not configured. Please set GROQ_API_KEY in your .env file."}), 400
        try:
            system_message = {
                "role": "system",
                "content": "You are a SQL assistant. Generate only SQL CREATE TABLE statements based on the user's description. Do not add data, comments or explanation."
            }
            user_message = {"role": "user", "content": prompt}

            resp = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[system_message, user_message]
            )

            sql_schema = resp.choices[0].message.content.strip()
            if sql_schema.startswith("```sql"):
                sql_schema = sql_schema.strip("```sql").strip("```").strip()
        except Exception as e:
            error_msg = str(e)
            if "401" in error_msg or "Unauthorized" in error_msg:
                return jsonify({"error": "Groq API authentication failed. Please check your GROQ_API_KEY in the .env file."}), 400
            elif "429" in error_msg or "rate limit" in error_msg.lower():
                return jsonify({"error": "Groq API rate limit exceeded. Please try again later."}), 400
            else:
                return jsonify({"error": f"Groq API error: {error_msg}"}), 400

        # Create actual SQLite DB
        with sqlite3.connect(db_path, timeout=10) as conn:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.executescript(sql_schema)
            conn.commit()

        # Save reference in user_dbs
        with sqlite3.connect(USER_DB) as conn:
            conn.execute("""
                INSERT INTO user_dbs (user_id, db_name, db_type, db_path)
                VALUES (?, ?, ?, ?)
            """, (current_user.id, db_name, "sqlite", db_path))
            conn.commit()

        return jsonify({"status": "Database created", "sql_schema": sql_schema})

    except Exception as e:
        return jsonify({"error": str(e)}), 400
@app.route("/add_row", methods=["POST"])
@login_required
def add_row():
    if current_user.subscription_tier not in ["basic", "standard", "premium"]:
        return jsonify({"error": "Basic, Standard, or Premium subscription required for managing rows"}), 403
    data = request.json
    db_name = data.get("db_name")
    table_name = data.get("table")
    values_text = data.get("values")
    if db_name == "Select a database" or db_name == "":
        return jsonify({"error": "Please select a valid database"}), 400
    try:
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT db_type, db_path FROM user_dbs WHERE user_id = ? AND db_name = ?", (current_user.id, db_name))
            db_info = cursor.fetchone()
            if not db_info:
                return jsonify({"error": "Database not found or not owned by user"}), 403
            db_type, db_path = db_info
        if db_type == "sqlite":
            conn = connect_db(db_name)
        else:
            conn = get_connection(db_type, path=db_path, host=data.get("host"), port=data.get("port"), database=data.get("database"), user=data.get("user"), password=data.get("password"))
        cursor = conn.cursor()
        schema = get_schema_info(conn) if db_type == "sqlite" else get_schema(conn, db_type)
        table_key = table_name.lower()
        if table_key not in schema:
            conn.close()
            return jsonify({"error": f"Table {table_name} not found!"}), 400
        columns = [c["name"] for c in schema[table_key]]
        raw_values = values_text.strip()
        values = [v.strip() for v in raw_values.split(",")]
        if len(values) != len(columns):
            conn.close()
            return jsonify({"error": f"Expected {len(columns)} values, got {len(values)}"}), 400
        placeholders = ",".join("?" * len(values))
        sql = f'INSERT INTO "{table_key}" ({",".join(columns)}) VALUES ({placeholders})'
        cursor.execute(sql, values)
        conn.commit()
        conn.close()
        return jsonify({"status": "Row added"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/delete_row", methods=["POST"])
@login_required
def delete_row():
    if current_user.subscription_tier not in ["basic", "standard", "premium"]:
        return jsonify({"error": "Basic, Standard, or Premium subscription required for managing rows"}), 403
    data = request.json
    db_name = data.get("db_name")
    table = data.get("table")
    condition = data.get("condition")
    if not all([db_name, table, condition]):
        return jsonify({"error": "db_name, table and condition are required"}), 400
    if db_name == "Select a database" or db_name == "":
        return jsonify({"error": "Please select a valid database"}), 400
    try:
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT db_type, db_path FROM user_dbs WHERE user_id = ? AND db_name = ?", (current_user.id, db_name))
            db_info = cursor.fetchone()
            if not db_info:
                return jsonify({"error": "Database not found or not owned by user"}), 403
            db_type, db_path = db_info
        if db_type == "sqlite":
            conn = connect_db(db_name)
        else:
            conn = get_connection(db_type, path=db_path, host=data.get("host"), port=data.get("port"), database=data.get("database"), user=data.get("user"), password=data.get("password"))
        cur = conn.cursor()
        cur.execute(f'PRAGMA table_info("{table}")')
        cols_info = cur.fetchall()
        valid_cols = {row[1] for row in cols_info}
        pk_cols = [row[1] for row in cols_info if row[5] == 1]
        left_side = condition.split('=')[0].strip().strip('"')
        if left_side not in valid_cols and len(pk_cols) == 1:
            pk = pk_cols[0]
            condition = condition.replace(left_side, pk, 1)
        left_side_final = condition.split('=')[0].strip().strip('"')
        if left_side_final not in valid_cols:
            conn.close()
            return jsonify({"error": f"Invalid column name: {left_side_final}"}), 400
        sql = f'DELETE FROM "{table}" WHERE {condition}'
        cur.execute(sql)
        conn.commit()
        conn.close()
        return jsonify({"status": "Row deleted", "rows_affected": cur.rowcount})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/connect_db", methods=["POST"])
@login_required
def connect_db_route():
    data = request.json
    db_type = data.get("db_type")
    db_name = data.get("db_name", data.get("database", "remote_db"))
    conn_info = data.copy()
    conn_info.pop("db_type", None)
    if db_type.lower() == "sqlite" and not conn_info.get("path"):
        return jsonify({"error": "SQLite database file path is required"}), 400
    try:
        conn = get_connection(db_type, **conn_info)
        schema = get_schema(conn, db_type)
        conn.close()
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO user_dbs (user_id, db_name, db_type, db_path) VALUES (?, ?, ?, ?)",
                          (current_user.id, db_name, db_type, conn_info.get("path", "")))
            conn.commit()
        return jsonify({"schema": schema})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/upload_db", methods=["POST"])
@login_required
def upload_db():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    if not file.filename.endswith('.db'):
        return jsonify({"error": "File must be a .db SQLite database"}), 400
    db_name = file.filename
    db_path = get_db_path(db_name)
    if os.path.exists(db_path):
        return jsonify({"error": "Database already exists!"}), 400
    try:
        file.save(db_path)
        conn = sqlite3.connect(db_path, timeout=10)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA case_sensitive_like = OFF;")
        schema = get_schema_info(conn)
        conn.close()
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO user_dbs (user_id, db_name, db_type, db_path) VALUES (?, ?, ?, ?)",
                          (current_user.id, db_name, "sqlite", db_path))
            conn.commit()
        return jsonify({"status": "Database uploaded", "schema": schema})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/suggested_queries", methods=["POST"])
def suggested_queries():
    data = request.json
    db_name = data.get("db_name")
    if db_name == "Select a database" or db_name == "":
        return jsonify({"error": "Please select a valid database"}), 400
    try:
        tier = "free" if not current_user.is_authenticated else current_user.subscription_tier
        if not current_user.is_authenticated:
            return jsonify({"error": "Login required for this database"}), 401
        with sqlite3.connect(USER_DB) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT db_type, db_path FROM user_dbs WHERE user_id = ? AND db_name = ?", (current_user.id, db_name))
            db_info = cursor.fetchone()
            if not db_info:
                return jsonify({"error": "Database not found or not owned by user"}), 403
            db_type, db_path = db_info
        if db_type == "sqlite":
            conn = connect_db(db_name)
        else:
            conn = get_connection(db_type, path=db_path, host=data.get("host"), port=data.get("port"), database=data.get("database"), user=data.get("user"), password=data.get("password"))
        schema_info = get_schema(conn, db_type)
        conn.close()
        if not groq_client:
            return jsonify({"error": "Groq API is not configured. Please set GROQ_API_KEY in your .env file."}), 400
        try:
            system_message = {
                "role": "system",
                "content": (
                    "You are a SQL assistant. Generate exactly 6 useful, practical NATURAL LANGUAGE QUESTIONS (not SQL queries) "
                    "that a business user would ask about this database.\n"
                    "Format: Number each question 1-6, followed by the question only. No SQL, no explanations.\n"
                    "Example:\n"
                    "1. Total number of employees department wise\n"
                    "2. Average salary by department\n"
                    "3. Top 5 highest paid employees\n"
                    "4. Employees hired in the last year\n"
                    "5. Department wise gender distribution\n"
                    "6. Total projects per department\n"
                )
            }
            user_message = {
                "role": "user",
                "content": f"Schema:\n{json.dumps(schema_info, indent=2)}\n\nGenerate 6 natural language questions:"
            }
            resp = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[system_message, user_message]
            )
            suggestions_text = resp.choices[0].message.content.strip()
            queries = []
            lines = suggestions_text.split('\n')
            for line in lines:
                if line.strip().startswith(tuple('123456')) and '.' in line:
                    question = line.split('.', 1)[1].strip()
                    queries.append(question.strip())
            return jsonify({"queries": queries[:6]})
        except Exception as e:
            error_msg = str(e)
            if "401" in error_msg or "Unauthorized" in error_msg:
                return jsonify({"error": "Groq API authentication failed. Please check your GROQ_API_KEY in the .env file."}), 400
            elif "429" in error_msg or "rate limit" in error_msg.lower():
                return jsonify({"error": "Groq API rate limit exceeded. Please try again later."}), 400
            else:
                return jsonify({"error": f"Groq API error: {error_msg}"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ---------- Stripe Integration ----------
PLANS = {
    "basic": ("Basic", 1000),
    "standard": ("Standard", 1500),
    "premium": ("Premium", 2500)
}

@app.route("/stripe_config", methods=["GET"])
def stripe_config():
    return jsonify({
        "publishableKey": STRIPE_PUBLISHABLE_KEY or "",
        "plans": {k: {"nickname": v[0], "amount_cents": v[1]} for k, v in PLANS.items()}
    })

@app.route("/create-checkout-session", methods=["POST"])
@login_required
def create_checkout_session():
    if not STRIPE_SECRET_KEY:
        return jsonify({"error": "Stripe secret key not configured on server."}), 500
    data = request.json or {}
    plan = data.get("plan")
    email = data.get("email") or current_user.email
    if plan not in PLANS:
        return jsonify({"error": "Invalid plan"}), 400
    nickname, amount_cents = PLANS[plan]
    domain_url = request.host_url.rstrip("/")
    try:
        session = stripe.checkout.Session.create(
            payment_method_types=["card"],
            mode="subscription",
            line_items=[{
                "price_data": {
                    "currency": "usd",
                    "product_data": {"name": f"SQL Playground - {nickname} Plan"},
                    "recurring": {"interval": "month"},
                    "unit_amount": amount_cents
                },
                "quantity": 1
            }],
            success_url=domain_url + "/app?checkout=success&session_id={CHECKOUT_SESSION_ID}",
            cancel_url=domain_url + "/app?checkout=cancelled",
            customer_email=email,
            allow_promotion_codes=True,
            metadata={"user_id": str(current_user.id)}
        )
        return jsonify({"url": session.url, "id": session.id})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/stripe_webhook", methods=["POST"])
def stripe_webhook():
    payload = request.data
    sig_header = request.headers.get("Stripe-Signature", None)
    event = None
    if STRIPE_WEBHOOK_SECRET and sig_header:
        try:
            event = stripe.Webhook.construct_event(
                payload=payload, sig_header=sig_header, secret=STRIPE_WEBHOOK_SECRET
            )
        except ValueError as e:
            return jsonify({"error": "Invalid payload"}), 400
        except stripe.error.SignatureVerificationError as e:
            return jsonify({"error": "Invalid signature"}), 400
    else:
        try:
            event = json.loads(payload)
        except Exception as e:
            return jsonify({"error": "Invalid payload and no webhook secret configured."}), 400
    evt_type = event.get("type")
    data_obj = event.get("data", {}).get("object", {})
    if evt_type in ("checkout.session.completed", "customer.subscription.created", "customer.subscription.updated"):
        user_id = data_obj.get("metadata", {}).get("user_id")
        if user_id:
            plan = None
            for p, (nickname, _) in PLANS.items():
                if f"SQL Playground - {nickname} Plan" in str(data_obj):
                    plan = p
                    break
            if plan:
                with sqlite3.connect(USER_DB) as conn:
                    conn.execute("UPDATE users SET subscription_tier = ? WHERE id = ?", (plan, user_id))
                    conn.commit()
    try:
        db_path = get_db_path("stripe_events.db")
        conn = sqlite3.connect(db_path, timeout=10)
        conn.execute("CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, type TEXT, payload TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)")
        evt_id = event.get("id", "")
        conn.execute("INSERT OR REPLACE INTO events (id, type, payload) VALUES (?, ?, ?)",
                     (evt_id, evt_type, json.dumps(event)))
        conn.commit()
        conn.close()
    except Exception as e:
        print("Failed to log stripe event:", e)
    return jsonify({"status": "success"})

# ---------- Start server ----------
if __name__ == "__main__":

    app.run(host="0.0.0.0", port=5000, debug=True)
