from datetime import timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_migrate import Migrate
import re
from html import escape
import os

app = Flask(__name__)

# ==============================================
# SECURITY MODULE 1: APPLICATION CONFIGURATION
# ==============================================
app.secret_key = os.environ.get('SECRET_KEY') or 'your-very-secret-key-here'

# Initialize SQLAlchemy and Migrate
db = SQLAlchemy()
migrate = Migrate()

# ==============================================
# SECURITY MODULE 2: INPUT VALIDATION & SANITIZATION
# ==============================================
class InputSecurity:
    @staticmethod
    def validate_email(email):
        """Validate email format to prevent injection attacks"""
        return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email)

    @staticmethod
    def validate_name(name):
        """Validate name format to prevent XSS"""
        return re.match(r'^[a-zA-Z\s\'-]{2,50}$', name)

    @staticmethod
    def validate_phone(phone):
        """Validate phone format to prevent injection"""
        return re.match(r'^\+?[0-9\s-]{6,20}$', phone)

    @staticmethod
    def sanitize_input(input_str):
        """Sanitize all user inputs to prevent XSS"""
        return escape(input_str.strip())

    @staticmethod
    def validate_password(password):
        """Ensure password meets complexity requirements"""
        return len(password) >= 8  # Add more checks as needed

# ==============================================
# SECURITY MODULE 3: AUTHENTICATION & PASSWORD SECURITY
# ==============================================
class AuthSecurity:
    def __init__(self, app):
        self.bcrypt = Bcrypt(app)
        self.limiter = Limiter(
            app=app,
            key_func=get_remote_address,
            default_limits=["200 per day", "50 per hour"]
        )

    def hash_password(self, password):
        """Securely hash passwords using bcrypt"""
        return self.bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, hashed_password, password):
        """Verify password against stored hash"""
        return self.bcrypt.check_password_hash(hashed_password, password)

    def login_limiter(self):
        """Decorator to limit login attempts"""
        return self.limiter.limit("5 per minute", 
                               error_message="Too many login attempts. Please try again later.")

# ==============================================
# SECURITY MODULE 4: CSRF & SESSION PROTECTION
# ==============================================
class SessionSecurity:
    def __init__(self, app):
        self.csrf = CSRFProtect(app)
        self.configure_session(app)

    def configure_session(self, app):
        """Secure session configuration"""
        app.config.update({
            'WTF_CSRF_TIME_LIMIT': 3600 * 3,
            'SESSION_COOKIE_SECURE': True,
            'SESSION_COOKIE_HTTPONLY': True,
            'SESSION_COOKIE_SAMESITE': 'Lax',
            'PERMANENT_SESSION_LIFETIME': timedelta(hours=3)
        })

    def generate_csrf_token(self):
        """Generate CSRF token for forms"""
        return self.csrf.generate_csrf()

# ==============================================
# SECURITY MODULE 5: DATABASE SECURITY
# ==============================================
class DatabaseSecurity:
    def __init__(self, app):
        app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or "sqlite:///site.db"
        app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
        db.init_app(app)
        migrate.init_app(app, db)

    class User(db.Model):
        """Secure user model with proper constraints"""
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False)
        password = db.Column(db.String(200), nullable=False)
        last_login = db.Column(db.DateTime)

        def __repr__(self):
            return f'<User {self.username}>'

    class Contact(db.Model):
        """Secure contact model with validation"""
        id = db.Column(db.Integer, primary_key=True)
        name = db.Column(db.String(100), nullable=False)
        email = db.Column(db.String(100), nullable=False)
        phone = db.Column(db.String(20))
        website = db.Column(db.String(100))
        message = db.Column(db.Text, nullable=False)
        date_created = db.Column(db.DateTime, default=db.func.current_timestamp())

        def __repr__(self):
            return f'<Contact {self.name}>'

# ==============================================
# SECURITY MODULE 6: ERROR HANDLING
# ==============================================
class ErrorSecurity:
    @staticmethod
    def init_error_handlers(app):
        """Configure secure error handling"""
        @app.errorhandler(404)
        def page_not_found(e):
            return render_template('404.html'), 404

        @app.errorhandler(500)
        def internal_server_error(e):
            return render_template('500.html'), 500

        @app.errorhandler(CSRFError)
        def handle_csrf_error(e):
            flash('CSRF token expired or invalid. Please try again.', 'danger')
            return redirect(url_for('login'))

# ==============================================
# INITIALIZE ALL SECURITY MODULES
# ==============================================
input_sec = InputSecurity()
auth_sec = AuthSecurity(app)
session_sec = SessionSecurity(app)
db_sec = DatabaseSecurity(app)
ErrorSecurity.init_error_handlers(app)

# Make User and Contact models available globally
User = db_sec.User
Contact = db_sec.Contact

@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('contact'))  # Redirect to contact if logged in
    return redirect(url_for('login'))        # Redirect to login if not logged in

# ==============================================
# APPLICATION ROUTES WITH SECURITY INTEGRATION
# ==============================================
@app.route('/login', methods=['GET', 'POST'])
@auth_sec.login_limiter()
def login():
    if request.method == 'POST':
        username = input_sec.sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('login'))
        
        user = User.query.filter_by(username=username).first()
        
        if user and auth_sec.check_password(user.password, password):
            session['username'] = username
            user.last_login = db.func.current_timestamp()
            db.session.commit()
            flash('Login successful!', 'success')
            return redirect(url_for('contact'))
        
        flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = input_sec.sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Please fill in all fields', 'danger')
            return redirect(url_for('register'))
        
        if not input_sec.validate_password(password):
            flash('Password must be at least 8 characters', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = auth_sec.hash_password(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        name = input_sec.sanitize_input(request.form.get('name', ''))
        email = input_sec.sanitize_input(request.form.get('email', ''))
        phone = input_sec.sanitize_input(request.form.get('phone', ''))
        website = input_sec.sanitize_input(request.form.get('website', ''))
        message = input_sec.sanitize_input(request.form.get('message', ''))
        
        # Validate all inputs
        if not all([name, email, message]):
            flash('Please fill in all required fields', 'danger')
            return redirect(url_for('contact'))
        
        if not input_sec.validate_email(email):
            flash('Invalid email address', 'danger')
            return redirect(url_for('contact'))
            
        if phone and not input_sec.validate_phone(phone):
            flash('Invalid phone number', 'danger')
            return redirect(url_for('contact'))
        
        if not input_sec.validate_name(name):
            flash('Invalid name format', 'danger')
            return redirect(url_for('contact'))
        
        # Secure database operation
        new_contact = Contact(
            name=name,
            email=email,
            phone=phone,
            website=website,
            message=message
        )
        
        db.session.add(new_contact)
        db.session.commit()
        
        flash('Your message has been sent!', 'success')
        return redirect(url_for('contact'))
    
    return render_template('contact.html')

@app.route('/messages')
def messages():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    contacts = Contact.query.order_by(Contact.date_created.desc()).all()
    return render_template('messages.html', contacts=contacts)

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# ==============================================
# APPLICATION STARTUP
# ==============================================
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)