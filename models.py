from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from extensions import db
import re

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime)

    def set_password(self, password):
        """Set password with enhanced validation."""
        # Check minimum length
        if len(password) < Config.PASSWORD_REQUIREMENTS['min_length']:
            raise ValueError(f"Password must be at least {Config.PASSWORD_REQUIREMENTS['min_length']} characters long")
            
        # Check maximum length
        if len(password) > Config.PASSWORD_REQUIREMENTS['max_length']:
            raise ValueError(f"Password must not exceed {Config.PASSWORD_REQUIREMENTS['max_length']} characters")

        # Check for uppercase
        if Config.PASSWORD_REQUIREMENTS['require_upper'] and not re.search(r'[A-Z]', password):
            raise ValueError("Password must contain at least one uppercase letter")

        # Check for lowercase
        if Config.PASSWORD_REQUIREMENTS['require_lower'] and not re.search(r'[a-z]', password):
            raise ValueError("Password must contain at least one lowercase letter")

        # Check for numbers
        if Config.PASSWORD_REQUIREMENTS['require_numbers'] and not re.search(r'\d', password):
            raise ValueError("Password must contain at least one number")

        # Check for special characters
        if Config.PASSWORD_REQUIREMENTS['require_special'] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            raise ValueError("Password must contain at least one special character")

        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>' 