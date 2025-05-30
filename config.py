from datetime import timedelta
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Basic Flask config
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Security settings
    FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'False').lower() == 'true'
    
    # Database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///instance/users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session config
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=10)  # 10 minute timeout
    SESSION_PERMANENT = True
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # API config
    NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
    NVD_API_TIMEOUT = 10  # seconds
    
    # CVE date range
    CVE_START_DATE = "2024-01-01T00:00:00.000Z"
    CVE_END_DATE = "2024-03-01T00:00:00.000Z"
    
    # Password rules
    MIN_PASSWORD_LENGTH = 12
    PASSWORD_REQUIREMENTS = {
        'min_length': 12,
        'require_upper': True,
        'require_lower': True,
        'require_numbers': True,
        'require_special': True,
        'max_length': 128
    }
    
    # Security Headers
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SAMESITE = 'Lax'
    
    # Rate Limiting
    RATELIMIT_DEFAULT = "100 per day"
    RATELIMIT_STORAGE_URL = "memory://"
    
    # Max file upload size - 8MB
    MAX_CONTENT_LENGTH = 8 * 1024 * 1024 