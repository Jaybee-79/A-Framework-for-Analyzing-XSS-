from datetime import timedelta
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Basic Flask config
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    
    # Database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Session config
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=10)  # 10 minute timeout
    SESSION_PERMANENT = True
    
    # API config
    NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
    NVD_API_TIMEOUT = 10  # seconds
    
    # CVE date range
    CVE_START_DATE = "2024-01-01T00:00:00.000Z"
    CVE_END_DATE = "2024-03-01T00:00:00.000Z"
    
    # Password rules
    MIN_PASSWORD_LENGTH = 8 