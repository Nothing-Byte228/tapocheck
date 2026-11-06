import os
from pathlib import Path

# Base configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or os.urandom(32)
    
    # Upload settings
    BASE_DIR = Path(__file__).parent
    UPLOAD_FOLDER = BASE_DIR / 'static' / 'uploads'
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    
    # Allowed file extensions
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'avi', 'mov', 'txt', 'py', 'cs', 'pas'}
    
    # Database settings
    DB_USERS = 'users.db'
    DB_CHATS = 'chats.db'
    
    # Session settings
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Rate limiting
    LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_TIME = 300  # 5 minutes
    
    # Typing indicator timeout (seconds)
    TYPING_TIMEOUT = 4
    
    # Debug mode (set via environment variable)
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'

class DevelopmentConfig(Config):
    DEBUG = False

class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
