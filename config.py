import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cybershield-ai-super-secret-key-2026-cse-secure')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f"sqlite:///{BASE_DIR / 'database' / 'cybershield.db'}")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # File Uploads
    UPLOAD_FOLDER = BASE_DIR / 'uploads'
    REPORTS_FOLDER = BASE_DIR / 'reports'
    MODELS_FOLDER = BASE_DIR / 'models'
    DATASETS_FOLDER = BASE_DIR / 'datasets'
    
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024  # 32 MB max upload
    ALLOWED_EXTENSIONS = {'csv'}
    
    # Session & Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = False  # Set to True when using HTTPS in production
    PERMANENT_SESSION_LIFETIME = 86400  # 24 hours
    
    # Machine Learning
    MODEL_VERSION = 'v1.0.0-unsw-nb15'
    RANDOM_STATE = 42

class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False
    UPLOAD_FOLDER = BASE_DIR / 'tests' / 'test_uploads'
