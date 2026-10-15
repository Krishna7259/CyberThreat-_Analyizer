import argparse
import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask
from config import Config
from database.db_models import db, User, ModelVersion

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    return app

def init_database(app):
    with app.app_context():
        # Ensure database directory exists
        db_path = Config.SQLALCHEMY_DATABASE_URI.replace('sqlite:///', '')
        if db_path != ':memory:':
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
            
        db.create_all()
        print("[+] Database tables initialized successfully.")

def create_admin_user(app, username, email, password):
    with app.app_context():
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            print(f"[!] User with username '{username}' or email '{email}' already exists.")
            return False
            
        admin = User(
            username=username,
            email=email,
            role='admin'
        )
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print(f"[+] Administrator '{username}' created successfully.")
        return True

def create_analyst_user(app, username, email, password):
    with app.app_context():
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            print(f"[!] User with username '{username}' or email '{email}' already exists.")
            return False
            
        analyst = User(
            username=username,
            email=email,
            role='analyst'
        )
        analyst.set_password(password)
        db.session.add(analyst)
        db.session.commit()
        print(f"[+] Security Analyst '{username}' created successfully.")
        return True

def main():
    parser = argparse.ArgumentParser(description="CyberShield AI Database Initialization CLI")
    parser.add_argument('--init-only', action='store_true', help="Only create database tables")
    parser.add_argument('--create-admin', action='store_true', help="Create an administrator account")
    parser.add_argument('--seed-demo', action='store_true', help="Seed standard development users (admin & analyst)")
    parser.add_argument('--username', type=str, help="Username for account")
    parser.add_argument('--email', type=str, help="Email for account")
    parser.add_argument('--password', type=str, help="Password for account")

    args = parser.parse_args()
    app = create_app()

    init_database(app)

    if args.seed_demo:
        print("[*] Seeding default development accounts...")
        create_admin_user(app, 'admin', 'admin@cybershield.local', 'Admin@CyberShield2026!')
        create_analyst_user(app, 'analyst', 'analyst@cybershield.local', 'Analyst@CyberShield2026!')
        print("[+] Seed complete: Admin credentials -> admin / Admin@CyberShield2026!")
        print("[+] Seed complete: Analyst credentials -> analyst / Analyst@CyberShield2026!")
    elif args.create_admin:
        username = args.username or input("Enter admin username: ").strip()
        email = args.email or input("Enter admin email: ").strip()
        password = args.password or input("Enter admin password: ").strip()
        if not username or not email or not password:
            print("[-] Error: Username, email, and password cannot be empty.")
            sys.exit(1)
        create_admin_user(app, username, email, password)

if __name__ == '__main__':
    main()
