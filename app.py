from flask import Flask
from flask_login import LoginManager
from config import Config
from database.db_models import db, User
from pathlib import Path

login_manager = LoginManager()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Ensure required directories exist
    for folder in [
        app.config['UPLOAD_FOLDER'],
        app.config['REPORTS_FOLDER'],
        app.config['MODELS_FOLDER'],
        app.config['DATASETS_FOLDER'],
    ]:
        Path(folder).mkdir(parents=True, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login_page'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # Register blueprints
    from routes.auth_routes import auth_bp
    from routes.dashboard_routes import dashboard_bp
    from routes.dataset_routes import dataset_bp
    from routes.analysis_routes import analysis_bp
    from routes.alert_routes import alert_bp
    from routes.simulation_routes import simulation_bp
    from routes.report_routes import report_bp
    from routes.pages_routes import pages_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(dataset_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(alert_bp)
    app.register_blueprint(simulation_bp)
    app.register_blueprint(report_bp)
    app.register_blueprint(pages_bp)

    with app.app_context():
        db.create_all()

    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, host='127.0.0.1', port=5000)
