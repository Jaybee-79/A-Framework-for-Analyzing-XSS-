from flask import Flask
from config import Config
from extensions import db, login_manager, csrf

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    
    # Configure login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Please log in to view CVE inputs and payloads."
    
    # Register blueprints
    from routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    from routes import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    # Initialize database
    with app.app_context():
        db.create_all()
    
    return app

# Create the app instance
app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
