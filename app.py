
from flask import Flask
from config import Config
from extensions import db, login_manager, csrf, limiter
from flask_talisman import Talisman
from error_handlers import configure_logging, register_error_handlers

def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.from_object(Config)
    
    # Initialize Talisman for security headers
    csp = {
        'default-src': "'self'",
        'script-src': ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com'],
        'style-src': ["'self'", 'cdn.jsdelivr.net', 'cdnjs.cloudflare.com', "'unsafe-inline'"],
        'font-src': ["'self'", 'cdnjs.cloudflare.com'],
        'img-src': ["'self'", 'data:', 'https:'],
    }
    
    # Only force HTTPS in production
    force_https = app.config.get('FORCE_HTTPS', False)
    
    Talisman(app,
             force_https=force_https,
             strict_transport_security=force_https,
             session_cookie_secure=force_https,
             session_cookie_http_only=True,
             content_security_policy=csp)
    
    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    
    # Configure login
    login_manager.login_view = 'auth.login'
    login_manager.login_message = "Please log in to view CVE inputs and payloads."
    
    # Register blueprints
    from routes import main as main_blueprint
    app.register_blueprint(main_blueprint)
    
    from routes import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)
    
    # Configure logging and error handlers
    configure_logging(app)
    register_error_handlers(app)
    
    # Initialize database
    with app.app_context():
        db.create_all()
    
    return app

# Create the app instance
app = create_app()

if __name__ == "__main__":
    app.run(debug=False)  # Set debug=False in production
