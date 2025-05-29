from flask import render_template
import logging
from logging.handlers import RotatingFileHandler
import os

def configure_logging(app):
    """Configure logging for the application."""
    if not os.path.exists('logs'):
        os.mkdir('logs')
        
    # Set up file handler
    file_handler = RotatingFileHandler(
        'logs/app.log', 
        maxBytes=10240,  # 10KB
        backupCount=10
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

def register_error_handlers(app):
    """Register error handlers for common HTTP errors."""
    
    @app.errorhandler(400)
    def bad_request_error(error):
        app.logger.error(f'Bad Request: {error}')
        return render_template('errors/400.html'), 400

    @app.errorhandler(401)
    def unauthorized_error(error):
        app.logger.error(f'Unauthorized access attempt: {error}')
        return render_template('errors/401.html'), 401

    @app.errorhandler(403)
    def forbidden_error(error):
        app.logger.error(f'Forbidden access attempt: {error}')
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found_error(error):
        app.logger.error(f'Page not found: {error}')
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def ratelimit_error(error):
        app.logger.warning(f'Rate limit exceeded: {error}')
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f'Server Error: {error}')
        return render_template('errors/500.html'), 500

    @app.errorhandler(Exception)
    def unhandled_exception(error):
        app.logger.error(f'Unhandled Exception: {error}', exc_info=True)
        return render_template('errors/500.html'), 500 