# XSS CVE Viewer

A web application for viewing and analyzing Cross-Site Scripting (XSS) vulnerabilities from the CVE database.

## Features

- View XSS-related CVEs
- Secure user authentication
- Protected payload viewing
- Rate limiting and security headers
- Input validation and sanitization

## Tech Stack

- Python 3.x
- Flask
- SQLite
- SQLAlchemy
- Flask-Login for authentication
- Flask-WTF for forms and CSRF protection
- Flask-Talisman for security headers
- Flask-Limiter for rate limiting

## Local Development Setup

1. Clone the repository:
```bash
git clone <your-repo-url>
cd cve-xss-app
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
Create a `.env` file in the root directory with:
```
SECRET_KEY=your-secret-key
NVD_API_KEY=your-nvd-api-key
FORCE_HTTPS=False
```

5. Initialize the database:
```bash
python init_db.py
```

6. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Deployment

This application is configured for deployment on Render. Required files are included:
- `requirements.txt`: Python dependencies
- `Procfile`: Gunicorn web server configuration

## Security Features

- CSRF Protection
- Rate Limiting
- Security Headers
- Password Policy Enforcement
- Input Validation
- Error Logging
- Secure Session Management

## License

MIT License 