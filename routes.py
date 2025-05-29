from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.fields import EmailField
from wtforms.validators import DataRequired, Email, Length, ValidationError
import requests
from datetime import datetime
import json
from config import Config
from models import User
from extensions import db

# Create blueprints
main = Blueprint('main', __name__, url_prefix='/')
auth = Blueprint('auth', __name__, url_prefix='/auth')

# Form Classes
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=3, max=80, message='Username must be between 3 and 80 characters')
    ])
    email = EmailField('Email', validators=[
        DataRequired(),
        Email(message='Please enter a valid email address')
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=Config.MIN_PASSWORD_LENGTH, 
               message=f'Password must be at least {Config.MIN_PASSWORD_LENGTH} characters long')
    ])

    def validate_username(self, field):
        if User.query.filter_by(username=field.data).first():
            raise ValidationError('Username already exists')

    def validate_email(self, field):
        if User.query.filter_by(email=field.data).first():
            raise ValidationError('Email already registered')

def load_payloads():
    try:
        with open("cve_payloads.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def load_inputs():
    try:
        with open("cve_inputs.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def fetch_cve_data(include_sensitive=False):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {'apiKey': Config.NVD_API_KEY}
    
    xss_cves = []
    start_index = 0
    total_results = 1
    page_size = 200
    
    payloads = load_payloads() if include_sensitive else {}
    inputs = load_inputs() if include_sensitive else {}
    
    while start_index < total_results:
        try:
            params = {
                "keywordSearch": "xss",
                "pubStartDate": Config.CVE_START_DATE,
                "pubEndDate": Config.CVE_END_DATE,
                "resultsPerPage": page_size,
                "startIndex": start_index
            }
            
            response = requests.get(
                url, 
                headers=headers, 
                params=params,
                timeout=Config.NVD_API_TIMEOUT
            )
            response.raise_for_status()
            data = response.json()
            
            total_results = data.get("totalResults", 0)
            
            for item in data.get("vulnerabilities", []):
                cve_id = item["cve"]["id"]
                desc_raw = item["cve"]["descriptions"][0]["value"]
                desc_lower = desc_raw.lower()
                
                published_date = item["cve"]["published"]
                try:
                    date_obj = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
                    formatted_date = date_obj.strftime("%B %d, %Y")
                except:
                    formatted_date = "Date not available"

                if "stored xss" in desc_lower:
                    xss_type = "Stored XSS"
                elif "reflected xss" in desc_lower:
                    xss_type = "Reflected XSS"
                elif "dom-based xss" in desc_lower or "dom xss" in desc_lower:
                    xss_type = "DOM XSS"
                elif "xss" in desc_lower:
                    xss_type = "XSS"
                else:
                    continue

                try:
                    severity = item["cve"]["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
                except:
                    severity = "Unknown"

                cve_data = {
                    "type": xss_type,
                    "cve": cve_id,
                    "description": desc_raw,
                    "severity": severity,
                    "published_date": formatted_date
                }

                if include_sensitive:
                    cve_data.update({
                        "input": inputs.get(cve_id, "Not Publicly Disclosed"),
                        "mitre": payloads.get(cve_id, "Not Publicly Disclosed")
                    })

                xss_cves.append(cve_data)
                
            start_index += page_size
            
        except requests.RequestException as e:
            flash(f"Error fetching CVE data: {str(e)}", "error")
            return []
            
    return xss_cves

# Main routes
@main.route("/")
def main_index():
    include_sensitive = current_user.is_authenticated
    xss_cves = fetch_cve_data(include_sensitive)
    return render_template("index.html", xss_cves=xss_cves)

@main.route('/cve/<cve_id>')
def cve_details(cve_id):
    xss_cves = fetch_cve_data(include_sensitive=current_user.is_authenticated)
    cve_data = next((cve for cve in xss_cves if cve['cve'] == cve_id), None)
    
    if cve_data is None:
        flash('CVE not found')
        return redirect(url_for('main.main_index'))
    
    if not current_user.is_authenticated:
        # Still show basic CVE info but without sensitive data
        return render_template('cve_details.html', cve=cve_data)
    
    return render_template('cve_details.html', cve=cve_data)

# Auth routes
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.main_index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            if next_page:
                # Validate that next_page is a relative URL to prevent open redirect
                if not next_page.startswith('/'):
                    next_page = None
            flash('Logged in successfully.', 'success')
            return redirect(next_page or url_for('main.main_index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html', form=form)

@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('main.main_index'))
        
    form = SignupForm()
    if form.validate_on_submit():
        try:
            user = User()
            user.username = form.username.data
            user.email = form.email.data
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('auth.signup'))
    
    # If form validation failed, errors will be shown in the template
    return render_template('signup.html', form=form)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.')
    return redirect(url_for('main.main_index')) 