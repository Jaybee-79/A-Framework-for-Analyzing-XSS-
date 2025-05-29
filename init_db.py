from app import create_app
from extensions import db
from models import User
import os

def init_db():
    # Create a new app instance
    app = create_app()
    
    # Push an application context
    with app.app_context():
        # Remove existing database file if it exists
        if os.path.exists('users.db'):
            os.remove('users.db')
            print("Removed existing database.")
        
        # Create all tables
        db.create_all()
        print("Created new database with updated schema.")
        
        # Create a test user
        test_user = User()
        test_user.username = "admin"
        test_user.email = "admin@example.com"
        test_user.set_password("AdminTest@123456")  # Strong password that meets all requirements
        
        # Add and commit the test user
        db.session.add(test_user)
        db.session.commit()
        print("Created test user 'admin' with password 'AdminTest@123456'")

if __name__ == "__main__":
    init_db() 