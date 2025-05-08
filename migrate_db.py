# Save this as migrate_db.py
from app import app, db
from sqlalchemy import text

def add_admin_column():
    """Add the is_admin column to the user table and set an admin user"""
    with app.app_context():
        # Check if the column already exists to avoid errors
        try:
            # Try to add the column
            db.session.execute(text("ALTER TABLE user ADD COLUMN is_admin BOOLEAN DEFAULT FALSE"))
            print("Added is_admin column to user table")
            
            # Set your admin user (change this email to match an existing user)
            admin_email = "admin@example.com"  # Change this to an existing user's email
            db.session.execute(text(f"UPDATE user SET is_admin = TRUE WHERE email = '{admin_email}'"))
            print(f"Set {admin_email} as admin")
            
            db.session.commit()
            print("Database migration completed successfully!")
        except Exception as e:
            db.session.rollback()
            if "duplicate column name" in str(e).lower():
                print("is_admin column already exists. No changes needed.")
            else:
                print(f"Error during migration: {e}")

if __name__ == "__main__":
    add_admin_column()