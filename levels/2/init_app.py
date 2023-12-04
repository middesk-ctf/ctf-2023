import os
from werkzeug.security import generate_password_hash

# Local imports.
from app import app, db, User

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ctfPassword1")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("Initialized Database")

        # Check if the admin user already exists to avoid duplicate entries
        admin_exists = User.query.filter_by(username='admin').first() is not None
        if not admin_exists:
            # Create a new admin user
            admin_user = User(
                username='admin',
                password_hash=generate_password_hash(ADMIN_PASSWORD),
                display_name='Admin User',
                is_admin=True
            )

            # Add the new user to the database
            db.session.add(admin_user)
            db.session.commit()
            print("Created Admin User")
