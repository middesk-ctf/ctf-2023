import os

from werkzeug.security import generate_password_hash

# Local imports.
from app import File, User, app, db

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ctfPassword1")
SECRET_FLAG = os.environ.get("SECRET_FLAG", "FLAG_random_stuff")

# Initial files for admins
files = [
    {"filename": "SECRET_FLAG.txt", "content": SECRET_FLAG},
    {
        "filename": "shopping-list.txt",
        "content": "Shopping List:\n- Loaf of Bread\n- Container of Milk\n- Stick of Butter\n",
    },
    {"filename": "plans.txt", "content": "Take over the world!\n"},
    {"filename": "plans.txt", "content": "Take over the world!\n"},
]


def create_admin():
    admin = User.query.filter_by(username="admin").first()
    if admin is None:
        # Create a new admin user
        new_user = User(
            username="admin",
            password_hash=generate_password_hash(ADMIN_PASSWORD),
            display_name="Admin User",
            is_admin=True,
            email="",  # Not used yet
        )

        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        print("Created Admin User")


def create_files():
    admin = User.query.filter_by(username="admin").first()
    for file in files:
        filename = file.get("filename")
        content = file.get("content").encode()
        file_exists = File.query.filter_by(filename=filename).first() is not None
        if not file_exists:
            new_file = File(
                owner=admin,
                filename=filename,
                content=content,
            )
            db.session.add(new_file)
            db.session.commit()
            print(f"Created file {filename}")


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_admin()
        create_files()
