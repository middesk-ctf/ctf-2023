import logging
import os
import re

from dotenv import load_dotenv
from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import text
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv(dotenv_path=".env.local")

LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(level=LOGLEVEL)

SQLALCHEMY_DATABASE_URI = os.environ.get(
    "SQLALCHEMY_DATABASE_URI", "sqlite:///filedesk.db"
)
SECRET_FLAG = os.environ.get("SECRET_FLAG", "FLAG_random_stuff")

USERNAME_PATTERN = r"^[a-z][a-z0-9]{5,11}$"
MIN_PASSWORD_LENGTH = 8
MAX_USERS = 10


def is_valid_username(username):
    return re.match(USERNAME_PATTERN, username) is not None


app = Flask("Middesk CTF Level 2")
app.secret_key = os.environ.get("SESSION_KEY", "session_secret")

app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# Hardcoded files for proof of concept purposes.
files = {
    1: {"name": "SECRET_FLAG.txt", "contents": SECRET_FLAG},
    2: {
        "name": "shopping-list.txt",
        "contents": "Shopping List:\n- Loaf of Bread\n- Container of Milk\n- Stick of Butter\n",
    },
    3: {"name": "plans.txt", "contents": "Take over the world!\n"},
}


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    email = db.Column(db.String(120), nullable=False)


def get_user(username):
    # Returns None if there is no such user.
    return User.query.filter_by(username=username).first()


def get_session_user():
    return get_user(session.get("username", ""))


@app.route("/", methods=["GET"])
def root():
    # Redirect to profile if authenticated.
    if get_session_user():
        return redirect(url_for("profile"))

    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        # Redirect to profile if authenticated.
        if get_session_user():
            return redirect(url_for("profile"))
        return render_template("signup.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if not is_valid_username(username):
        return (
            jsonify({"message": f"Invalid username: must match: {USERNAME_PATTERN}"}),
            400,
        )

    if len(password) < MIN_PASSWORD_LENGTH:
        return (
            jsonify(
                {
                    "message": f"Invalid password: must be at least {MIN_PASSWORD_LENGTH} characters"
                }
            ),
            400,
        )

    # Check the number of users
    user_count = User.query.count()
    if user_count >= MAX_USERS:
        return (
            jsonify({"message": "Sorry. We're currently not allowing more users!"}),
            400,
        )

    new_user = User(
        username=username,
        password_hash=generate_password_hash(password),
        display_name=username,
        is_admin=False,
        email="",  # Not used yet
    )

    try:
        db.session.add(new_user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "That username already exists!"}), 400

    session["username"] = username

    return jsonify({"message": "Signup successful"}), 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if get_session_user():
            return redirect(url_for("profile"))
        return render_template("login.html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # Lookup user in database.
    user = get_user(username)
    if not user:
        return jsonify({"message": "Incorrect username or password"}), 401

    # Verify password hash.
    if not check_password_hash(user.password_hash, password):
        return jsonify({"message": "Incorrect username or password"}), 401

    session["username"] = username

    return jsonify({"message": "Login successful"}), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("authenticated", None)
    session.pop("username", None)
    return jsonify({"message": "Logout successful"}), 200


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = get_session_user()
    if request.method == "GET":
        if not user:
            return redirect(url_for("root"))
        return render_template("profile.html", user=user)

    if not user:
        return jsonify({"message": "Unauthenticated"}), 401

    username = user.username
    display_name = request.form.get("display_name", "")

    if len(display_name) < 2:
        return jsonify({"message": "Display name too short"}), 400
    if len(display_name) > 30:
        return jsonify({"message": "Display name too long"}), 400

    # Make sure the display_name doesn't have a semi-colon or
    # hyphen (to protect against SQL injection attacks)
    if "-" in display_name or ";" in display_name:
        return (
            jsonify({"message": "Display name may not contain '-' or ';' characters"}),
            400,
        )

    try:
        statement = text(
            f'UPDATE user SET display_name = "{display_name}" WHERE username = "{username}";'
        )
        db.session.execute(statement)
        db.session.commit()
    except Exception as e:
        print(f"error: {e}")
        return jsonify({"message": "An unexpected error occurred"}), 500

    return jsonify({"message": "User profile updated"}), 200


@app.route("/edit-profile", methods=["GET"])
def edit_profile():  #
    if not get_session_user():
        return redirect(url_for("root"))
    return render_template("edit-profile.html")


@app.route("/files", methods=["GET"])
def list_files():
    user = get_session_user()
    if not user:
        return redirect(url_for("root"))

    # Ensure they are an admin user.
    if not user.is_admin:
        # Redirect to profile page if not an admin.
        return redirect(url_for("profile"))

    return render_template("files.html", files=files)


@app.route("/files/<int:id>", methods=["GET"])
def download_file(id):
    user = get_session_user()
    if not user:
        return redirect(url_for("root"))

    # Ensure they are an admin user.
    if not user.is_admin:
        # Redirect to profile page if not an admin.
        return redirect(url_for("profile"))

    file = files.get(id)
    if not file:
        return jsonify({"message": "File not found"}), 404

    file_contents = file.get("contents", "")
    return Response(file_contents, status=200, mimetype="text/plain")


if __name__ == "__main__":
    debug = LOGLEVEL == "DEBUG"
    app.run(debug=debug, port=3000)
