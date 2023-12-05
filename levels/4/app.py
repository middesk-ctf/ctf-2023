import logging
import os
import re
from datetime import datetime, timezone
from functools import wraps

import jwt
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
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv(dotenv_path=".env.local")

LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(level=LOGLEVEL)

SQLALCHEMY_DATABASE_URI = os.environ.get(
    "SQLALCHEMY_DATABASE_URI", "sqlite:///filedesk.db"
)

USERNAME_PATTERN = r"^[a-z][a-z0-9]{5,11}$"
MIN_PASSWORD_LENGTH = 8
MAX_USERS = 10


def is_valid_username(username):
    return re.match(USERNAME_PATTERN, username) is not None


app = Flask("Middesk CTF Level 3")
app.secret_key = os.environ.get("SESSION_KEY", "session_secret")

app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    email = db.Column(db.String(120), nullable=False)


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), unique=True, nullable=False)
    content = db.Column(db.LargeBinary, nullable=False)


def get_user_from_db(username):
    # Returns None if there is no such user.
    return User.query.filter_by(username=username).first()


def require_json(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({"message": "Content type must be JSON"}), 400
        return f(*args, **kwargs)

    return decorated_function


def require_auth_user(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = get_auth_token()
            auth_user = get_auth_user(token)
        except Exception as e:
            print(f"Unable to authenticate client: {e}")
            return jsonify({"message": f"Authentication error: {e}"}), 401
        return f(*args, auth_user=auth_user, **kwargs)

    return decorated_function


def require_admin(f):
    @wraps(f)
    @require_auth_user
    def decorated_function(*args, auth_user, **kwargs):
        if not auth_user.is_admin:
            return jsonify({"message": "Admin required"}), 403
        return f(*args, admin=auth_user, **kwargs)

    return decorated_function


def get_auth_user(token):
    data = jwt.decode(token, app.secret_key)

    expires_at = data.get("exp", 0)
    now = datetime.now(tz=timezone.utc).timestamp()
    if expires_at <= now:
        raise ValueError("token expired")

    username = data.get("sub", "")
    return get_user_from_db(username)


def create_token(user):
    # expires 12 hours from now.
    expires_at = int(datetime.now(tz=timezone.utc).timestamp()) + (12 * 60 * 60)
    data = {
        "sub": user.username,
        "is_admin": user.is_admin,
        "exp": expires_at,
    }
    return jwt.encode(data, app.secret_key)


def get_auth_token():
    # Retrieve the Authorization header
    auth_header = request.headers.get("Authorization")

    if auth_header is None:
        raise ValueError("authorization header required")

    # Split the header into 'Bearer' and the token
    parts = auth_header.split()

    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise ValueError("invalid authorization header")

    return parts[1]


@app.route("/", methods=["GET"])
def landing_page():
    return render_template("index.html")


@app.route("/signup", methods=["GET"])
def signup_page():
    return render_template("signup.html")


@app.route("/login", methods=["GET"])
def login_page():
    return render_template("login.html")


@app.route("/profile", methods=["GET"])
def profile_page():
    return render_template("profile.html")


@app.route("/edit-profile", methods=["GET"])
def edit_profile_page():
    return render_template("edit-profile.html")


@app.route("/files", methods=["GET"])
def files_page():
    return render_template("files.html")


@app.route("/view-file/<int:id>", methods=["GET"])
def view_file_page(id):
    return render_template("view-file.html", file_id=id)


@app.route("/v1/signup", methods=["POST"])
@require_json
def v1_signup():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

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

    return jsonify({"token": create_token(new_user)}), 200


@app.route("/v1/login", methods=["POST"])
@require_json
def v1_login():
    data = request.get_json()
    username = data.get("username", "")
    password = data.get("password", "")

    # Lookup user in database.
    user = get_user_from_db(username)
    if not user:
        return jsonify({"message": "Incorrect username or password"}), 401

    # Verify password hash.
    if not check_password_hash(user.password_hash, password):
        return jsonify({"message": "Incorrect username or password"}), 401

    return jsonify({"token": create_token(user)}), 200


@app.route("/v1/users", methods=["GET"])
@require_auth_user
def v1_users(auth_user):
    user_list = []
    for user in User.query.all():
        user_list.append(
            {
                "username": user.username,
                "display_name": user.display_name,
                "is_admin": user.is_admin,
            }
        )
    return jsonify({"users": user_list})


@app.route("/v1/user", methods=["GET", "PATCH"])
def v1_user():
    if request.method == "GET":
        return v1_get_user()

    return v1_patch_user()


@require_auth_user
def v1_get_user(auth_user):
    user = auth_user
    return (
        jsonify(
            {
                "username": user.username,
                "display_name": user.display_name,
                "is_admin": user.is_admin,
            }
        ),
        200,
    )


@require_json
@require_auth_user
def v1_patch_user(auth_user):
    data = request.get_json()
    display_name = data.get("display_name", "")

    if len(display_name) < 2:
        return jsonify({"message": "Display name too short"}), 400
    if len(display_name) > 30:
        return jsonify({"message": "Display name too long"}), 400

    user = auth_user
    user.display_name = display_name
    db.session.commit()

    return (
        jsonify(
            {
                "username": user.username,
                "display_name": user.display_name,
                "is_admin": user.is_admin,
            }
        ),
        200,
    )


@app.route("/v1/files", methods=["GET"])
@require_admin
def list_files(admin):
    files = File.query.options(db.defer(File.content)).all()
    file_list = []
    for file in files:
        file_list.append(
            {
                "id": file.id,
                "filename": file.filename,
            }
        )
    return jsonify({"files": file_list}), 200


@app.route("/v1/files/<int:id>", methods=["GET"])
@require_admin
def v1_get_file(id, admin):
    file = File.query.get(id)
    if not file:
        return jsonify({"message": "File not found"}), 404

    return (
        jsonify(
            {
                "id": file.id,
                "filename": file.filename,
                "content": file.content.decode(),
            }
        ),
        200,
    )


if __name__ == "__main__":
    debug = LOGLEVEL == "DEBUG"
    app.run(debug=debug, port=3000)
