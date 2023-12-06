import logging
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps

import jwt
from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import relationship
from sqlalchemy.schema import UniqueConstraint
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv(dotenv_path=".env.local")

LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(level=LOGLEVEL)

SQLALCHEMY_DATABASE_URI = os.environ.get(
    "SQLALCHEMY_DATABASE_URI", "sqlite:///filedesk.db"
)

MAX_USERS = 10
USERNAME_PATTERN = r"^[a-z][a-z0-9]{5,11}$"
MIN_PASSWORD_LENGTH = 8

MAX_FILES_PER_USER = 10
FILENAME_PATTERN = r"^[a-zA-Z0-9_][a-zA-Z0-9_\-\.]{3,126}[a-zA-Z0-9]$"
MAX_FILE_SIZE = 10240  # 10KB


def is_valid_username(username):
    return re.match(USERNAME_PATTERN, username) is not None


def is_valid_filename(filename):
    return re.match(FILENAME_PATTERN, filename) is not None


app = Flask("Middesk CTF Level 3")
app.secret_key = os.environ.get("SESSION_KEY", "session_secret")

app.config["SQLALCHEMY_DATABASE_URI"] = SQLALCHEMY_DATABASE_URI
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Uncomment for LOTS of SQL logging.
# app.config['SQLALCHEMY_ECHO'] = True

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    email = db.Column(db.String(120), nullable=False)  # Not used for now.

    files = relationship(
        "File", backref="owner", lazy=True, cascade="all, delete-orphan"
    )
    shares = relationship(
        "FileShare", backref="recipient", cascade="all, delete-orphan"
    )

    def num_owned_files(self):
        return File.query.filter_by(owner_id=self.id).count()

    def is_file_owner(self, file):
        return self.is_admin or file.owner_id == self.id

    def is_file_viewer(self, file):
        if self.is_file_owner(file):
            return True

        shared = FileShare.query.filter_by(
            file_id=file.id, recipient_id=self.id
        ).first()

        return shared is not None

    def files_recieved(self):
        results = (
            FileShare.query.filter_by(
                # FROM file_share WHERE file_share.recipient_id = {self.id}
                recipient_id=self.id
            )
            .join(
                # JOIN file ON file.id = file_share.file_id
                File,
                File.id == FileShare.file_id,
            )
            .join(
                # JOIN user ON user.id = file_share.owner_id
                User,
                User.id == File.owner_id,
            )
            .with_entities(
                # SELECT user.id, user.username, user.dispay_name, file.id, file.filename
                User.id,
                User.username,
                User.display_name,
                File.id,
                File.filename,
            )
            .all()
        )

        # Build a map of each owner_id to (owner_username, display_name)
        owner_info = {}
        # Build a map of each owner_id to list of {file_id, filename}
        files_by_owner = defaultdict(list)
        for owner_id, owner_username, owner_display_name, file_id, filename in results:
            owner_info[owner_id] = (owner_username, owner_display_name)
            files_by_owner[owner_id].append(
                {
                    "id": file_id,
                    "filename": filename,
                }
            )

        owner_files = []
        for owner_id, (owner_username, owner_display_name) in owner_info.items():
            owner_files.append(
                {
                    "owner": {
                        "id": owner_id,
                        "username": owner_username,
                        "display_name": owner_display_name,
                    },
                    "files": files_by_owner[owner_id],
                }
            )

        return owner_files


class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(
        db.Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )
    filename = db.Column(db.String(255), nullable=False)
    content = db.Column(db.LargeBinary, nullable=False)
    content_type = db.Column(db.String(120), default="text/plain", nullable=False)

    shares = relationship("FileShare", backref="file", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("owner_id", "filename", name="_owner_filename_uc"),
    )


class FileShare(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    file_id = db.Column(
        db.Integer, ForeignKey("file.id", ondelete="CASCADE"), nullable=False
    )
    recipient_id = db.Column(
        db.Integer, ForeignKey("user.id", ondelete="CASCADE"), nullable=False
    )

    __table_args__ = (
        UniqueConstraint("file_id", "recipient_id", name="_file_recipient_uc"),
    )


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
            if not auth_user:
                raise ValueError("user not found")
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


@app.route("/add-file", methods=["GET"])
def add_file_page():
    return render_template("add-file.html")


@app.route("/view-file/<int:file_id>", methods=["GET"])
def view_file_page(file_id):
    return render_template("view-file.html", file_id=file_id)


@app.route("/file-sharing/<int:file_id>", methods=["GET"])
def view_file_sharing(file_id):
    return render_template("file-sharing.html", file_id=file_id)


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

    return jsonify({"token": create_token(new_user)}), 201


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

    return jsonify({"token": create_token(user)}), 201


@app.route("/v1/users", methods=["GET"])
@require_auth_user
def v1_list_users(auth_user):
    user_list = []
    for user in User.query.all():
        user_list.append(
            {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "is_admin": user.is_admin,
            }
        )
    return jsonify({"users": user_list})


@app.route("/v1/user", methods=["GET", "PATCH"])
def v1_current_user():
    if request.method == "GET":
        return v1_get_current_user()

    return v1_patch_current_user()


@require_auth_user
def v1_get_current_user(auth_user):
    user = auth_user
    return (
        jsonify(
            {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "is_admin": user.is_admin,
            }
        ),
        200,
    )


@require_json
@require_auth_user
def v1_patch_current_user(auth_user):
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
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "is_admin": user.is_admin,
            }
        ),
        200,
    )


@app.route("/v1/users/<username>", methods=["GET"])
@require_auth_user
def v1_user(username, auth_user):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"message": "User not found"}), 404

    return (
        jsonify(
            {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "is_admin": user.is_admin,
            }
        ),
        200,
    )


@app.route("/v1/files", methods=["GET"])
@require_auth_user
def v1_list_files(auth_user):
    owned_files = [
        {
            "id": file.id,
            "filename": file.filename,
        }
        for file in auth_user.files
    ]

    received_files = auth_user.files_recieved()
    print(received_files)

    return (
        jsonify(
            {
                "owned_files": owned_files,
                "received_files": received_files,
            }
        ),
        200,
    )


@app.route("/v1/files", methods=["POST"])
@require_auth_user
def v1_create_file(auth_user):
    if auth_user.num_owned_files() >= MAX_FILES_PER_USER:
        return (
            jsonify({"message": "Sorry. You've reached the limit on number of files!"}),
            400,
        )

    data = request.get_json()
    filename = data.get("filename", "")
    content = data.get("content", "").encode()

    # Validate Filename
    if not is_valid_filename(filename):
        return (
            jsonify({"message": f"Invalid filename: must match: {FILENAME_PATTERN}"}),
            400,
        )

    # Validate Content
    if len(content) > MAX_FILE_SIZE:
        return (
            jsonify(
                {
                    "message": f"Invalid content: must be at most {MAX_FILE_SIZE} characters"
                }
            ),
            400,
        )

    new_file = File(
        owner=auth_user,
        filename=filename,
        content=content,
    )

    try:
        db.session.add(new_file)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"message": "That filename already exists!"}), 400

    return (
        jsonify(
            {
                "message": "File successfully created",
                "id": new_file.id,
            }
        ),
        201,
    )


@app.route("/v1/files/<int:id>", methods=["GET", "DELETE"])
@require_auth_user
def v1_file(id, auth_user):
    file = db.session.query(File).get(id)

    # Check that the file exists and that the user can access it.
    if not (file or auth_user.is_file_viewer(file)):
        return jsonify({"message": "File Not Found"}), 404

    if request.method == "DELETE":
        return v1_delete_file(file, auth_user)

    return v1_get_file(file)


def v1_get_file(file):
    return (
        jsonify(
            {
                "id": file.id,
                "filename": file.filename,
                "owner": {
                    "id": file.owner.id,
                    "username": file.owner.username,
                    "display_name": file.owner.display_name,
                },
                "content": file.content.decode(),
                "content_type": file.content_type,
            }
        ),
        200,
    )


def v1_delete_file(file, auth_user):
    # Check that the auth_user can delete it.
    if not auth_user.is_file_owner(file):
        return jsonify({"message": "Permission Denied"}), 403

    db.session.delete(file)
    db.session.commit()

    return "", 204


@app.route("/v1/files/<int:id>/shares", methods=["GET"])
@require_auth_user
def v1_file_shares(id, auth_user):
    file = File.query.get(id)
    if not (file or auth_user.is_file_viewer(file)):
        return jsonify({"message": "File Not Found"}), 404

    if not auth_user.is_file_owner(file):
        return jsonify({"message": "Permission Denied"}), 403

    # Return a list of {username, display_name} for all users
    # which are a recipient of a file share for this file.
    results = (
        FileShare.query.filter_by(file_id=file.id)
        .join(
            User,
            User.id == FileShare.recipient_id,
        )
        .with_entities(User.id, User.username, User.display_name)
        .all()
    )

    shares = []
    for user_id, username, display_name in results:
        shares.append(
            {
                "id": user_id,
                "username": username,
                "display_name": display_name,
            }
        )

    return jsonify({"shares": shares}), 200


@app.route(
    "/v1/files/<int:file_id>/shares/<int:recipient_id>", methods=["PUT", "DELETE"]
)
@require_auth_user
def v1_file_share(file_id, recipient_id, auth_user):
    file = File.query.get(file_id)

    if not (file or auth_user.is_file_viewer(file)):
        return jsonify({"message": "File Not Found"}), 404

    if not auth_user.is_file_owner(file):
        return jsonify({"message": "Permission Denied"}), 403

    if request.method == "PUT":
        return v1_create_file_share(file, recipient_id)

    return v1_delete_file_share(file, recipient_id)


def v1_create_file_share(file, recipient_id):
    if recipient_id == file.owner_id:
        return jsonify({"message": "File already owned by this user"}), 400

    # Create file share and check for integrity error
    # (repeat share) in which case return OK anyway.
    new_share = FileShare(file_id=file.id, recipient_id=recipient_id)

    try:
        db.session.add(new_share)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()

    return jsonify({"message": "File share successfully created"}), 201


def v1_delete_file_share(file, recipient_id):
    share = FileShare.query.filter_by(
        file_id=file.id, recipient_id=recipient_id
    ).first()

    # Ok if it already doesn't exist.
    if share:
        db.session.delete(share)
        db.session.commit()

    return "", 204


if __name__ == "__main__":
    debug = LOGLEVEL == "DEBUG"
    app.run(debug=debug, port=3000)
