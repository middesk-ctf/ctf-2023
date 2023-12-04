import logging
import os

from dotenv import load_dotenv
from flask_sqlalchemy import SQLAlchemy
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

load_dotenv(dotenv_path=".env.local")

LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(level=LOGLEVEL)

SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI", "sqlite:///filedesk.db")
SECRET_FLAG = os.environ.get("SECRET_FLAG", "FLAG_random_stuff")

app = Flask("Middesk CTF Level 2")
app.secret_key = os.environ.get("SESSION_KEY", "session_secret")

app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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


@app.route("/", methods=["GET"])
def root():
    # Redirect to profile if authenticated.
    if session.get("authenticated"):
        return redirect(url_for("profile"))

    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        # Redirect to profile if authenticated.
        if session.get("authenticated"):
            return redirect(url_for("profile"))
        return render_template("signup.html")
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')

    # TODO:
    # Validate username:
    # - check it meets regex `^[a-z0-9]{6,12}$`
    # - check it is not already taken
    # Validate Password:
    # - Must be at least 8 characters long

    # Add user to database
    # - Reuse username for display name
    # - Set is_admin to false
    return jsonify({"message": "Signup successful"}), 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("authenticated"):
            return redirect(url_for("profile"))
        return render_template("login.html")

    username = request.form.get('username', "")
    password = request.form.get("password", "")

    # Lookup user in database.
    # Verify password hash.

    session["authenticated"] = True
    session["username"] = username

    return jsonify({"message": "Login successful"}), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("authenticated", None)
    session.pop("username", None)
    return jsonify({"message": "Logout successful"}), 200


@app.route("/profile", methods=["GET", "POST"])
def profile():
    if request.method == "GET":
        if not session.get("authenticated"):
            return redirect(url_for("root"))
        
        username = session.get("username")
        # Lookup user in database.
        
        return render_template("profile.html", user=user)
    
    if not session.get("authenticated"):
        return jsonify({"message": "Unauthenticated"}), 401
    
    username = session.get("username")
    # Lookup user in database.

    display_name = request.form.get("display_name", "")

    # Validate the display name.
    # - Make sure it isn't empty (min 2 characters)
    # - Make sure it isn't too long (max 30 characters)
    # - Make sure it doesn't have a semi-colon or hyphen (catch sql injection attacks)

    # Update the user's display name in the database.

    return jsonify({"message": "User profile update"}), 200


@app.route("/edit-profile", methods=["GET"])
def edit_profile():
    if not session.get("authenticated"):
        return redirect(url_for("root"))
    return render_template("edit-profile.html")


@app.route("/files", methods=["GET"])
def list_files():
    if not session.get("authenticated"):
        return redirect(url_for("root"))
    
    username = session.get("username")
    # Lookup User in database.
    # Ensure they are an admin user.
    # Redirect to profile page if not an admin.

    return render_template("files.html", files=files)


@app.route("/files/<int:id>", methods=["GET"])
def download_file(id):
    if not session.get("authenticated"):
        return redirect(url_for("root"))
    
    username = session.get("username")
    # Lookup User in database.
    # Ensure they are an admin user.
    # Redirect to profile page if not an admin.

    file = files.get(id)
    if not file:
        return jsonify({"message": "File not found"}), 404

    file_contents = file.get("contents", "")
    return Response(file_contents, status=200, mimetype="text/plain")


if __name__ == "__main__":
    debug = LOGLEVEL == "DEBUG"
    app.run(debug=debug, port=3000)
