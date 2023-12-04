import logging
import os
import time

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

load_dotenv(dotenv_path=".env.local")

LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(level=LOGLEVEL)

app = Flask("Middesk CTF Level 1")
app.secret_key = os.environ.get("SESSION_KEY", "session_secret")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "ctfPassword1").encode("utf-8")
SECRET_FLAG = os.environ.get("SECRET_FLAG", "FLAG_random_stuff")

# Hardcoded files for demonstration purposes.
files = {
    1: {"name": "SECRET_FLAG.txt", "contents": SECRET_FLAG},
    2: {
        "name": "shopping-list.txt",
        "contents": "Shopping List:\n- Loaf of Bread\n- Container of Milk\n- Stick of Butter\n",
    },
    3: {"name": "plans.txt", "contents": "Take over the world!\n"},
}


@app.route("/", methods=["GET"])
def root():
    # Redirect to login if not authenticated.
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    # Redirect to files list if authenticated.
    return redirect(url_for("list_files"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if session.get("authenticated"):
            return redirect(url_for("list_files"))
        return render_template("login.html")

    password = request.form.get("password", "").encode("utf-8")

    # Haven't bothered implementing real password hashing yet but this
    # seems good enough.
    for i, char in enumerate(password):
        if i >= len(ADMIN_PASSWORD) or char != ADMIN_PASSWORD[i]:
            # Password verification needs to be slow so that it's harder to
            # brute force, so sleep for 100ms if a charecter is wrong.
            time.sleep(0.1)
            return jsonify({"message": "Incorrect password"}), 401

    if len(password) < len(ADMIN_PASSWORD):
        return jsonify({"message": "Incorrect password"}), 401

    session["authenticated"] = True
    return jsonify({"message": "Login successful"}), 200


@app.route("/logout", methods=["POST"])
def logout():
    session.pop("authenticated", None)
    return jsonify({"message": "Logout successful"}), 200


@app.route("/files", methods=["GET"])
def list_files():
    if not session.get("authenticated"):
        return jsonify({"message": "Unauthenticated"}), 401

    return render_template("files.html", files=files)


@app.route("/files/<int:id>", methods=["GET"])
def download_file(id):
    if not session.get("authenticated"):
        return jsonify({"message": "Unauthenticated"}), 401

    file = files.get(id)
    if not file:
        return jsonify({"message": "File not found"}), 404

    file_contents = file.get("contents", "")
    return Response(file_contents, status=200, mimetype="text/plain")


if __name__ == "__main__":
    debug = LOGLEVEL == "DEBUG"
    app.run(debug=debug, port=3000)
