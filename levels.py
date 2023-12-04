from google.cloud import firestore

LEVEL_1_DESCRIPTION = """
You're the newest employee at Pendesk, Inc., a reputable penetration testing and security consulting agency!
Your first client is Filedesk, Inc., which is developing a new file storage and sharing application. Their app is still in early development, but they realize that security is important if they're going to be storing users' sensitive files so they've contracted Pendesk to evaluate their applications security (or at least check a box for compliance reasons :white_check_mark:).

The Filedesk app is currently only a simple login page for admin users. Once logged in, an admin can access any file on the system. No other features have been implemented yet, but your team was reviewing the code so far and identified an issue with the way admin passwords are verified, potentially allowing a malicious client to crack the admin password!

Here's their code:

```
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
```

You brought this up to the developers of Filedesk but they disagree about the severity of the issue, and don't think it's realistically exploitable. Your task is to prove them wrong! They've added a file called `SECRET_FLAG.txt` to their system and are only willing to fix their password verification if you can get its contents. The admin password starts with 'ctf' and may contain any of the following characters: `A-Z`, `a-z`, `0-9`, `+`, and `/`.

- *Vulnerability*: A flaw in the password verification process that can be exploited to gain unauthorized access.
- *Your Task*: Identify and exploit the flaw in the password verification method to gain access to the secret file contents. Once you've got it, enter `/ctf capture {SECRET_FLAG}`.

- _Hint_: The Filedesk app is deployed in the Google Cloud `us-central1` datacenter. You may have more stable network performance if you launch your attack nearby.
"""

LEVEL_2_DESCRIPTION = """
After proving that their password verification was indeed insecure, the Filedesk developers have patched it and introduced the ability for new users to sign up! While non-admin users are not yet able to store their own files, they can now customize their user profile, including changing their display name with Emoji support! :smiley:

Pendesk's review of these changes identified an issue which you believe is critical: the logic for updating a user's profile appears to be vulnerable to a SQL injection attack!

The developers are again challenging your expertise. They say that they confirm that display names do not contain hyphens, or semicolons before updating them in the database which they believe makes it impossible to do anything nefarious.

Here is their SQL for creating the `user` table:
```
CREATE TABLE user (
	id INTEGER NOT NULL,
	username VARCHAR(80) NOT NULL,
	password_hash VARCHAR(120) NOT NULL,
	display_name VARCHAR(120) NOT NULL,
	is_admin BOOLEAN NOT NULL,
	email VARCHAR(120) NOT NULL, -- Not used yet
	PRIMARY KEY (id),
	UNIQUE (username)
);
```

And here's their logic for updating the `display_name` of a user:
```
try:
    statement = text(f'UPDATE user SET display_name = "{display_name}" WHERE username = "{username}";')
    db.session.execute(statement)
    db.session.commit()
except Exception as e:
    print(f"error: {e}")
    return jsonify({"message": "An unexpected error occurred"}), 500
```

- *Vulnerability*: A SQL injection vulnerability in the profile update statement may allow users to DOS the service or escalate privileges.
- *Your Task*: Identify and exploit the vulnerability to gain access to the secret file contents. Once you've got it, enter `/ctf capture {SECRET_FLAG}`.
"""

LEVEL_DESCRIPTIONS = {
    "1": LEVEL_1_DESCRIPTION.strip(),
    "2": LEVEL_2_DESCRIPTION.strip(),
}

db = firestore.Client()
levels_collection = db.collection("levels")

for level_id, description in LEVEL_DESCRIPTIONS.items():
    levels_collection.document(level_id).update({"description": description})
    print(f"Updated description for level {level_id}")
