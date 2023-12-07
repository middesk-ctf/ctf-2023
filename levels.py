from datetime import datetime

from dotenv import load_dotenv
from google.cloud import firestore
from slack_bolt import App

load_dotenv(dotenv_path=".env.local")


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

LEVEL_3_DESCRIPTION = """
Your rapid progress at Pendesk has not gone unnoticed! :chart_with_upwards_trend: In just a short time, you've demonstrated exceptional skill and resourcefulness. Recognizing your talent, your team entrusts you with leading the investigation into the next potential vulnerability in Filedesk's system.

The Filedesk team has recently transitioned from using session cookies to JSON Web Tokens (JWTs) for authentication. These tokens are now stored in the browser's local storage and can be accessed via JavaScript. However, there's a catch: the JWT library they're using is alarmingly outdated, dating back to versions of the JWT specification from 2014.

Your mission is to conduct a thorough examination of this JWT library. Look for any weaknesses or outdated practices that could be exploited. :eyes-intensifies: Remember, the Filedesk developers have been rather complacent about security; it seems the only way to make them acknowledge a vulnerability is by demonstrating it practically. This means your goal is to use any discovered vulnerabilities in the JWT implementation to access the now-familiar `SECRET_FLAG.txt` which is usually only viewable by the `admin` user.

As always, once you've successfully exploited the vulnerability and obtained the contents of the secret file, enter the command `/ctf capture {SECRET_FLAG}` to complete your task.

Good luck, and happy hunting! :salute-face:

Vulnerability: Potential flaws in the outdated JWT library that could be exploited for unauthorized access.
Your Task: Examine the JWT library, identify and exploit any vulnerabilities to access the secret file. Once successful, submit the secret flag as before.
Included with this challenge is <https://gist.github.com/jlhawn/03a99bf6991598d45e89202e18f2d117|a copy of the JWT library used by Filedesk>. Familiarize yourself with its code and functions as it could be the key to uncovering the security flaw.
"""

LEVEL_4_DESCRIPTION = """
Welcome back, cyber sleuth! :sleuth_or_spy:

After your recent exploits at Filedesk, Inc., the developers have finally unveiled their first version of file storage and sharing functionalities for all users! :tada:
While they're a tad irked about the breach of their secret flag yesterday, the excitement over these new features overshadows their concerns. They've diligently patched the JWT library loophole but now need your sharp eyes on their latest feature additions.

Today, your mission is to scrutinize the security of these new file creation and sharing features and they want you to try them out.
Even the Filedesk `admin` user is eagerly refreshing their files list multiple times each minute :arrows_counterclockwise: to check out any new files shared with them.

As you dive into the task, your colleague Xenia Sophia Serrano (cool initials btw), believes she's onto something. She thinks there could be vulnerabilities related to content sharing. She was close to cracking it but hasn't quite figured it out yet. :thinking_face:

🎯 Your primary goal is to discover and exploit any vulnerability here that grants access to the `SECRET_FLAG.txt` file, which is under the `admin` user's ownership.

_Suggestion_: The Filedesk team has implemented a plethora of API functionalities, accessible to JavaScript running in the browser. This is used extensively for their app logic and front-end rendering. A clever hacker might find these APIs (accessible through the "sources" tab of your browser's dev tools) quite handy!

Once you've successfully breached the security and obtained the file, complete your mission by entering:
   `/ctf capture {SECRET_FLAG}`.
"""

LEVEL_5_DESCRIPTION = """
After your recent triumph :triumph: in uncovering the (now patched) XSS vulnerability, the developers at Filedesk, still reeling from the vulnerabilities you exposed in their old JWT library, have now rolled out a custom JSON Web Token (JWT) library, with a particular focus on their Elliptic Curve Digital Signature Algorithm (ECDSA) Signing Key implementation which they’re now using for signing session tokens. :hammer_and_wrench: 

However, whispers in the cryptographic corridors at Pendesk suggest there may be a critical flaw in their new ES256 signing key implementation. The Filedesk team, still riding high on their coding marathon, challenges the notion, confident that their cryptographic skills are top-notch. :lock: 

You’ve been given the task to dive into the cryptographic depths of Filedesk’s latest security measures. :dart: Your objective is to uncover and exploit any critical vulnerability in their ECDSA Signing Key implementation, and once again gain unauthorized access to the legendary `SECRET_FLAG.txt` file. :file_folder:

Equipped with <https://gist.github.com/jlhawn/4a13c5622631f216c6d7a7cd5e9883cc|a copy of Filedesk’s new JWT library> :page_facing_up:, you stand at the threshold of what could be your most challenging and enlightening adventure yet at Pendesk. :female-detective:

Once you’ve deciphered the code and seized the secret file, complete your cryptographic conquest by entering:
`/ctf capture {SECRET_FLAG}.`

Gear up for a journey where every detail could be the key to unlocking the mystery. Good luck, and may your crypto-skills shine bright! :tophat::sparkles:
"""

LEVEL_DESCRIPTIONS = {
    "1": LEVEL_1_DESCRIPTION.strip(),
    "2": LEVEL_2_DESCRIPTION.strip(),
    "3": LEVEL_3_DESCRIPTION.strip(),
    "4": LEVEL_4_DESCRIPTION.strip(),
    "5": LEVEL_5_DESCRIPTION.strip(),
}

db = firestore.Client()
levels_collection = db.collection("levels")


def update_descriptions():
    for level_id, description in LEVEL_DESCRIPTIONS.items():
        levels_collection.document(level_id).update({"description": description})
        print(f"Updated description for level {level_id}")


ENG_CHANNEL_ID = "CSTFHC97W"

app = App()

# Function to schedule a message
def schedule_message(channel_id, message_text, post_time):
    try:
        # Schedule the message
        result = app.client.chat_scheduleMessage(
            channel=channel_id, text=message_text, post_at=post_time
        )
        print(f"Message scheduled: {result}")
        return True
    except Exception as e:
        print(f"Error scheduling message: {e}")
        return False


def schedule_announcements():
    levels_ref = db.collection("levels")
    for doc in levels_ref.stream():
        level_data = doc.to_dict()
        already_scheduled = level_data.get("announcement_scheduled", False)
        if not already_scheduled:
            start_at = datetime.fromisoformat(level_data["start_at"])
            message_text = f"Level {level_data['id']} of Middesk CTF 2023 is Starting Now! :cathack:"
            was_scheduled = schedule_message(
                ENG_CHANNEL_ID, message_text, int(start_at.timestamp())
            )
            if was_scheduled:
                doc.reference.update({"announcement_scheduled": True})


if __name__ == "__main__":
    update_descriptions()
    schedule_announcements()
