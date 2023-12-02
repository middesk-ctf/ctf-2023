import logging
import os

from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from flask import Flask, request, make_response


load_dotenv(dotenv_path=".env.local")

LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(level=LOGLEVEL)

app = App()


# Listens to incoming messages that contain "ctf-bot"
@app.message("ctf-bot")
def hello_from_ctf_bot(message, say):
    # say() sends a message to the channel where the event was triggered
    say(f"Hey there <@{message['user']}>!")


def ctf_usage():
    commands = [
        "join",
        "standings",
        "standings [LEVEL]",
        "start",
        "restart",
        "capture [FLAG]",
    ]
    usage = "Valid commands are:"
    for command in commands:
        usage += f"\n- `/ctf {command}`"
    return usage


def unrecognized_command():
    return f"Sorry, I don't recognize your command.\n{ctf_usage()}"


@app.command("/ctf")
def ctf_command(ack, command, say):
    ack()  # Acknowledge the command request.

    print(f"\n{command}\n")

    text = command["text"]
    if text == "join":
        user_id = command["user_id"]
        # Add user_id to firestore collection of players.
        say(
            f"Hi, <@{user_id}>. You've been added to the CTF competition! (not really)\nI'll notify you when the 1st level is ready!"
        )
    elif text == "standings":
        say(f"The CTF competition has not yet started. Please check back later!")
    elif text.startswith("standings "):
        say(f"The CTF competition has not yet started. Please check back later!")
    elif text.startswith("capture "):
        say(f"The CTF competition has not yet started. Please check back later!")
    else:
        say(unrecognized_command())


# TODO
def handle_join(slack_user_id):
    pass


def handle_standings(level=None):
    pass


def handle_start(slack_user_id):
    pass


def handle_restart(slack_user_id):
    pass


def handle_capture(slack_user_id, flag):
    pass


flask_app = Flask("Middesk CTF Bot")
handler = SlackRequestHandler(app)


@flask_app.route("/", methods=["GET"])
def get_root():
    return make_response("OK", 200)


@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    return handler.handle(request)


if __name__ == "__main__":
    # POST http://localhost:3000/slack/events
    debug = LOGLEVEL == "DEBUG"
    flask_app.run(debug=debug, port=3000)
