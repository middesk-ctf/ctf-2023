from collections import defaultdict
from datetime import datetime, timezone
import logging
import os

from dotenv import load_dotenv
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from flask import Flask, request, make_response
from google.cloud import firestore


load_dotenv(dotenv_path=".env.local")

LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(level=LOGLEVEL)

# Initialize Firestore
db = firestore.Client()

app = App()


def dm_channel_id(user_id, client):
    response = client.conversations_open(users=user_id)
    return response["channel"]["id"]


def dm_user(user_id, client, message):
    channel_id = dm_channel_id(user_id, client)
    client.chat_postMessage(channel=channel_id, text=message)


# Listens to incoming messages that contain "ctf-bot"
@app.message("ctf-bot")
def hello_from_ctf_bot(message, say):
    # say() sends a message to the channel where the event was triggered
    say(f"Hey there <@{message['user']}>!")


COMMANDS = [
    "join",
    "standings [LEVEL]",
    "start",
    "restart",
    "capture FLAG",
]


def ctf_usage():
    usage = "Valid commands are:"
    for command in COMMANDS:
        usage += f"\n- `/ctf {command}`"
    return usage


def dm_unrecognized_command(user_id, client):
    dm_user(user_id, client, f"Sorry, I don't recognize your command.\n{ctf_usage()}")


@app.command("/ctf")
def ctf_command(ack, command, client, say):
    ack()  # Acknowledge the command request.

    print(f"Got Command:\n{command}\n")

    user_id = command["user_id"]

    args = command["text"].split(" ")
    if not args:
        return dm_unrecognized_command(user_id, client)

    match args[0]:
        case "join":
            return handle_join(args[1:], user_id, client)
        case "standings":
            return handle_standings(args[1:], user_id, client)
        case _:
            return dm_unrecognized_command(user_id, client)


def handle_join(args, user_id, client):
    if args:
        # There should be no arguments.
        return dm_unrecognized_command(user_id, client)

    # Player IDs are Slack User IDs.
    player_id = user_id

    # Firestore: Check if the user already exists
    players_collection = db.collection("players")
    player_doc = players_collection.document(player_id).get()

    if player_doc.exists:
        return dm_user(
            user_id, client, f"Welcome back <@{user_id}>! You are already registered."
        )

    # Fetch user info from Slack
    user_info = client.users_info(user=user_id)
    user_email = user_info["user"]["profile"]["email"]

    # Add new player to Firestore
    players_collection.document(user_id).set(
        {
            "id": user_id,
            "email": user_email,
            "joined_at": datetime.now(tz=timezone.utc).isoformat(),
            "current_level": 0,
            "deployment": {},
            "secret_flag": "",
        }
    )

    dm_user(
        user_id, client, f"Welcome <@{user_id}>! You have been successfully registered."
    )


MAX_POINTS = 15
MIN_POINTS = 1


def calculate_level_points(standings):
    # Standings is a list of player IDs in the order
    # in which they have completed the level.
    return [
        (player_id, max(MIN_POINTS, MAX_POINTS - i))
        for (i, player_id) in enumerate(standings)
    ]


def handle_standings(args, user_id, client):
    # There should be at most one argument specifying a level.
    if len(args) > 1:
        return dm_unrecognized_command(user_id, client)

    levels_collection = db.collection("levels")

    if len(args) == 1:
        level = args[0]
        level_doc = levels_collection.document(level).get()

        if not level_doc.exists:
            return dm_user(
                user_id,
                client,
                f"No such level: {level}. Valid levels are 1 through 5.",
            )

        standings = level_doc.get("standings")
        ordered_player_points = calculate_level_points(standings)

        message = f"No standings for Level {level} yet!"
        if ordered_player_points:
            message = f"Standings for Level {level}:"
    else:
        player_points = defaultdict(int)  # Maps player_id to points (default 0)
        for doc in levels_collection.list_documents():
            level_standings = doc.get().get("standings")
            level_points = calculate_level_points(level_standings)

            for player_id, level_points in level_points:
                player_points[player_id] += level_points

        ordered_player_points = sorted(
            player_points.items(),
            key=lambda item: item[1],
            reverse=True,
        )

        message = "No standings yet!"
        if ordered_player_points:
            message = f"Standings:"

    for player_id, points in ordered_player_points:
        message += f"\n<@{player_id}> ({points} Points)"

    dm_user(user_id, client, message)


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
