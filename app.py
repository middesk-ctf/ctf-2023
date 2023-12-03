import base64
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, make_response, request
from google.cloud import firestore, pubsub_v1
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler

load_dotenv(dotenv_path=".env.local")

LOGLEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
logging.basicConfig(level=LOGLEVEL)

CTF_ADMIN_PLAYER_IDS = set(
    [
        "U01A8GBSEF5",  # Stewart Park
        "U03U0ELF3UH",  # Josh Hawn
    ]
)

GOOGLE_CLOUD_PROJECT = os.environ.get("GOOGLE_CLOUD_PROJECT", "middesk-ctf-2023")
LEVEL_PROVISIONER_PUBSUB_TOPIC_ID = os.environ.get(
    "LEVEL_PROVISIONER_PUBSUB_TOPIC_ID", "level-provisioner"
)

# Initialize Pub/Sub publisher client.
publisher = pubsub_v1.PublisherClient()
topic_path = publisher.topic_path(
    GOOGLE_CLOUD_PROJECT, LEVEL_PROVISIONER_PUBSUB_TOPIC_ID
)


# Initialize Firestore
db = firestore.Client()

app = App()


def dm_channel_id(user_id, client):
    response = client.conversations_open(users=user_id)
    return response["channel"]["id"]


def dm_user(user_id, client, message):
    channel_id = dm_channel_id(user_id, client)
    client.chat_postMessage(channel=channel_id, text=message)


def dm_user_error(user_id, client):
    return dm_user(
        user_id,
        client,
        "An error occurred! Please ping one of the following admins for assistance:\n"
        f"{', '.join([f'@<{user_id}>' for user_id in CTF_ADMIN_PLAYER_IDS])}",
    )


# Admin passwords always start with 'ctf' and contain any of the following
# characters: A-Z, a-z, 0-9, `+`, and `/`.
def make_admin_password():
    # Generate 9 random bytes
    encoded_bytes = base64.b64encode(os.urandom(9))
    return "ctf" + encoded_bytes.decode("utf-8")


# Secret Flags always start with 'FLAG' and containe any of the following
# characters: A-Z, a-z, 0-9, `+`, and `/`.
def make_secret_flag():
    # Generate 24 random bytes.
    encoded_bytes = base64.b64encode(os.urandom(24))
    return "FLAG" + encoded_bytes.decode("utf-8")


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

MAX_LEVEL = 1  # Set this to the number of levels currenty implemented.


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
        case "help":
            return dm_user(user_id, client, ctf_usage())
        case "join":
            return handle_join(args[1:], user_id, client)
        case "standings":
            return handle_standings(args[1:], user_id, client)
        case "start":
            return handle_start(args[1:], user_id, client)
        case "destroy":
            return handle_destroy(args[1:], user_id, client)
        case "restart":
            return handle_restart(args[1:], user_id, client)
        case "capture":
            return handle_capture(args[1:], user_id, client)
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
            "current_level": 1,
            "deployment": {
                "status": None,
            },
            "secret_flag": None,
            "admin_password": None,
        }
    )

    dm_user(
        user_id,
        client,
        f"Welcome <@{user_id}>! You have been successfully registered.\nEnter `/ctf start` to start the first level!",
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


def handle_start(args, user_id, client):
    if args:
        # There should be no arguments.
        return dm_unrecognized_command(user_id, client)

    player_id = user_id

    # Get player document from firestore.
    players_collection = db.collection("players")
    player_doc = players_collection.document(player_id).get()

    if not player_doc.exists:
        return dm_user(user_id, client, "Please join first by entering `/ctf join`!")

    player_doc = player_doc.to_dict()

    current_deployment = player_doc.get("deployment", {})
    current_deployment_status = current_deployment.get("status")
    if current_deployment_status is not None:
        return dm_user(
            user_id,
            client,
            f"You have an existing deployment with status: {current_deployment_status}.\nYou cannot start the next level yet. Please try again momentarily.",
        )

    current_level = player_doc.get("current_level", 1)
    if current_level > MAX_LEVEL:
        return dm_user(
            user_id, client, "You've already completed all the challenges available!"
        )

    # Lookup the level.
    levels_collection = db.collection("levels")
    # Should be ok to assume the level exists.
    level_doc = levels_collection.document(str(current_level)).get().to_dict()

    # Make sure this level has started first!
    #    (except for admin players)
    starts_at = datetime.fromisoformat(level_doc["start_at"])
    current_time = datetime.now(tz=timezone.utc)
    delta_seconds = (starts_at - current_time).total_seconds()
    if delta_seconds > 0 and player_id not in CTF_ADMIN_PLAYER_IDS:
        hours = int(delta_seconds // 3600)
        minutes = int((delta_seconds % 3600) // 60)
        seconds = int(delta_seconds % 60)
        return dm_user(
            user_id,
            client,
            f"Level {current_level} doesn't start for another {hours}hr {minutes}min {seconds}s. :stopwatch:\nTake a break! :tropical_drink:",
        )

    # Prepare the pub/sub message.
    admin_password = make_admin_password()
    secret_flag = make_secret_flag()

    message_data = {
        "action": "create",
        "player_id": player_id,
        "level": current_level,
        "variables": {
            "encoded_admin_password": base64.b64encode(
                admin_password.encode("utf-8")
            ).decode(),
            "encoded_secret_flag": base64.b64encode(
                secret_flag.encode("utf-8")
            ).decode(),
        },
    }

    dm_user(user_id, client, level_doc.get("description"))
    dm_user(user_id, client, "Creating new level deployment ...")

    # Send the message.
    try:
        message = json.dumps(message_data).encode("utf-8")
        # Block until the message is published, returning the message ID.
        message_id = publisher.publish(topic_path, message).result()
        print(f"Message published with ID: {message_id}")
    except Exception as e:
        # Handle any exceptions that occur during publish
        print(f"An error occurred: {e}")
        return dm_user_error(user_id, client)

    players_collection.document(player_id).update(
        {
            "deployment": {
                "status": "pending",
            },
            "secret_flag": secret_flag,
            "admin_password": admin_password,
        }
    )

    return dm_user(
        user_id,
        client,
        "Your challenge is pending deployment! :kubernetes:\nPlease wait for it to be ready!",
    )


def handle_destroy(args, user_id, client, force=False):
    player_id = user_id

    if not force and player_id not in CTF_ADMIN_PLAYER_IDS:
        # Force destory can only be done by an admin or part of other
        # internal operations.
        return dm_user(
            user_id,
            client,
            "Sorry, only admins can run this command. Try `/ctf start` or `/ctf restart` instead!",
        )

    # If an argument is specified, the player should be an admin attempting
    # to destroy a specific player deployment.
    if args:
        if player_id not in CTF_ADMIN_PLAYER_IDS:
            # Admins can't do this.
            return dm_unrecognized_command(user_id, client)

        # Player is an admin. There should be exactly one arg.
        if len(args) != 1:
            return dm_unrecognized_command(user_id, client)

        # The admin's argument specifies the player whose deployment to
        # destroy.
        player_id = args[0]

    # Get player document from firestore.
    players_collection = db.collection("players")
    player_doc = players_collection.document(player_id).get()

    if not player_doc.exists:
        return dm_user(user_id, client, "Please join first by entering `/ctf join`!")

    player_doc = player_doc.to_dict()

    current_deployment = player_doc.get("deployment", {})
    current_deployment_status = current_deployment.get("status")

    # There should be an existing deployment.
    if current_deployment_status is None:
        return dm_user(
            user_id,
            client,
            f"You don't currently have a deployment!\nYou can start the next by entering `/ctf start`.",
        )

    # Send a pub/sub message to destroy the current deployment for the user.
    message_data = {
        "action": "destroy",
        "player_id": player_id,
    }

    # Send the message.
    try:
        message = json.dumps(message_data).encode("utf-8")
        # Block until the message is published, returning the message ID.
        message_id = publisher.publish(topic_path, message).result()
        print(f"Message published with ID: {message_id}")
    except Exception as e:
        # Handle any exceptions that occur during publish
        print(f"An error occurred: {e}")
        return dm_user_error(user_id, client)

    dm_user(user_id, client, "Waiting for your current deployment to be destroyed ...")

    time.sleep(1)
    for i in range(60):
        print(f"[{i}/60] Waiting for player {player_id} deployment to be destroyed...")
        player_doc = players_collection.document(player_id).get().to_dict()
        if player_doc.get("deployment", {}).get("status") is None:
            break
        time.sleep(1)

    dm_user(user_id, client, "Deployment destroyed! :boom:")


def handle_restart(args, user_id, client):
    if args:
        # There should be no arguments.
        return dm_unrecognized_command(user_id, client)

    handle_destroy([], user_id, client, force=True)
    handle_start([], user_id, client)


def handle_capture(args, user_id, client):
    if len(args) != 1:
        # There should be exactly one arguments.
        return dm_unrecognized_command(user_id, client)

    flag = args[0]
    player_id = user_id

    # Get player document from firestore.
    players_collection = db.collection("players")
    player_doc = players_collection.document(player_id).get()

    if not player_doc.exists:
        return dm_user(user_id, client, "Please join first by entering `/ctf join`!")

    player_doc = player_doc.to_dict()

    deployment = player_doc.get("deployment", {})
    deployment_status = deployment.get("status")

    if deployment_status is None:
        return dm_user(
            user_id,
            client,
            "You don't have a current level deployment. Try `/ctf start` to deploy your next challenge!",
        )

    if flag != player_doc.get("secret_flag"):
        return dm_user(
            user_id, client, "Your flag value is inncorrect! :triangular_flag_on_post:"
        )

    current_level = player_doc.get("current_level")
    next_level = current_level + 1

    dm_user(
        user_id,
        client,
        f"You've captured the level {current_level} flag! :checkered_flag:",
    )

    # The user has captured the flag! Destroy their deployment.
    handle_destroy([], user_id, client, force=True)

    player_ref = db.collection("players").document(player_id)
    level_ref = db.collection("levels").document(str(current_level))

    # Update the user's level and append their ID to the level's standings.
    transaction = db.transaction()
    update_player_level(transaction, player_ref, level_ref)

    if next_level > MAX_LEVEL:
        return dm_user(user_id, client, "That's all the levels for now!")

    return dm_user(user_id, client, "You can start the next level with `/ctf start`")


@firestore.transactional
def update_player_level(transaction, player_ref, level_ref):
    player_doc = player_ref.get(transaction=transaction).to_dict()
    level_doc = level_ref.get(transaction=transaction).to_dict()

    player_id = player_doc.get("id")
    standings = level_doc.get("standings")
    # It shouldn't be possible, but add this check anyway.
    if player_id not in standings:
        standings.append(player_id)

    transaction.update(level_ref, {"standings": standings})
    transaction.update(player_ref, {"current_level": level_doc.get("id") + 1})


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
