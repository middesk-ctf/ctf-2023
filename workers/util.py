from cloudevents.http import CloudEvent
import base64
import json


def get_pubsub_json_payload(cloud_event: CloudEvent):
    pubsub_message = base64.b64decode(cloud_event.data["message"]["data"]).decode()
    return json.loads(pubsub_message)
