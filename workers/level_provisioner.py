import random
from typing import Literal, TypedDict, Union

import functions_framework
import yaml
from cloudevents.http import CloudEvent
from google.cloud import firestore
from kr8s.objects import object_from_spec
from mako.template import Template
from util import get_k8s, get_pubsub_json_payload

db = firestore.Client()


class ProvisionLevelPayload(TypedDict):
    action: Union[Literal["create"], Literal["destroy"]]
    player_id: str
    level: str
    variables: dict


@functions_framework.cloud_event
def provision_level(cloud_event: CloudEvent) -> None:
    payload: ProvisionLevelPayload = get_pubsub_json_payload(cloud_event)
    action, player_id, level, variables = (
        payload["action"],
        payload["player_id"],
        payload["level"],
        payload["variables"],
    )

    players_collection = db.collection("players")
    player_doc = players_collection.document(player_id)
    if not player_doc.get().exists:
        raise Exception(f"unknown player: {player_id}")

    player = player_doc.get().to_dict()
    namespace = f"lv-{level}-{random.randint(0, 2**32)}"
    variables["namespace"] = namespace
    variables["player"] = player
    level_yaml = Template(filename=f"./levels/{level}.yaml").render(**variables)
    k8s = get_k8s()
    yamls = list(yaml.safe_load_all(level_yaml))
    k8s_objects = list(object_from_spec(doc, _asyncio=False) for doc in yamls)

    print("Rendered YAMLs:", yamls)

    if action == "create":
        player_doc.update(
            {
                "deployment": {
                    "status": "creating",
                },
            }
        )

        for obj in k8s_objects:
            try:
                obj.create()
            except Exception as e:
                print(e)

        player_doc.update(
            {
                "deployment": {
                    "status": "ready",
                    "app_url": f"http://{namespace}.ctf.middesk.com/",
                },
            }
        )
    elif action == "destroy":
        player_doc.update(
            {
                "deployment": {
                    "status": "deleting",
                },
            }
        )

        for obj in k8s_objects:
            try:
                obj.delete()
            except Exception as e:
                print(e)

        player_doc.update({"deployment": {"status": None}})
    else:
        raise Exception(f"unknown action: {action}")
