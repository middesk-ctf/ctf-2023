import random
import time
from typing import Literal, Optional, TypedDict, Union

import functions_framework
import kr8s
import requests
import yaml
from cloudevents.http import CloudEvent
from google.cloud import firestore
from kr8s.objects import Namespace, object_from_spec
from mako.template import Template
from util import dm_user, get_k8s, get_pubsub_json_payload, get_slack

db = firestore.Client()


class ProvisionLevelPayload(TypedDict):
    action: Union[Literal["create"], Literal["destroy"]]
    player_id: str

    # When creating,
    level: Optional[str]
    variables: Optional[dict]


@functions_framework.cloud_event
def provision_level(cloud_event: CloudEvent) -> None:
    payload: ProvisionLevelPayload = get_pubsub_json_payload(cloud_event)
    action, player_id, level, variables = (
        payload["action"],
        payload["player_id"],
        payload.get("level"),
        payload.get("variables", {}),
    )

    players_collection = db.collection("players")
    player_doc = players_collection.document(player_id)
    if not player_doc.get().exists:
        raise Exception(f"unknown player: {player_id}")
    player = player_doc.get().to_dict()

    k8s = get_k8s()
    slack = get_slack()

    if action == "create":
        namespace = f"lv-{level}-{random.randint(0, 2**32)}"
        app_url = f"https://{namespace}.ctf.middesk.com/"
        variables["namespace"] = namespace
        variables["player"] = player
        level_yaml = Template(filename=f"./levels/{level}.yaml").render(**variables)
        yamls = list(yaml.safe_load_all(level_yaml))
        k8s_objects = list(object_from_spec(doc, _asyncio=False) for doc in yamls)
        print("Rendered YAMLs:", yamls)

        player_doc.update(
            {
                "deployment": {
                    "status": "creating",
                    "namespace": namespace,
                    "app_url": app_url,
                },
            }
        )

        for obj in k8s_objects:
            try:
                obj.create()
            except Exception as e:
                print(e)

        # Wait until all deployments are ready.
        time.sleep(1)
        for i in range(300):
            if all([d.ready() for d in kr8s.get("deployments", namespace=namespace)]):
                break
            print(f"Deployments in namespace {namespace} are not yet ready")
            time.sleep(1)

        # Wait until the service is actually running.
        time.sleep(1)
        for i in range(300):
            print(f"[{i}/300] Waiting for {app_url} to come online...")
            try:
                response = requests.get(app_url, timeout=5)
                if response.status_code < 400:
                    break
            except Exception as e:
                print(e)
            time.sleep(1)
        else:
            raise Exception(f"deployment never became ready: {app_url}")

        print(f"{app_url} is online!")

        player_doc.update({"deployment.status": "ready"})

        dm_user(
            player_id,
            slack,
            f"🤖 Your challenge (Level {level}) is ready at {app_url} . 😈 Go crazy!",
        )
    elif action == "destroy":
        player_doc.update({"deployment.status": "deleting"})

        try:
            Namespace.get(player["deployment"]["namespace"]).delete()
        except Exception as e:
            print(e)

        player_doc.update(
            {
                "deployment": {
                    "status": None,
                },
                "secret_flag": None,
                "admin_password": None,
            }
        )
    else:
        raise Exception(f"unknown action: {action}")
