import base64
import json
import os

import kr8s
from cloudevents.http import CloudEvent


def get_pubsub_json_payload(cloud_event: CloudEvent):
    pubsub_message = base64.b64decode(cloud_event.data["message"]["data"]).decode()
    return json.loads(pubsub_message)


def get_k8s():
    k8s = kr8s.api(url=os.getenv("KUBE_URL"))
    k8s.auth.token = os.getenv("KUBE_SA_TOKEN")
    k8s.auth._insecure_skip_tls_verify = True
    return k8s
