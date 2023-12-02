from cloudevents.http import CloudEvent
import functions_framework

from util import get_pubsub_json_payload, get_k8s


@functions_framework.cloud_event
def provision_level(cloud_event: CloudEvent) -> None:
    payload = get_pubsub_json_payload(cloud_event)

    k8s = get_k8s()
    print(k8s.get("pods"))
    print(payload)
