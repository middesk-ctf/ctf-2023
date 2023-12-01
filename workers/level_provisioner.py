from kubernetes import client, config
from cloudevents.http import CloudEvent
import functions_framework

from util import get_pubsub_json_payload

config.load_kube_config()


@functions_framework.cloud_event
def provision_level(cloud_event: CloudEvent) -> None:
    payload = get_pubsub_json_payload(cloud_event)
    
    print(payload)
