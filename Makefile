VERSION=latest

all:

fmt:
	isort .
	black .

workers: fmt 
	export KUBE_URL=https://`gcloud --project=middesk-ctf-2023 container clusters describe middesk-ctf-2023 --region=us-central1 --format=json | jq -r '.endpoint'`; \
	export KUBE_SA_TOKEN=`kubectl get secrets -n default --context=gke_middesk-ctf-2023_us-central1_middesk-ctf-2023 cloud-functions-token -ojson | jq .data.token -r | base64 -d`; \
	gcloud --project=middesk-ctf-2023 functions deploy \
		level-provisioner \
		--gen2 \
		--runtime=python311 \
		--region=us-central1 \
		--source=./workers \
		--entry-point=provision_level \
		--trigger-topic=level-provisioner \
		--update-env-vars=KUBE_URL=$$KUBE_URL,KUBE_SA_TOKEN=$$KUBE_SA_TOKEN

build:
	docker build --platform linux/amd64 -t us-central1-docker.pkg.dev/middesk-ctf-2023/ctf-bot/app:$(VERSION) .

push:
	docker push us-central1-docker.pkg.dev/middesk-ctf-2023/ctf-bot/app:$(VERSION)
