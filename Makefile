VERSION=latest

all:

fmt:
	black .

worker: fmt 
	gcloud --project=middesk-ctf-2023 functions deploy \
		level-provisioner \
		--gen2 \
		--runtime=python311 \
		--region=us-central1 \
		--source=./workers \
		--entry-point=provision_level \
		--trigger-topic=level-provisioner

build:
	docker build --platform linux/amd64 -t us-central1-docker.pkg.dev/middesk-ctf-2023/ctf-bot/app:$(VERSION) .

push:
	docker push us-central1-docker.pkg.dev/middesk-ctf-2023/ctf-bot/app:$(VERSION)
