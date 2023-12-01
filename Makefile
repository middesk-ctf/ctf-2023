VERSION=latest

build:
	docker build --platform linux/amd64 -t us-central1-docker.pkg.dev/middesk-ctf-2023/ctf-bot/app:$(VERSION) .

push:
	docker push us-central1-docker.pkg.dev/middesk-ctf-2023/ctf-bot/app:$(VERSION)