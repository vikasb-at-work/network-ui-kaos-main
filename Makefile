IMAGE_NAME = flask_kaos_alpine
CONTAINER_NAME = kaos_alpine
OUTSITE_PORT = 8087
INSIDE_PORT = 8080

VAULT_SECRET_ID = $(shell echo $$VAULT_SECRET_ID)
VAULT_APP_ROLE_ID = $(shell echo $$VAULT_APP_ROLE_ID)

.PHONY: help
help:
	@echo "Usage:"
	@echo " make build"		":Build the Docker image"
	@echo " make run"		":Run the container"
	@echo "	make stop"		":Stop and removes the container"
	@echo "	make rebuild"	":Rebuild and re-run the container"
	@echo "	make reload"	":Reload the container, basically remove the container and rebuild the image and restart the container"
	@echo "	make restart"	":Restart the container without rebuilding the image, just for small quick changes"

.PHONY: build
build:
	sudo docker build -t $(IMAGE_NAME) .

.PHONY: run
run:
	sudo docker run -e VAULT_SECRET_ID=$(VAULT_SECRET_ID) -e VAULT_APP_ROLE_ID=$(VAULT_APP_ROLE_ID) --name $(CONTAINER_NAME) -it -v $(PWD):/app -p $(OUTSITE_PORT):$(INSIDE_PORT) $(IMAGE_NAME)

.PHONY: stop
stop:
	@if [ $$(docker ps -q -f name=$(CONTAINER_NAME)) ]; then \
		echo "Stopping container $(CONTAINER_NAME)..."; \
		docker stop $(CONTAINER_NAME); \
	else \
		echo "Container is not running"; \
	fi; \
	if [ $$(docker ps -a -q -f name=$(CONTAINER_NAME)) ]; then \
		echo "Removing container $(CONTAINER_NAME)..."; \
		docker rm $(CONTAINER_NAME); \
	else \
		echo "Container does not exist"; \
	fi

.PHONY: restart
restart: stop run

.PHONY: rebuild
rebuild: build run

.PHONY: reload
reload: stop build run