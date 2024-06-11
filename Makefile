.PHONY: server-run server-stop server-restart server-tests

server-run:
	docker-compose -f ./server/deploy/docker-compose.yaml up -d --build

server-stop:
	docker-compose -f ./server/deploy/docker-compose.yaml down

server-restart: stop run

server-tests: 
	@echo 'not implemented yet'