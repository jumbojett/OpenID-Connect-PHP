# Suppresses Make-specific output. Remove for more debugging info.
.SILENT:

# Variables
KCADM = /opt/keycloak/bin/kcadm.sh
DOCKER_EXEC = docker-compose exec -T keycloak

# Commands
all: help

help: ## Display available commands
	echo "Available make commands:"
	echo
	grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

docker-up: ## Start Keycloak
	docker-compose up -d

docker-down: ## Stop Keycloak
	docker-compose down

keycloak-create-test-realm: ## Create test realm
	$(DOCKER_EXEC) $(KCADM) config credentials --server http://localhost:8080 --realm master --user admin --password admin --client admin-cli
	$(DOCKER_EXEC) $(KCADM) create realms -s realm="testrealm" -s id="testrealm" -s enabled=true
	$(DOCKER_EXEC) $(KCADM) create users -r testrealm -s username=testuser -s enabled=true -s firstName=John -s lastName=Doe
	$(DOCKER_EXEC) $(KCADM) set-password -r testrealm --username testuser --new-password testpassword
	$(DOCKER_EXEC) $(KCADM) create clients -r testrealm -s clientId=testclient -s enabled=true -s clientAuthenticatorType=client-secret -s secret=testsecret -s 'redirectUris=["http://localhost:8000/*"]' -i

serve-test-application: ## Serve test application
	php -S localhost:8000 tests/client-secret-test.php