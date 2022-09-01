.PHONY: run
run:
	poetry run flask --app app.server --debug run --cert=adhoc

.PHONY: fmt
fmt:
	poetry run autoflake --ignore-init-module-imports --remove-all-unused-imports --verbose --remove-unused-variables -r -i app/*
	poetry run isort .
	poetry run black .


.PHONY: clean
clean:
	@echo "Cleaning build..."

.PHONY: requirements
requirements:
	@poetry export --without-hashes -o requirements.txt
	
.PHONY: build
build: clean fmt requirements

	