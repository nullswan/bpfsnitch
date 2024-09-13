# Automatically include environment variables from .env file
ifneq (,$(wildcard ./.env))
    include .env
    export $(shell sed 's/=.*//' .env)
endif

.PHONY: build-local
build-local:
	DEBUG=1 TARGETARCH=$(shell go env GOARCH) ./bpf/build.sh
	go build -o ./dist/ -v ./...

.PHONY: build-docker
build-docker:
	docker build \
		-t bpfsnitch:latest \
		. -f deployments/Dockerfile

.PHONY: build-docker-multiarch
build-docker-multiarch:
	docker buildx build \
		--platform linux/amd64,linux/arm64,linux/arm/v7 \
		-t nullswan/bpfsnitch:latest \
		--push \
		. -f deployments/Dockerfile

.PHONY: build
build: build-local build-docker

.PHONY: build-binaries
build-binaries: clean
	goreleaser build --snapshot

.PHONY: build-multiarch
build-multiarch: build-binaries build-docker-multiarch

.PHONY: clean
clean:
	rm -rf dist
	docker rmi bpfsnitch || true

.PHONY: fmt
fmt:
	golines . --write-output --max-len=80 --base-formatter="gofmt" --tab-len=2
	golangci-lint run --fix

.PHONY: test
test:
	go test -v -cover ./...
