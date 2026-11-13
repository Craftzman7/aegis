VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
BIN     := aegis-agent
DIST    := dist

.PHONY: all test vet build build-linux-amd64 build-linux-arm64 build-linux docker-test clean

all: vet test build-linux

vet:
	go vet ./...

test:
	go test ./...

build:
	go build -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN) ./cmd/aegis-agent

build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN)-linux-amd64 ./cmd/aegis-agent

build-linux-arm64:
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN)-linux-arm64 ./cmd/aegis-agent

build-linux: build-linux-amd64 build-linux-arm64

# Runs the suite (including linux-only code paths) in a Linux container.
docker-test:
	docker run --rm -v $(CURDIR):/src -w /src golang:1.27 go test ./...

clean:
	rm -rf $(DIST)
