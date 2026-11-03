.PHONY: all hub agent test clean rpm rpmtest srpm lint

VERSION?=1.0.0
BIN_DIR=bin

all: hub agent

hub:
	@echo "Building redborder-hub server..."
	mkdir -p $(BIN_DIR)
	go build -ldflags="-w -s" -o $(BIN_DIR)/redborder-hub cmd/hub/main.go

agent:
	@echo "Building redborder-satellite..."
	mkdir -p $(BIN_DIR)
	go build -ldflags="-w -s" -o $(BIN_DIR)/redborder-satellite cmd/agent/main.go

test:
	@echo "Running tests..."
	go test -v ./...

lint:
	go vet ./...
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	elif [ -f $$(go env GOPATH)/bin/golangci-lint ]; then \
		$$(go env GOPATH)/bin/golangci-lint run ./...; \
	else \
		echo "golangci-lint is not installed. Run 'go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest'"; \
	fi

clean:
	@echo "Cleaning binaries and RPM build artifacts..."
	rm -rf $(BIN_DIR)
	$(MAKE) -C packaging/rpm clean

rpm:
	$(MAKE) -C packaging/rpm

rpmtest:
	$(MAKE) LATEST=`git stash create` -C packaging/rpm

srpm:
	$(MAKE) -C packaging/rpm srpm
