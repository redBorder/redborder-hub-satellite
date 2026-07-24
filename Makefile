.PHONY: all hub agent test clean rpm rpmtest srpm

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
